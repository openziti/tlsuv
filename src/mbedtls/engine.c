// Copyright (c) NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/ssl.h>
#include <mbedtls/debug.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/base64.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/version.h>

#include "../bio.h"
#include "../um_debug.h"
#include "keys.h"
#include "mbed_p11.h"
#include <tlsuv/tlsuv.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#if TARGET_OS_IOS
#include <Security/Security.h>
#endif
#endif

#if _WIN32
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#else

#include <stddef.h>
#include <unistd.h>

#endif

#define container_of(ptr, type, member) \
  ((type *) ((char *) (ptr) - offsetof(type, member)))

// inspired by https://golang.org/src/crypto/x509/root_linux.go
// Possible certificate files; stop after finding one.
const char *const caFiles[] = {
        "/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
        "/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
        "/etc/ssl/ca-bundle.pem",                            // OpenSUSE
        "/etc/pki/tls/cacert.pem",                           // OpenELEC
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
        "/etc/ssl/cert.pem"                                  // macOS
};
#define NUM_CAFILES (sizeof(caFiles) / sizeof(char *))

struct mbedtls_context {
    tls_context api;
//    mbedtls_ssl_config config;
    char *ca;
    size_t ca_len;
    struct priv_key_s *own_key;
    mbedtls_x509_crt *own_cert;
    int (*cert_verify_f)(const struct tlsuv_certificate_s* , void *v_ctx);
    void *verify_ctx;
};

struct mbedtls_engine {
    struct tlsuv_engine_s api;

    char **protocols;
    mbedtls_ssl_config config;
    mbedtls_x509_crt *ca;
    mbedtls_ssl_context *ssl;
    mbedtls_ssl_session *session;

    io_ctx io;
    uv_os_fd_t io_fd;
    io_read read_f;
    io_write write_f;

    int error;

    int ip_len;
    struct in6_addr addr;
    int (*cert_verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx);
    void *verify_ctx;
    mbedtls_ctr_drbg_context *drbg;
    mbedtls_entropy_context *entropy;
};

static void mbedtls_set_alpn_protocols(tlsuv_engine_t engine, const char** protos, int len);
static int mbedtls_set_own_cert(tls_context *ctx, tlsuv_private_key_t key, tlsuv_certificate_t cert);

tlsuv_engine_t new_mbedtls_engine(void *ctx, const char *host);

static void mbedtls_set_io(tlsuv_engine_t, io_ctx , io_read , io_write );
static void mbedtls_set_fd(tlsuv_engine_t, uv_os_fd_t );

static tls_handshake_state mbedtls_hs_state(tlsuv_engine_t engine);
static tls_handshake_state
mbedtls_continue_hs(tlsuv_engine_t engine);

static const char* mbedtls_get_alpn(tlsuv_engine_t engine);

static int mbedtls_write(tlsuv_engine_t engine, const char *data, size_t data_len);

static int
mbedtls_read(tlsuv_engine_t engine, char *, size_t *, size_t );

static int mbedtls_close(tlsuv_engine_t engine);

static int mbedtls_reset(tlsuv_engine_t engine);

static const char *mbedtls_version(void);

static const char *mbedtls_eng_error(tlsuv_engine_t engine);

static void mbedtls_free(tlsuv_engine_t engine);

static void mbedtls_free_ctx(tls_context *ctx);

static void mbedtls_free_cert(tlsuv_certificate_t cert);

static void mbedtls_set_cert_verify(tls_context *ctx,
                                    int (*verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx), void *v_ctx);

static int mbedtls_verify_signature(const struct tlsuv_certificate_s * cert, enum hash_algo md,
                                    const char *data, size_t datalen, 
                                    const char *sig, size_t siglen);

static int parse_pkcs7_certs(tlsuv_certificate_t *chain, const char *pkcs7, size_t pkcs7len);

static int write_cert_pem(const struct tlsuv_certificate_s * cert, int full_chain, char **pem, size_t *pemlen);

static int generate_csr(tlsuv_private_key_t key, char **pem, size_t *pemlen, ...);

static int mbedtls_load_cert(tlsuv_certificate_t *c, const char *cert_buf, size_t cert_len);

struct cert_s {
    TLSUV_CERT_API
    mbedtls_x509_crt *chain;
};

static struct cert_s cert_api = {
    .free = mbedtls_free_cert,
    .to_pem = write_cert_pem,
    .verify = mbedtls_verify_signature,
};

static tls_context mbedtls_context_api = {
        .version = mbedtls_version,
        .strerror = mbedtls_error,
        .new_engine = new_mbedtls_engine,
        .free_ctx = mbedtls_free_ctx,
        .set_own_cert = mbedtls_set_own_cert,
        .set_cert_verify = mbedtls_set_cert_verify,
        .parse_pkcs7_certs = parse_pkcs7_certs,
        .generate_key = gen_key,
        .load_key = load_key,
        .load_pkcs11_key = load_key_p11,
        .load_cert = mbedtls_load_cert,
        .generate_csr_to_pem = generate_csr,
};

static struct tlsuv_engine_s mbedtls_engine_api = {
        .set_io = mbedtls_set_io,
        .set_io_fd = mbedtls_set_fd,
        .set_protocols = mbedtls_set_alpn_protocols,
        .handshake_state = mbedtls_hs_state,
        .handshake = mbedtls_continue_hs,
        .get_alpn = mbedtls_get_alpn,
        .close = mbedtls_close,
        .write = mbedtls_write,
        .read = mbedtls_read,
        .reset = mbedtls_reset,
        .strerror = mbedtls_eng_error,
        .free = mbedtls_free,
};

static void init_ssl_context(mbedtls_ssl_config *ssl_config, const char *ca, size_t cabuf_len);

static const char* mbedtls_version(void) {
    return MBEDTLS_VERSION_STRING_FULL;
}

const char *mbedtls_error(long code) {
    static char errbuf[1024];
    mbedtls_strerror((int)code, errbuf, sizeof(errbuf));
    return errbuf;

}

static const char *mbedtls_eng_error(tlsuv_engine_t eng) {
    struct mbedtls_engine *e = (struct mbedtls_engine *)eng;
    return mbedtls_error(e->error);
}

tls_context *new_mbedtls_ctx(const char *ca, size_t ca_len) {
    struct mbedtls_context *c = calloc(1, sizeof(struct mbedtls_context));
    c->api = mbedtls_context_api;
    if (ca && ca_len > 0) {
        c->ca_len = ca_len;
        c->ca = calloc(1, ca_len + 1);
        memcpy(c->ca, ca, ca_len);
    }

    return &c->api;
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str);

static void init_ssl_context(mbedtls_ssl_config *ssl_config, const char *cabuf, size_t cabuf_len) {
    char *tls_debug = getenv("MBEDTLS_DEBUG");
    if (tls_debug != NULL) {
        int level = (int) strtol(tls_debug, NULL, 10);
        mbedtls_debug_set_threshold(level);
    }

    struct mbedtls_engine *engine = container_of(ssl_config, struct mbedtls_engine, config);

    mbedtls_ssl_config_init(ssl_config);
    mbedtls_ssl_conf_dbg(ssl_config, tls_debug_f, stdout);
    mbedtls_ssl_config_defaults(ssl_config,
                                MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_renegotiation(ssl_config, MBEDTLS_SSL_RENEGOTIATION_ENABLED);
    mbedtls_ssl_conf_authmode(ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
    engine->drbg = calloc(1, sizeof(mbedtls_ctr_drbg_context));
    engine->entropy = calloc(1, sizeof(mbedtls_entropy_context));
    mbedtls_ctr_drbg_init(engine->drbg);
    mbedtls_entropy_init(engine->entropy);
    unsigned char *seed = malloc(MBEDTLS_ENTROPY_MAX_SEED_SIZE); // uninitialized memory
    mbedtls_ctr_drbg_seed(engine->drbg, mbedtls_entropy_func, engine->entropy, seed, MBEDTLS_ENTROPY_MAX_SEED_SIZE);
    mbedtls_ssl_conf_rng(ssl_config, mbedtls_ctr_drbg_random, engine->drbg);

    engine->ca = calloc(1, sizeof(mbedtls_x509_crt));
    mbedtls_x509_crt_init(engine->ca);

    if (cabuf != NULL) {
        int rc = cabuf_len > 0 ? mbedtls_x509_crt_parse(engine->ca, (const unsigned char *)cabuf, cabuf_len) : 0;
        if (rc < 0) {
            UM_LOG(VERB, "mbedtls_engine: %s", mbedtls_error(rc));
            mbedtls_x509_crt_init(engine->ca);

            rc = mbedtls_x509_crt_parse_file(engine->ca, cabuf);
            if (rc < 0) {
                UM_LOG(WARN, "failed to load CA from file or memory: %s", mbedtls_error(rc));
            }
        }
    } else { // try loading default CA stores
#if _WIN32
        HCERTSTORE       hCertStore;
        PCCERT_CONTEXT   pCertContext = NULL;

        if (!(hCertStore = CertOpenSystemStore(0, "ROOT")))
        {
            printf("The first system store did not open.");
            return;
        }
        while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) {
            mbedtls_x509_crt_parse(engine->ca, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
        }
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hCertStore, 0);
#else
        const char* sys_bundle = NULL;
        for (size_t i = 0; i < NUM_CAFILES; i++) {
            if (access(caFiles[i], R_OK) != -1) {
                sys_bundle = caFiles[i];
                UM_LOG(INFO, "using system CA bundle[%s]", sys_bundle);
                mbedtls_x509_crt_parse_file(engine->ca, caFiles[i]);
                break;
            }
        }
        if (sys_bundle == NULL) {
            UM_LOG(WARN, "failed to find any of the system CA bundles");
        }
#endif
    }


    mbedtls_ssl_conf_ca_chain(ssl_config, engine->ca, NULL);
    free(seed);
}

static int internal_cert_verify(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    struct mbedtls_engine *eng = ctx;

    // mbedTLS does not verify IP address SANs, here we patch the result if we find a match
    if (depth == 0 && eng->ip_len > 0 && (*flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) != 0) {
        const mbedtls_x509_sequence *cur;
        for (cur = &crt->subject_alt_names; cur != NULL; cur = cur->next) {
            const unsigned char san_type = (unsigned char) cur->buf.tag & MBEDTLS_ASN1_TAG_VALUE_MASK;
            if (san_type == MBEDTLS_X509_SAN_IP_ADDRESS) {
                if (cur->buf.len == eng->ip_len && memcmp(cur->buf.p, &eng->addr, eng->ip_len) == 0) {
                    // found matching address -- can clear the flag
                    *flags &= ~MBEDTLS_X509_BADCERT_CN_MISMATCH;
                    break;
                }
            }
        }
    }

#if defined(__APPLE__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS
    if (*flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
        CFMutableArrayRef certs = CFArrayCreateMutable(kCFAllocatorDefault, 1, &kCFTypeArrayCallBacks);
        mbedtls_x509_crt *c1 = crt;
        SecCertificateRef c;
        while(c1) {
            CFDataRef raw = CFDataCreate(kCFAllocatorDefault, c1->raw.p, (CFIndex)c1->raw.len);
            c = SecCertificateCreateWithData(kCFAllocatorDefault, raw);

            CFArrayAppendValue(certs, c);
            c1 = c1->next;

            CFRelease(c);
            CFRelease(raw);
        }

        SecPolicyRef x509policy = SecPolicyCreateBasicX509();
        SecTrustRef trust;
        OSStatus status = SecTrustCreateWithCertificates(certs, x509policy, &trust);
        if (status == errSecSuccess) {
            CFErrorRef err = 0;
            if (SecTrustEvaluateWithError(trust, &err)) {
                *flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
            } else {
                CFStringRef e = CFErrorCopyDescription(err);
                char errbuf[1024];
                CFStringGetCString(e, errbuf, 1024, kCFStringEncodingUTF8);
                UM_LOG(WARN, "certificate verify failed: %s", errbuf);
                CFRelease(e);
                CFRelease(err);
            }
            CFRelease(trust);
        } else {
            CFStringRef error = SecCopyErrorMessageString(status, NULL);
            char err[128];
            CFStringGetCString(error, err, 128, kCFStringEncodingASCII);
            UM_LOG(WARN, "failed to create Trust object: %s", err);
            CFRelease(error);
        }
        CFRelease(x509policy);
        CFRelease(certs);
    }
#endif
    
    // app wants to verify cert on its own
    // mark intermediate certs as trusted
    // and call app cb for the leaf (depth == 0)
    if (eng->cert_verify_f) {
        if (depth > 0) {
            *flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        } else {
            struct cert_s c;
            c = cert_api;
            c.chain = crt;
            int rc = eng->cert_verify_f((tlsuv_certificate_t) &c, eng->verify_ctx);
            if (rc == 0) {
                *flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
            } else {
                *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
            }
        }
    }
    return 0;
}

tlsuv_engine_t new_mbedtls_engine(void *ctx, const char *host) {
    struct mbedtls_context *context = ctx;

    struct mbedtls_engine *mbed_eng = calloc(1, sizeof(struct mbedtls_engine));
    init_ssl_context(&mbed_eng->config, context->ca, context->ca_len);

    if (context->own_key && context->own_cert) {
        mbedtls_ssl_conf_own_cert(&mbed_eng->config, context->own_cert, &context->own_key->pkey);
    }
    mbedtls_ssl_context *ssl = calloc(1, sizeof(mbedtls_ssl_context));

    mbedtls_ssl_init(ssl);
    mbedtls_ssl_setup(ssl, &mbed_eng->config);
    mbedtls_ssl_set_hostname(ssl, host);

    mbed_eng->api = mbedtls_engine_api;
    mbed_eng->ssl = ssl;

    mbedtls_ssl_set_verify(ssl, internal_cert_verify, mbed_eng);

    if (uv_inet_pton(AF_INET6, host, &mbed_eng->addr) == 0) {
        mbed_eng->ip_len = 16;
    } else if (uv_inet_pton(AF_INET, host, &mbed_eng->addr) == 0) {
        mbed_eng->ip_len = 4;
    }

    mbed_eng->cert_verify_f = context->cert_verify_f;
    mbed_eng->verify_ctx = context->verify_ctx;

    return &mbed_eng->api;
}

static void mbedtls_set_cert_verify(tls_context *ctx,
                                    int (*verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx),
                                    void *v_ctx) {
    struct mbedtls_context *c = (struct mbedtls_context *)ctx;
    c->cert_verify_f = verify_f;
    c->verify_ctx = v_ctx;
}

static size_t mbedtls_sig_to_asn1(const char *sig, size_t siglen, unsigned char *asn1sig) {
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    CK_ULONG coordlen = siglen / 2;
    mbedtls_mpi_read_binary(&r, (const uint8_t *)sig, coordlen);
    mbedtls_mpi_read_binary(&s, (const uint8_t *)sig + coordlen, coordlen);

    int ret;
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char *p = buf + sizeof(buf);
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, &s));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, &r));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    memcpy(asn1sig, p, len);
    return len;
}

static int mbedtls_verify_signature(const struct tlsuv_certificate_s *c, enum hash_algo md, const char* data, size_t datalen, const char* sig, size_t siglen) {

    int type;
    const mbedtls_md_info_t *md_info = NULL;
    switch (md) {
        case hash_SHA256:
            type = MBEDTLS_MD_SHA256;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;
        case hash_SHA384:
            type = MBEDTLS_MD_SHA384;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            break;
        case hash_SHA512:
            type = MBEDTLS_MD_SHA512;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            break;
        default:
            return -1;
    }

    mbedtls_x509_crt *crt = ((struct cert_s*)c)->chain;

    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    if (mbedtls_md(md_info, (uint8_t *)data, datalen, hash) != 0) {
        return -1;
    }

    if (mbedtls_pk_get_type(&crt->pk) == MBEDTLS_PK_ECKEY) {

    }

    int rc = mbedtls_pk_verify(&crt->pk, type, hash, 0, (uint8_t *) sig, siglen);
    if (rc != 0) {
        if (mbedtls_pk_get_type(&crt->pk) == MBEDTLS_PK_ECKEY) {
            unsigned char asn1sig[MBEDTLS_ECDSA_MAX_LEN];
            size_t asn1len = mbedtls_sig_to_asn1(sig, siglen, asn1sig);

            rc = mbedtls_pk_verify(&crt->pk, type, hash, 0, asn1sig, asn1len);
        }
    }
    return rc != 0 ? -1 : 0;
}

static void mbedtls_free_ctx(tls_context *ctx) {
    struct mbedtls_context *c = (struct mbedtls_context *)ctx;
    if (c->own_key) {
        c->own_key->free((struct tlsuv_private_key_s *) c->own_key);
        c->own_key = NULL;
    }

    if (c->own_cert) {
        mbedtls_x509_crt_free(c->own_cert);
        free(c->own_cert);
    }

    free(c->ca);

    free(c);
}

static int mbedtls_reset(tlsuv_engine_t engine) {
    struct mbedtls_engine *e = (struct mbedtls_engine *)engine;
    if (e->session == NULL) {
        e->session = calloc(1, sizeof(mbedtls_ssl_session));
    }
    if (mbedtls_ssl_get_session(e->ssl, e->session) != 0) {
        mbedtls_ssl_session_free(e->session);
        free(e->session);
        e->session = NULL;
    }
    e->io = NULL;
    e->read_f = NULL;
    e->write_f = NULL;
    return mbedtls_ssl_session_reset(e->ssl);
}

static void mbedtls_free(tlsuv_engine_t engine) {
    struct mbedtls_engine *e = (struct mbedtls_engine *)engine;

    mbedtls_ssl_free(e->ssl);
    if (e->ssl) {
        free(e->ssl);
        e->ssl = NULL;
    }
    free(e->ssl);
    if (e->session) {
        mbedtls_ssl_session_free(e->session);
        free(e->session);
    }

    if (e->protocols) {
        for (int i = 0; e->protocols[i] != NULL; i++) {
            free(e->protocols[i]);
        }
        free(e->protocols);
    }
    mbedtls_x509_crt_free(e->ca);
    mbedtls_ssl_config_free(&e->config);
    mbedtls_ctr_drbg_free(e->drbg);
    mbedtls_entropy_free(e->entropy);
    free(e->drbg);
    free(e->entropy);
    free(e->ca);
    free(e);
}

static void mbedtls_free_cert(tlsuv_certificate_t cert) {
    struct cert_s *c = (struct cert_s *) cert;
    mbedtls_x509_crt_free(c->chain);
    free(c);
}

static void mbedtls_set_alpn_protocols(tlsuv_engine_t engine, const char** protos, int len) {
    struct mbedtls_engine *e = (struct mbedtls_engine *)engine;

    e->protocols = calloc(len + 1, sizeof(char*));
    for (int i = 0; i < len; i++) {
        e->protocols[i] = strdup(protos[i]);
    }
    mbedtls_ssl_conf_alpn_protocols(&e->config, (const char **)e->protocols);
}

static int mbedtls_load_cert(tlsuv_certificate_t *c, const char *cert_buf, size_t cert_len) {
    mbedtls_x509_crt *cert = calloc(1, sizeof(mbedtls_x509_crt));
    if (cert_buf[cert_len - 1] != '\0') {
        cert_len += 1;
    }
    int rc = mbedtls_x509_crt_parse(cert, (const unsigned char *)cert_buf, cert_len);
    if (rc < 0) {
        rc = mbedtls_x509_crt_parse_file(cert, cert_buf);
        if (rc < 0) {
            UM_LOG(WARN, "failed to load certificate");
            mbedtls_x509_crt_free(cert);
            free(cert);
            cert = NULL;
        }
    }
    struct cert_s *crt = calloc(1, sizeof(*crt));
    *crt = cert_api;
    crt->chain = cert;
    *c = (tlsuv_certificate_t) crt;
    return rc;
}

static int mbedtls_set_own_cert(tls_context *ctx, tlsuv_private_key_t key, tlsuv_certificate_t cert) {
    struct mbedtls_context *c = (struct mbedtls_context *)ctx;
    int rc = 0;

    if (key == NULL) {
        c->own_key = NULL;
        c->own_cert = NULL;
        return 0;
    }

    if (cert == NULL && key->get_certificate) {
        if (key->get_certificate(key, &cert) != 0) {
            return -1;
        }
    }

    if (cert == NULL) {
        return -1;
    }

    struct priv_key_s *pk = (struct priv_key_s *)key;
    struct cert_s *crt = (struct cert_s *) cert;
    mbedtls_x509_crt *x509 = crt->chain;

#if MBEDTLS_VERSION_MAJOR == 3
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    mbedtls_entropy_free(&entropy);

    if (mbedtls_pk_check_pair(&x509->pk, &pk->pkey, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
#else
    if (mbedtls_pk_check_pair(&x509->pk, &pk->pkey) != 0) {
#endif
        rc = -1;
    } else {
        c->own_cert = crt->chain;
        c->own_key = pk;
    }

#if MBEDTLS_VERSION_MAJOR == 3
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
#endif

    return rc;
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str) {
    ((void) ctx);
    um_log(level, file, line, "%s", str);
}

static int engine_io_write(void *e, const unsigned char *data, size_t len) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) e;
    if (len > INT_MAX) {
        len = INT_MAX;
    }

    ssize_t rc = eng->write_f(eng->io, (const char*)data, len);
    if (rc < 0) {
        if (rc == TLS_AGAIN) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }

        if (rc == TLS_ERR) {
            return MBEDTLS_ERR_NET_SEND_FAILED;
        }
    }
    return (int)rc;
}

static int engine_io_read(void *e, unsigned char *buf, size_t max) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) e;
    if (max > INT_MAX) {
        max = INT_MAX;
    }

    ssize_t rc = eng->read_f(eng->io, (char*)buf, max);

    if (rc < 0) {
        if (rc == TLS_AGAIN) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }

        if (rc == TLS_ERR) {
            return MBEDTLS_ERR_NET_RECV_FAILED;
        }
    }

    return (int)rc;
}

static void mbedtls_set_io(tlsuv_engine_t e, io_ctx io, io_read read_f, io_write write_f) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) e;
    assert(eng->io == NULL);
    eng->io = io;
    eng->read_f = read_f;
    eng->write_f = write_f;
    mbedtls_ssl_set_bio(eng->ssl, eng, engine_io_write, engine_io_read, NULL);
}

static void mbedtls_set_fd(tlsuv_engine_t e, uv_os_fd_t fd) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) e;
    assert(eng->io == NULL);
    eng->io_fd = fd;
    eng->io = &eng->io_fd;
    mbedtls_ssl_set_bio(eng->ssl, eng->io, mbedtls_net_send, mbedtls_net_recv, NULL);
}

static tls_handshake_state mbedtls_hs_state(tlsuv_engine_t engine) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    switch (eng->ssl->MBEDTLS_PRIVATE(state)) {
        case MBEDTLS_SSL_HANDSHAKE_OVER: return TLS_HS_COMPLETE;
        case MBEDTLS_SSL_HELLO_REQUEST: return TLS_HS_BEFORE;
        default: return TLS_HS_CONTINUE;
    }
}

static const char* mbedtls_get_alpn(tlsuv_engine_t engine) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    return mbedtls_ssl_get_alpn_protocol(eng->ssl);
}

static tls_handshake_state
mbedtls_continue_hs(tlsuv_engine_t engine) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;

    if (eng->ssl->MBEDTLS_PRIVATE(state) == MBEDTLS_SSL_HELLO_REQUEST && eng->session) {
        mbedtls_ssl_set_session(eng->ssl, eng->session);
        mbedtls_ssl_session_free(eng->session);
    }

    int state = mbedtls_ssl_handshake(eng->ssl);
    char err[1024];
    mbedtls_strerror(state, err, 1024);

    if (eng->ssl->MBEDTLS_PRIVATE(state) == MBEDTLS_SSL_HANDSHAKE_OVER) {
        return TLS_HS_COMPLETE;
    }
    else if (state == MBEDTLS_ERR_SSL_WANT_READ || state == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return TLS_HS_CONTINUE;
    }
    else {
        eng->error = state;
        return TLS_HS_ERROR;
    }
}

static int mbedtls_write(tlsuv_engine_t engine, const char *data, size_t data_len) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    if (data_len > INT_MAX) {
        data_len = INT_MAX;
    }

    int err = 0;
    size_t wrote = 0;
    while (data_len > wrote) {
        int rc = mbedtls_ssl_write(eng->ssl, (const unsigned char *)(data + wrote), data_len - wrote);
        if (rc < 0) {
            err = rc;
            break;
        }
        wrote += rc;
    }

    if (wrote > 0) {
        return (int)wrote;
    }

    if (err == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return TLS_AGAIN;
    }
    return TLS_ERR;
}

static int mbedtls_read(tlsuv_engine_t engine, char *out, size_t *out_bytes, size_t max) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;

    int rc;
    uint8_t *writep = (uint8_t*)out;
    size_t total_out = 0;

    int err = 0;
    while (max > total_out) {
        rc = mbedtls_ssl_read(eng->ssl, writep, max - total_out);
        if (rc < 0) {
            if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
                err = TLS_AGAIN;
            } else if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                UM_LOG(DEBG, "mbedTLS: peer close notify");
                eng->error = rc;
                err = TLS_EOF;
            } else {
                UM_LOG(ERR, "mbedTLS: %0x(%s)", rc, mbedtls_error(rc));
                eng->error = rc;
                err = TLS_ERR;
            }
            break;
        }
        if (rc == 0) {
            err = TLS_EOF;
            break;
        }

        total_out += rc;
        writep += rc;
    }

    if (total_out > 0) {
        *out_bytes = total_out;
        return mbedtls_ssl_get_bytes_avail(eng->ssl) > 0 ? TLS_MORE_AVAILABLE : TLS_OK;
    }

    *out_bytes = total_out;
    return err;
}

static int mbedtls_close(tlsuv_engine_t engine) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    mbedtls_ssl_close_notify(eng->ssl);
    return 0;
}

#define OID_PKCS7 MBEDTLS_OID_PKCS "\x07"
#define OID_PKCS7_DATA OID_PKCS7 "\x02"
#define OID_PKCS7_SIGNED_DATA OID_PKCS7 "\x01"

static int parse_pkcs7_certs(tlsuv_certificate_t *chain, const char *pkcs7, size_t pkcs7len) {
    size_t der_len;
    unsigned char *p;
    unsigned char *end;
    unsigned char *cert_buf;

    int rc = mbedtls_base64_decode(NULL, 0, &der_len, (const uint8_t *)pkcs7, pkcs7len); // determine necessary buffer size
    if (rc != 0 && rc != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        UM_LOG(ERR, "base64 decoding parsing error: %d", rc);
        return rc;
    }
    uint8_t *base64_decoded_pkcs7 = calloc(1, der_len + 1);
    rc = mbedtls_base64_decode(base64_decoded_pkcs7, der_len, &der_len, (const uint8_t *)pkcs7, pkcs7len);
    if (rc != 0) {
        UM_LOG(ERR, "base64 decoding parsing error: %d", rc);
        return rc;
    }

    unsigned char *der = (unsigned char *) base64_decoded_pkcs7;

    p = der;
    end = der + der_len;
    size_t len;

    if ((rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        UM_LOG(ERR, "ASN.1 parsing error: %d", rc);
        return rc;
    }

    if ((rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID)) != 0) {
        UM_LOG(ERR, "ASN.1 parsing error: %d", rc);
        return rc;
    }

    mbedtls_asn1_buf oid;
    oid.p = p;
    oid.len = len;
    if (!MBEDTLS_OID_CMP(OID_PKCS7_SIGNED_DATA, &oid)) {
        UM_LOG(ERR, "invalid pkcs7 signed data");
        return -1;
    }
    p += len;

    if ((rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC)) != 0) {
        UM_LOG(ERR, "ASN.1 parsing error: %d", rc);
        return rc;
    }

    if ((rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        UM_LOG(ERR, "ASN.1 parsing error: %d", rc);
        return rc;
    }

    int ver;
    if ((rc = mbedtls_asn1_get_int(&p, end, &ver)) != 0) {
        UM_LOG(ERR, "ASN.1 parsing error: %d", rc);
        return rc;
    }

    if ((rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0) {
        UM_LOG(ERR, "ASN.1 parsing error: %d", rc);
        return rc;
    }

    if ((rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        UM_LOG(ERR, "ASN.1 parsing error: %d", rc);
        return rc;
    }

    if ((rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID)) != 0) {
        UM_LOG(ERR, "ASN.1 parsing error: %d", rc);
        return rc;
    }

    oid.p = p;
    oid.len = len;
    if (!MBEDTLS_OID_CMP(OID_PKCS7_DATA, &oid)) {
        UM_LOG(ERR, "invalid pkcs7 data");
        return -1;
    }
    p += len;

    if ((rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC)) != 0) {
        UM_LOG(ERR, "ASN.1 parsing error: %d", rc);
        return rc;
    }

    cert_buf = p;
    mbedtls_x509_crt *certs = NULL;
    do {
        size_t cert_len;
        unsigned char *cbp = cert_buf;
        rc = mbedtls_asn1_get_tag(&cbp, end, &cert_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (rc != 0) {
            break;
        }

        if (certs == NULL) {
            certs = calloc(1, sizeof(mbedtls_x509_crt));
        }
        cert_len += (cbp - cert_buf);
        rc = mbedtls_x509_crt_parse(certs, cert_buf, cert_len);
        if (rc != 0) {
            UM_LOG(ERR, "failed to parse cert: %d", rc);
            mbedtls_x509_crt_free(certs);
            free(certs);
            *chain = NULL;
            return rc;
        }
        cert_buf += cert_len;

    } while (rc == 0);

    free(der);
    struct cert_s *c = calloc(1, sizeof(*c));
    *c = cert_api;
    c->chain = certs;
    *chain = (tlsuv_certificate_t) c;
    return 0;
}

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"
static int write_cert_pem(const struct tlsuv_certificate_s * cert, int full_chain, char **pem, size_t *pemlen) {
    mbedtls_x509_crt *c = ((struct cert_s*)cert)->chain;

    size_t total_len = 0;
    while (c != NULL) {
        size_t len;
        mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT, c->raw.p, c->raw.len, NULL, 0, &len);
        total_len += len;
        if (!full_chain) { break; }
        c = c->next;
    }

    uint8_t *pembuf = malloc(total_len + 1);
    uint8_t *p = pembuf;
    c = ((struct cert_s*)cert)->chain;
    while (c != NULL) {
        size_t len;
        mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT, c->raw.p, c->raw.len, p, total_len - (p - pembuf), &len);
        p += (len - 1);
        if (!full_chain) {
            break;
        }
        c = c->next;
    }

    *pem = (char *) pembuf;
    *pemlen = total_len;
    return 0;
}


static int generate_csr(tlsuv_private_key_t key, char **pem, size_t *pemlen, ...) {
    struct priv_key_s *k = (struct priv_key_s *) key;

    int ret;
    mbedtls_pk_context *pk = &k->pkey;
    mbedtls_ctr_drbg_context ctr_drbg;
    char buf[1024];
    mbedtls_entropy_context entropy;
    const char *pers = "gen_csr";

    mbedtls_x509write_csr csr;
    // Set to sane values
    mbedtls_x509write_csr_init(&csr);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    memset(buf, 0, sizeof(buf));

    char subject_name[MBEDTLS_X509_MAX_DN_NAME_SIZE];
    char *s = subject_name;
    va_list va;
    va_start(va, pemlen);
    bool first = true;
    while (true) {
        char *id = va_arg(va, char*);
        if (id == NULL) { break; }

        char *val = va_arg(va, char*);
        if (val == NULL) { break; }

        if (!first) {
            *s++ = ',';
        }
        else {
            first = false;
        }
        strcpy(s, id);
        s += strlen(id);
        *s++ = '=';
        strcpy(s, val);
        s += strlen(val);
    }
    *s = '\0';


    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key_usage(&csr, 0);
    mbedtls_x509write_csr_set_ns_cert_type(&csr, MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT);
    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        UM_LOG(ERR, "mbedtls_ctr_drbg_seed returned %d: %s", ret, mbedtls_error(ret));
        goto on_error;
    }

    if ((ret = mbedtls_x509write_csr_set_subject_name(&csr, subject_name)) != 0) {
        UM_LOG(ERR, "mbedtls_x509write_csr_set_subject_name returned %d", ret);
        goto on_error;
    }

    mbedtls_x509write_csr_set_key(&csr, pk);
    uint8_t pembuf[4096];
    if ((ret = mbedtls_x509write_csr_pem(&csr, pembuf, sizeof(pembuf), mbedtls_ctr_drbg_random, &ctr_drbg)) < 0) {
        UM_LOG(ERR, "mbedtls_x509write_csr_pem returned %d/%s", ret, mbedtls_error(ret));
        goto on_error;
    }
    on_error:
    if (ret == 0) {
        *pem = strdup((const char*)pembuf);
        if (pemlen) {
            *pemlen = strlen((const char *)pembuf);
        }
    }
    mbedtls_x509write_csr_free(&csr);
    return ret;
}
