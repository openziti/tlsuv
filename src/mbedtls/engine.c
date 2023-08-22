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
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>

#include "../bio.h"
#include "../um_debug.h"
#include "keys.h"
#include "mbed_p11.h"
#include <tlsuv/tlsuv.h>

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
    int (*cert_verify_f)(void *cert, void *v_ctx);
    void *verify_ctx;
};

struct mbedtls_engine {
    struct tlsuv_engine_s api;

    char **protocols;
    mbedtls_ssl_config config;
    mbedtls_x509_crt *ca;
    mbedtls_ssl_context *ssl;
    mbedtls_ssl_session *session;
    tlsuv_BIO *in;
    tlsuv_BIO *out;
    int error;

    int ip_len;
    struct in6_addr addr;
    int (*cert_verify_f)(void *cert, void *v_ctx);
    void *verify_ctx;
    mbedtls_ctr_drbg_context *drbg;
    mbedtls_entropy_context *entropy;
};

static void mbedtls_set_alpn_protocols(tlsuv_engine_t engine, const char** protos, int len);
static int mbedtls_set_own_key(tls_context *ctx, tlsuv_private_key_t key);
static int mbedtls_set_own_cert(tls_context *ctx, tlsuv_private_key_t key, tls_cert cert);
static int mbedtls_set_own_cert_p11(void *ctx, const char *cert_buf, size_t cert_len,
            const char *pkcs11_lib, const char *pin, const char *slot, const char *key_id);

static int mbedtls_load_key_p11(tlsuv_private_key_t *key, const char *string, const char *string1, const char *string2, const char *string3, const char *string4);

tlsuv_engine_t new_mbedtls_engine(void *ctx, const char *host);

static tls_handshake_state mbedtls_hs_state(tlsuv_engine_t engine);
static tls_handshake_state
mbedtls_continue_hs(tlsuv_engine_t engine, char *in, size_t in_bytes, char *out, size_t *out_bytes, size_t maxout);

static const char* mbedtls_get_alpn(tlsuv_engine_t engine);

static int mbedtls_write(tlsuv_engine_t engine, const char *data, size_t data_len, char *out, size_t *out_bytes, size_t maxout);

static int
mbedtls_read(tlsuv_engine_t engine, const char *ssl_in, size_t ssl_in_len, char *out, size_t *out_bytes, size_t maxout);

static int mbedtls_close(tlsuv_engine_t engine, char *out, size_t *out_bytes, size_t maxout);

static int mbedtls_reset(tlsuv_engine_t engine);

static const char *mbedtls_version();

static const char *mbedtls_eng_error(tlsuv_engine_t engine);

static void mbedtls_free(tlsuv_engine_t engine);

static void mbedtls_free_ctx(tls_context *ctx);

static void mbedtls_free_cert(tls_cert *cert);

static void mbedtls_set_cert_verify(tls_context *ctx, int (*verify_f)(void *cert, void *v_ctx), void *v_ctx);

static int mbedtls_verify_signature(void *cert, enum hash_algo md, const char *data, size_t datalen, const char *sig,
                                    size_t siglen);

static int parse_pkcs7_certs(tls_cert *chain, const char *pkcs7, size_t pkcs7len);

static int write_cert_pem(tls_cert cert, int full_chain, char **pem, size_t *pemlen);

static int generate_csr(tlsuv_private_key_t key, char **pem, size_t *pemlen, ...);

static int mbedtls_load_cert(tls_cert *c, const char *cert, size_t certlen);

static tls_context mbedtls_context_api = {
        .version = mbedtls_version,
        .strerror = mbedtls_error,
        .new_engine = new_mbedtls_engine,
        .free_ctx = mbedtls_free_ctx,
        .free_cert = mbedtls_free_cert,
        .set_own_cert = mbedtls_set_own_cert,
        .set_cert_verify = mbedtls_set_cert_verify,
        .verify_signature =  mbedtls_verify_signature,
        .parse_pkcs7_certs = parse_pkcs7_certs,
        .write_cert_to_pem = write_cert_pem,
        .generate_key = gen_key,
        .load_key = load_key,
        .load_pkcs11_key = load_key_p11,
        .load_cert = mbedtls_load_cert,
        .generate_csr_to_pem = generate_csr,
};

static struct tlsuv_engine_s mbedtls_engine_api = {
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

static const char* NO_PROTOCOL[] = { NULL };

static void init_ssl_context(mbedtls_ssl_config *ssl_config, const char *ca, size_t cabuf_len);

static int mbed_ssl_recv(void *ctx, uint8_t *buf, size_t len);

static int mbed_ssl_send(void *ctx, const uint8_t *buf, size_t len);

static const char* mbedtls_version() {
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
            UM_LOG(WARN, "mbedtls_engine: %s\n", mbedtls_error(rc));
            mbedtls_x509_crt_init(engine->ca);

            rc = mbedtls_x509_crt_parse_file(engine->ca, cabuf);
            UM_LOG(WARN, "mbedtls_engine: %s\n", mbedtls_error(rc));
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
        for (size_t i = 0; i < NUM_CAFILES; i++) {
            if (access(caFiles[i], R_OK) != -1) {
                mbedtls_x509_crt_parse_file(engine->ca, caFiles[i]);
                break;
            }
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

    // app wants to verify cert on its own
    // mark intermediate certs as trusted
    // and call app cb for the leaf (depth == 0)
    if (eng->cert_verify_f) {
        if (depth > 0) {
            *flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        } else {
            int rc = eng->cert_verify_f(crt, eng->verify_ctx);
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
    mbed_eng->in = tlsuv_BIO_new();
    mbed_eng->out = tlsuv_BIO_new();
    mbedtls_ssl_set_bio(ssl, mbed_eng, mbed_ssl_send, mbed_ssl_recv, NULL);

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

static void mbedtls_set_cert_verify(tls_context *ctx, int (*verify_f)(void *cert, void *v_ctx), void *v_ctx) {
    struct mbedtls_context *c = ctx;
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

static int mbedtls_verify_signature(void *cert, enum hash_algo md, const char* data, size_t datalen, const char* sig, size_t siglen) {

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

    mbedtls_x509_crt *crt = cert;

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
    struct mbedtls_context *c = ctx;
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
    return mbedtls_ssl_session_reset(e->ssl);
}

static void mbedtls_free(tlsuv_engine_t engine) {
    struct mbedtls_engine *e = (struct mbedtls_engine *)engine;
    tlsuv_BIO_free(e->in);
    tlsuv_BIO_free(e->out);

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

static void mbedtls_free_cert(tls_cert *cert) {
    mbedtls_x509_crt *c = *cert;
    mbedtls_x509_crt_free(c);
    free(c);
    *cert = NULL;
}

static void mbedtls_set_alpn_protocols(tlsuv_engine_t engine, const char** protos, int len) {
    struct mbedtls_engine *e = (struct mbedtls_engine *)engine;

    e->protocols = calloc(len + 1, sizeof(char*));
    for (int i = 0; i < len; i++) {
        e->protocols[i] = strdup(protos[i]);
    }
    mbedtls_ssl_conf_alpn_protocols(&e->config, e->protocols);
}

static int mbedtls_set_own_key(tls_context *ctx, tlsuv_private_key_t key) {
    struct mbedtls_context *c = ctx;
    c->own_key = (struct priv_key_s *) key;
    return 0;
}

static int mbedtls_load_cert(tls_cert *c, const char *cert_buf, size_t cert_len) {
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
    *c = cert;
    return rc;
}

static int mbedtls_set_own_cert(tls_context *ctx, tlsuv_private_key_t key, tls_cert cert) {
    struct mbedtls_context *c = ctx;
    int rc;

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
    mbedtls_x509_crt *x509 = cert;

    if (mbedtls_pk_check_pair(&x509->pk, &pk->pkey) != 0) {
        return -1;
    }

    c->own_cert = cert;
    c->own_key = pk;

    return 0;
}

static int mbedtls_set_own_cert_p11(void *ctx, const char *cert_buf, size_t cert_len,
        const char *pkcs11_lib, const char *pin, const char *slot, const char *key_id) {

    struct mbedtls_context *c = ctx;
    c->own_key = calloc(1, sizeof(*c->own_key));
    int rc = mp11_load_key(&c->own_key->pkey, pkcs11_lib, pin, slot, key_id);
    if (rc != CKR_OK) {
        fprintf(stderr, "failed to load private key - %s", p11_strerror(rc));
        mbedtls_pk_free(&c->own_key->pkey);
        free(c->own_key);
        c->own_key = NULL;
        return TLS_ERR;
    }

    c->own_cert = calloc(1, sizeof(mbedtls_x509_crt));
    rc = mbedtls_x509_crt_parse(c->own_cert, (const unsigned char *)cert_buf, cert_len);
    if (rc < 0) {
        rc = mbedtls_x509_crt_parse_file(c->own_cert, cert_buf);
        if (rc < 0) {
            fprintf(stderr, "failed to load certificate");
            mbedtls_x509_crt_free(c->own_cert);
            free(c->own_cert);
            c->own_cert = NULL;

            c->own_key->free((struct tlsuv_private_key_s *) c->own_key);
            c->own_key = NULL;
            return TLS_ERR;
        }
    }

    return TLS_OK;
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str) {
    ((void) level);
    printf("%s:%04d: %s", file, line, str);
    fflush(stdout);
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
mbedtls_continue_hs(tlsuv_engine_t engine, char *in, size_t in_bytes, char *out, size_t *out_bytes, size_t maxout) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    if (in_bytes > 0) {
        tlsuv_BIO_put(eng->in, (const unsigned char *) in, in_bytes);
    }

    if (eng->ssl->MBEDTLS_PRIVATE(state) == MBEDTLS_SSL_HELLO_REQUEST && eng->session) {
        mbedtls_ssl_set_session(eng->ssl, eng->session);
        mbedtls_ssl_session_free(eng->session);
    }

    int state = mbedtls_ssl_handshake(eng->ssl);
    char err[1024];
    mbedtls_strerror(state, err, 1024);
    *out_bytes = tlsuv_BIO_read(eng->out, (unsigned char *) out, maxout);

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

static int mbedtls_write(tlsuv_engine_t engine, const char *data, size_t data_len, char *out, size_t *out_bytes, size_t maxout) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    size_t wrote = 0;
    while (data_len > wrote) {
        int rc = mbedtls_ssl_write(eng->ssl, (const unsigned char *)(data + wrote), data_len - wrote);
        if (rc < 0) {
            eng->error = rc;
            return rc;
        }
        wrote += rc;
    }
    *out_bytes = tlsuv_BIO_read(eng->out, (unsigned char *) out, maxout);
    return (int) tlsuv_BIO_available(eng->out);
}

static int
mbedtls_read(tlsuv_engine_t engine, const char *ssl_in, size_t ssl_in_len, char *out, size_t *out_bytes, size_t maxout) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    if (ssl_in_len > 0 && ssl_in != NULL) {
        tlsuv_BIO_put(eng->in, (const unsigned char *) ssl_in, ssl_in_len);
    }

    int rc;
    uint8_t *writep = (uint8_t*)out;
    size_t total_out = 0;

    do {
        rc = mbedtls_ssl_read(eng->ssl, writep, maxout - total_out);

        if (rc > 0) {
            total_out += rc;
            writep += rc;
        }
    } while(rc > 0 && (maxout - total_out) > 0);

    *out_bytes = total_out;

    // this indicates that more bytes are needed to complete SSL frame
    if (rc == MBEDTLS_ERR_SSL_WANT_READ) {
        return tlsuv_BIO_available(eng->out) > 0 ? TLS_HAS_WRITE : TLS_OK;
    }

    if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        return TLS_EOF;
    }

    if (rc < 0) {
        eng->error = rc;
        char err[1024];
        mbedtls_strerror(rc, err, 1024);
        UM_LOG(ERR, "mbedTLS: %0x(%s)", rc, err);
        return TLS_ERR;
    }

    if (tlsuv_BIO_available(eng->in) > 0 || mbedtls_ssl_check_pending(eng->ssl)) {
        return TLS_MORE_AVAILABLE;
    }

    return TLS_OK;
}

static int mbedtls_close(tlsuv_engine_t engine, char *out, size_t *out_bytes, size_t maxout) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    mbedtls_ssl_close_notify(eng->ssl); // TODO handle error

    *out_bytes = tlsuv_BIO_read(eng->out, (unsigned char *) out, maxout);
    return 0;
}

static int mbed_ssl_recv(void *ctx, uint8_t *buf, size_t len) {
    struct mbedtls_engine *eng = ctx;
    if (tlsuv_BIO_available(eng->in) == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    return tlsuv_BIO_read(eng->in, buf, len);
}

static int mbed_ssl_send(void *ctx, const uint8_t *buf, size_t len) {
    struct mbedtls_engine *eng = ctx;
    tlsuv_BIO_put(eng->out, buf, len);
    return (int) len;
}

#define OID_PKCS7 MBEDTLS_OID_PKCS "\x07"
#define OID_PKCS7_DATA OID_PKCS7 "\x02"
#define OID_PKCS7_SIGNED_DATA OID_PKCS7 "\x01"

#define MBEDTLS_OID_CMP_PRIVATE(oid_str, oid_buf)                                   \
                ( ( MBEDTLS_OID_SIZE(oid_str) != (oid_buf)->MBEDTLS_PRIVATE(len) ) ||                \
                  memcmp( (oid_str), (oid_buf)->MBEDTLS_PRIVATE(p), (oid_buf)->MBEDTLS_PRIVATE(len)) != 0 )

static int parse_pkcs7_certs(tls_cert *chain, const char *pkcs7, size_t pkcs7len) {
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
    *chain = certs;
    return 0;
}

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"
static int write_cert_pem(tls_cert cert, int full_chain, char **pem, size_t *pemlen) {
    mbedtls_x509_crt *c = cert;

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
    c = cert;
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

    int ret = 1;
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
        UM_LOG(ERR, "mbedtls_x509write_csr_pem returned %d", ret);
        goto on_error;
    }
    on_error:
    if (ret == 0) {
        *pem = strdup((const char*)pembuf);
        *pemlen = strlen((const char*)pembuf) + 1;
    }
    mbedtls_x509write_csr_free(&csr);
    return ret;
}