/*
Copyright 2019-2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


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
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/error.h>

#include "bio.h"
#include "p11_mbedtls/mbed_p11.h"
#include "um_debug.h"
#include <uv_mbed/uv_mbed.h>

#if _WIN32
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#else

#include <unistd.h>

#endif

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
    mbedtls_ssl_config config;
    mbedtls_pk_context *own_key;
    mbedtls_x509_crt *own_cert;
    const char **alpn_protocols;
    int (*cert_verify_f)(void *cert, void *v_ctx);
    void *verify_ctx;
};

struct mbedtls_engine {
    mbedtls_ssl_context *ssl;
    mbedtls_ssl_session *session;
    um_BIO  *in;
    um_BIO *out;
    int error;
};

static void mbedtls_set_alpn_protocols(void *ctx, const char** protos, int len);
static int mbedtls_set_own_cert(void *ctx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len);
static int mbedtls_set_own_cert_p11(void *ctx, const char *cert_buf, size_t cert_len,
            const char *pkcs11_lib, const char *pin, const char *slot, const char *key_id);

tls_engine *new_mbedtls_engine(void *ctx, const char *host);

static tls_handshake_state mbedtls_hs_state(void *engine);
static tls_handshake_state
mbedtls_continue_hs(void *engine, char *in, size_t in_bytes, char *out, size_t *out_bytes, size_t maxout);

static const char* mbedtls_get_alpn(void *engine);

static int mbedtls_write(void *engine, const char *data, size_t data_len, char *out, size_t *out_bytes, size_t maxout);

static int
mbedtls_read(void *engine, const char *ssl_in, size_t ssl_in_len, char *out, size_t *out_bytes, size_t maxout);

static int mbedtls_close(void *engine, char *out, size_t *out_bytes, size_t maxout);

static int mbedtls_reset(void *engine);

static const char *mbedtls_error(int code);

static const char *mbedtls_eng_error(void *eng);

static void mbedtls_free(tls_engine *engine);

static void mbedtls_free_ctx(tls_context *ctx);

static void mbedtls_free_key(tls_private_key *k);
static void mbedtls_free_cert(tls_cert *cert);

static void mbedtls_set_cert_verify(tls_context *ctx, int (*verify_f)(void *cert, void *v_ctx), void *v_ctx);

static int mbedtls_verify_signature(void *cert, enum hash_algo md, const char *data, size_t datalen, const char *sig,
                                    size_t siglen);

static int parse_pkcs7_certs(tls_cert *chain, const char *pkcs7, size_t pkcs7len);

static int write_cert_pem(tls_cert cert, int full_chain, char **pem, size_t *pemlen);

static int write_key_pem(tls_private_key pk, char **pem, size_t *pemlen);

static int gen_key(tls_private_key *key);
static int load_key(tls_private_key *key, const char* keydata, size_t keydatalen);

static int generate_csr(tls_private_key key, char **pem, size_t *pemlen, ...);

static tls_context_api mbedtls_context_api = {
        .strerror = mbedtls_error,
        .new_engine = new_mbedtls_engine,
        .free_engine = mbedtls_free,
        .free_ctx = mbedtls_free_ctx,
        .free_key = mbedtls_free_key,
        .free_cert = mbedtls_free_cert,
        .set_alpn_protocols = mbedtls_set_alpn_protocols,
        .set_own_cert = mbedtls_set_own_cert,
        .set_own_cert_pkcs11 = mbedtls_set_own_cert_p11,
        .set_cert_verify = mbedtls_set_cert_verify,
        .verify_signature =  mbedtls_verify_signature,
        .parse_pkcs7_certs = parse_pkcs7_certs,
        .write_cert_to_pem = write_cert_pem,
        .generate_key = gen_key,
        .load_key = load_key,
        .write_key_to_pem = write_key_pem,
        .generate_csr_to_pem = generate_csr,
};

static tls_engine_api mbedtls_engine_api = {
        .handshake_state = mbedtls_hs_state,
        .handshake = mbedtls_continue_hs,
        .get_alpn = mbedtls_get_alpn,
        .close = mbedtls_close,
        .write = mbedtls_write,
        .read = mbedtls_read,
        .reset = mbedtls_reset,
        .strerror = mbedtls_eng_error
};


static void init_ssl_context(mbedtls_ssl_config *ssl_config, const char *ca, size_t cabuf_len);

static int mbed_ssl_recv(void *ctx, uint8_t *buf, size_t len);

static int mbed_ssl_send(void *ctx, const uint8_t *buf, size_t len);


static const char *mbedtls_error(int code) {
    static char errbuf[1024];
    mbedtls_strerror(code, errbuf, sizeof(errbuf));
    return errbuf;

}

static const char *mbedtls_eng_error(void *eng) {
    struct mbedtls_engine *e = eng;
    return mbedtls_error(e->error);
}

tls_context *new_mbedtls_ctx(const char *ca, size_t ca_len) {
    tls_context *ctx = calloc(1, sizeof(tls_context));
    ctx->api = &mbedtls_context_api;
    struct mbedtls_context *c = calloc(1, sizeof(struct mbedtls_context));
    init_ssl_context(&c->config, ca, ca_len);
    ctx->ctx = c;

    return ctx;
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str);

static void init_ssl_context(mbedtls_ssl_config *ssl_config, const char *cabuf, size_t cabuf_len) {
    char *tls_debug = getenv("MBEDTLS_DEBUG");
    if (tls_debug != NULL) {
        int level = (int) strtol(tls_debug, NULL, 10);
        mbedtls_debug_set_threshold(level);
    }

    mbedtls_ssl_config_init(ssl_config);
    mbedtls_ssl_conf_dbg(ssl_config, tls_debug_f, stdout);
    mbedtls_ssl_config_defaults(ssl_config,
                                MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_renegotiation(ssl_config, MBEDTLS_SSL_RENEGOTIATION_ENABLED);
    mbedtls_ssl_conf_authmode(ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ctr_drbg_context *drbg = calloc(1, sizeof(mbedtls_ctr_drbg_context));
    mbedtls_entropy_context *entropy = calloc(1, sizeof(mbedtls_entropy_context));
    mbedtls_ctr_drbg_init(drbg);
    mbedtls_entropy_init(entropy);
    unsigned char *seed = malloc(MBEDTLS_ENTROPY_MAX_SEED_SIZE); // uninitialized memory
    mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, entropy, seed, MBEDTLS_ENTROPY_MAX_SEED_SIZE);
    mbedtls_ssl_conf_rng(ssl_config, mbedtls_ctr_drbg_random, drbg);
    mbedtls_x509_crt *ca = calloc(1, sizeof(mbedtls_x509_crt));
    mbedtls_x509_crt_init(ca);

    if (cabuf != NULL) {
        int rc = cabuf_len > 0 ? mbedtls_x509_crt_parse(ca, (const unsigned char *)cabuf, cabuf_len) : 0;
        if (rc < 0) {
            UM_LOG(WARN, "mbedtls_engine: %s\n", mbedtls_error(rc));
            mbedtls_x509_crt_init(ca);

            rc = mbedtls_x509_crt_parse_file(ca, cabuf);
            UM_LOG(WARN, "mbedtls_engine: %s\n", mbedtls_error(rc));
        }
    }
    else { // try loading default CA stores
#if _WIN32
        HCERTSTORE       hCertStore;
        PCCERT_CONTEXT   pCertContext = NULL;

        if (!(hCertStore = CertOpenSystemStore(0, "ROOT")))
        {
            printf("The first system store did not open.");
            return;
        }
        while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) {
            mbedtls_x509_crt_parse(ca, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
        }
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hCertStore, 0);
#else
        for (size_t i = 0; i < NUM_CAFILES; i++) {
            if (access(caFiles[i], R_OK) != -1) {
                mbedtls_x509_crt_parse_file(ca, caFiles[i]);
                break;
            }
        }
#endif
    }


    mbedtls_ssl_conf_ca_chain(ssl_config, ca, NULL);
    free(seed);
}

tls_engine *new_mbedtls_engine(void *ctx, const char *host) {
    struct mbedtls_context *context = ctx;
    mbedtls_ssl_context *ssl = calloc(1, sizeof(mbedtls_ssl_context));
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_setup(ssl, &context->config);
    mbedtls_ssl_set_hostname(ssl, host);

    tls_engine *engine = calloc(1, sizeof(tls_engine));
    struct mbedtls_engine *mbed_eng = calloc(1, sizeof(struct mbedtls_engine));
    engine->engine = mbed_eng;
    mbed_eng->ssl = ssl;
    mbed_eng->in = um_BIO_new(0);
    mbed_eng->out = um_BIO_new(0);
    mbedtls_ssl_set_bio(ssl, mbed_eng, mbed_ssl_send, mbed_ssl_recv, NULL);
    engine->api = &mbedtls_engine_api;

    return engine;
}

static int cert_verify_cb(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    struct mbedtls_context *c = ctx;
    if (depth > 0) {
        *flags = (*flags) & ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        return 0;
    }

    if (depth == 0 && c->cert_verify_f) {
        int rc = c->cert_verify_f(crt, c->verify_ctx);
        if (rc == 0) {
            *flags = (*flags) & ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        } else {
            return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        }
    }
    return 0;
}

static void mbedtls_set_cert_verify(tls_context *ctx, int (*verify_f)(void *cert, void *v_ctx), void *v_ctx) {
    struct mbedtls_context *c = ctx->ctx;
    c->cert_verify_f = verify_f;
    c->verify_ctx = v_ctx;
    mbedtls_ssl_conf_verify(&c->config, cert_verify_cb, c);
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

    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    if (mbedtls_md(md_info, (uint8_t *)data, datalen, hash) != 0) {
        return -1;
    }

    mbedtls_x509_crt *crt = cert;
    if (mbedtls_pk_verify(&crt->pk, type, hash, 0, (uint8_t *)sig, siglen) != 0) {
        return -1;
    }

    return 0;
}


static void mbedtls_free_ctx(tls_context *ctx) {
    struct mbedtls_context *c = ctx->ctx;
    mbedtls_x509_crt_free(c->config.ca_chain);
    free(c->config.ca_chain);
    mbedtls_ctr_drbg_context *drbg = c->config.p_rng;
    mbedtls_entropy_free(drbg->p_entropy);
    free(drbg->p_entropy);
    mbedtls_ctr_drbg_free(drbg);
    free(drbg);

    if (c->alpn_protocols) {
        const char **p = c->alpn_protocols;
        while(*p) {
            free((void*)*p);
            p++;
        }
        free(c->alpn_protocols);
    }

    if (c->own_key) {
        mbedtls_pk_free(c->own_key);
        free(c->own_key);
    }

    if (c->own_cert) {
        mbedtls_x509_crt_free(c->own_cert);
        free(c->own_cert);
    }

    mbedtls_ssl_config_free(&c->config);
    free(c);
    free(ctx);
}

static int mbedtls_reset(void *engine) {
    struct mbedtls_engine *e = engine;
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

static void mbedtls_free(tls_engine *engine) {
    struct mbedtls_engine *e = engine->engine;
    um_BIO_free(e->in);
    um_BIO_free(e->out);

    mbedtls_ssl_free(e->ssl);
    if (e->ssl) {
        free(e->ssl);
        e->ssl = NULL;
    }
    if (e->session) {
        mbedtls_ssl_session_free(e->session);
        free(e->session);
    }
    free(e);
    free(engine);
}

static void mbedtls_free_key(tls_private_key *k) {
    mbedtls_pk_context *key = *k;
    mbedtls_pk_free(key);
    free(key);
    *k = NULL;
}

static void mbedtls_free_cert(tls_cert *cert) {
    mbedtls_x509_crt *c = *cert;
    mbedtls_x509_crt_free(c);
    free(c);
    *cert = NULL;
}

static void mbedtls_set_alpn_protocols(void *ctx, const char** protos, int len) {
    struct mbedtls_context *c = ctx;
    if (c->alpn_protocols) {
        const char **p = c->alpn_protocols;
        while(*p) {
            free((char*)*p);
            p++;
        }
        free(c->alpn_protocols);
    }
    c->alpn_protocols = calloc(len + 1, sizeof(char*));
    for (int i = 0; i < len; i++) {
        c->alpn_protocols[i] = strdup(protos[i]);
    }
    mbedtls_ssl_conf_alpn_protocols(&c->config, c->alpn_protocols);
}

static int mbedtls_set_own_cert(void *ctx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len) {
    struct mbedtls_context *c = ctx;
    int rc = load_key((tls_private_key *) &c->own_key, key_buf, key_len);
    if (rc != 0) return rc;


    c->own_cert = calloc(1, sizeof(mbedtls_x509_crt));
    rc = mbedtls_x509_crt_parse(c->own_cert, (const unsigned char *)cert_buf, cert_len);
    if (rc < 0) {
        rc = mbedtls_x509_crt_parse_file(c->own_cert, cert_buf);
        if (rc < 0) {
            fprintf(stderr, "failed to load certificate");
            mbedtls_x509_crt_free(c->own_cert);
            free(c->own_cert);
            c->own_cert = NULL;

            mbedtls_pk_free(c->own_key);
            free(c->own_key);
            c->own_key = NULL;
            return rc;
        }
    }

    rc = mbedtls_ssl_conf_own_cert(&c->config, c->own_cert, c->own_key);
    return rc;
}

static int mbedtls_set_own_cert_p11(void *ctx, const char *cert_buf, size_t cert_len,
        const char *pkcs11_lib, const char *pin, const char *slot, const char *key_id) {

    struct mbedtls_context *c = ctx;
    c->own_key = calloc(1, sizeof(mbedtls_pk_context));
    int rc = mp11_load_key(c->own_key, pkcs11_lib, pin, slot, key_id);
    if (rc != CKR_OK) {
        fprintf(stderr, "failed to load private key - %s", p11_strerror(rc));
        mbedtls_pk_free(c->own_key);
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

            mbedtls_pk_free(c->own_key);
            free(c->own_key);
            c->own_key = NULL;
            return TLS_ERR;
        }
    }

    mbedtls_ssl_conf_own_cert(&c->config, c->own_cert, c->own_key);
    return TLS_OK;
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str) {
    ((void) level);
    printf("%s:%04d: %s", file, line, str);
    fflush(stdout);
}

static tls_handshake_state mbedtls_hs_state(void *engine) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    switch (eng->ssl->state) {
        case MBEDTLS_SSL_HANDSHAKE_OVER: return TLS_HS_COMPLETE;
        case MBEDTLS_SSL_HELLO_REQUEST: return TLS_HS_BEFORE;
        default: return TLS_HS_CONTINUE;
    }
}

static const char* mbedtls_get_alpn(void *engine) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    return mbedtls_ssl_get_alpn_protocol(eng->ssl);
}

static tls_handshake_state
mbedtls_continue_hs(void *engine, char *in, size_t in_bytes, char *out, size_t *out_bytes, size_t maxout) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    if (in_bytes > 0) {
        um_BIO_put(eng->in, (const unsigned char *)in, in_bytes);
    }
    if (eng->ssl->state == MBEDTLS_SSL_HELLO_REQUEST && eng->session) {
        mbedtls_ssl_set_session(eng->ssl, eng->session);
        mbedtls_ssl_session_free(eng->session);
    }
    int state = mbedtls_ssl_handshake(eng->ssl);
    char err[1024];
    mbedtls_strerror(state, err, 1024);
    *out_bytes = um_BIO_read(eng->out, (unsigned char *)out, maxout);

    if (eng->ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER) {
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

static int mbedtls_write(void *engine, const char *data, size_t data_len, char *out, size_t *out_bytes, size_t maxout) {
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
    *out_bytes = um_BIO_read(eng->out, (unsigned char *)out, maxout);
    return (int)um_BIO_available(eng->out);
}

static int
mbedtls_read(void *engine, const char *ssl_in, size_t ssl_in_len, char *out, size_t *out_bytes, size_t maxout) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    if (ssl_in_len > 0 && ssl_in != NULL) {
        um_BIO_put(eng->in, (const unsigned char *)ssl_in, ssl_in_len);
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

    // this indicates that more bytes are neded to complete SSL frame
    if (rc == MBEDTLS_ERR_SSL_WANT_READ) {
        return um_BIO_available(eng->out) > 0 ? TLS_HAS_WRITE : TLS_OK;
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

    if (um_BIO_available(eng->in) > 0 || mbedtls_ssl_check_pending(eng->ssl)) {
        return TLS_MORE_AVAILABLE;
    }

    return TLS_OK;
}

static int mbedtls_close(void *engine, char *out, size_t *out_bytes, size_t maxout) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    mbedtls_ssl_close_notify(eng->ssl); // TODO handle error

    *out_bytes = um_BIO_read(eng->out, (unsigned char *)out, maxout);
    return 0;
}

static int mbed_ssl_recv(void *ctx, uint8_t *buf, size_t len) {
    struct mbedtls_engine *eng = ctx;
    if (um_BIO_available(eng->in) == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    return um_BIO_read(eng->in, buf, len);
}

static int mbed_ssl_send(void *ctx, const uint8_t *buf, size_t len) {
    struct mbedtls_engine *eng = ctx;
    um_BIO_put(eng->out, buf, len);
    return (int) len;
}

#define OID_PKCS7 MBEDTLS_OID_PKCS "\x07"
#define OID_PKCS7_DATA OID_PKCS7 "\x02"
#define OID_PKCS7_SIGNED_DATA OID_PKCS7 "\x01"

static int parse_pkcs7_certs(tls_cert *chain, const char *pkcs7, size_t pkcs7len) {
    size_t der_len;
    unsigned char *p;
    unsigned char *end;
    unsigned char *cert_buf;

    int rc = mbedtls_base64_decode(NULL, 0, &der_len, pkcs7, pkcs7len); // determine necessary buffer size
    uint8_t *base64_decoded_pkcs7 = calloc(1, der_len + 1);
    rc = mbedtls_base64_decode(base64_decoded_pkcs7, der_len, &der_len, pkcs7, pkcs7len);

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

static int write_key_pem(tls_private_key pk, char **pem, size_t *pemlen) {
    mbedtls_pk_context *key = pk;
    uint8_t keybuf[4096];
    int ret;
    if ((ret = mbedtls_pk_write_key_pem(key, keybuf, sizeof(keybuf))) != 0) {
        UM_LOG(ERR, "mbedtls_pk_write_key_pem returned -0x%04x: %s", -ret, mbedtls_error(ret));
        return ret;
    }

    *pemlen = strlen(keybuf) + 1;
    *pem = strdup(keybuf);
    return 0;
}

static int load_key(tls_private_key *key, const char* keydata, size_t keydatalen) {
    mbedtls_pk_context *pk = calloc(1, sizeof(mbedtls_pk_context));
    mbedtls_pk_init(pk);

    int rc = mbedtls_pk_parse_key(pk, (const unsigned char *) keydata, keydatalen, NULL, 0);
    if (rc < 0) {
        rc = mbedtls_pk_parse_keyfile(pk, keydata, NULL);
        if (rc < 0) {
            mbedtls_pk_free(pk);
            free(pk);
            *key = NULL;
            return rc;
        }
    }
    *key = pk;
    return rc;
}

static int gen_key(tls_private_key *key) {

    int ret;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";
    mbedtls_ecp_group_id ec_curve = MBEDTLS_ECP_DP_SECP256R1;
    mbedtls_pk_type_t pk_type = MBEDTLS_PK_ECKEY;

    mbedtls_pk_context *pk = malloc(sizeof(mbedtls_pk_context));
    mbedtls_pk_init(pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        UM_LOG(ERR, "mbedtls_ctr_drbg_seed returned -0x%04x: %s", -ret, mbedtls_error(ret));
        goto on_error;
    }

    // Generate the key
    if ((ret = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(pk_type))) != 0) {
        UM_LOG(ERR, "mbedtls_pk_setup returned -0x%04x: %s", -ret, mbedtls_error(ret));
        goto on_error;
    }

    if ((ret = mbedtls_ecp_gen_key(ec_curve, mbedtls_pk_ec(*pk), mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        UM_LOG(ERR, "mbedtls_ecp_gen_key returned -0x%04x: %s", -ret, mbedtls_error(ret));
        goto on_error;
    }

    on_error:
    if (ret != 0) {
        mbedtls_pk_free(pk);
        free(pk);
    }
    else {
        *key = pk;
    }

    return ret;
}

static int generate_csr(tls_private_key key, char **pem, size_t *pemlen, ...) {
    int ret = 1;
    mbedtls_pk_context *pk = key;
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
        *pem = strdup(pembuf);
        *pemlen = strlen(pembuf) + 1;
    }
    mbedtls_x509write_csr_free(&csr);
    return ret;
}