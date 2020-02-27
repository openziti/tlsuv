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
#include <mbedtls/ssl.h>
#include <mbedtls/debug.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <uv_mbed/uv_mbed.h>
#include "bio.h"
#include "p11_mbedtls/mbed_p11.h"
#include "um_debug.h"

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
};

struct mbedtls_engine {
    mbedtls_ssl_context *ssl;
    BIO *in;
    BIO *out;
};

static int mbedtls_set_own_cert(void *ctx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len);
static int mbedtls_set_own_cert_p11(void *ctx, const char *cert_buf, size_t cert_len,
            const char *pkcs11_lib, const char *pin, const char *slot, const char *key_id);

static tls_engine *new_mbedtls_engine(void *ctx, const char *host);

static tls_handshake_state mbedtls_hs_state(void *engine);
static tls_handshake_state
mbedtls_continue_hs(void *engine, char *in, size_t in_bytes, char *out, size_t *out_bytes, size_t maxout);

static int mbedtls_write(void *engine, const char *data, size_t data_len, char *out, size_t *out_bytes, size_t maxout);

static int
mbedtls_read(void *engine, const char *ssl_in, size_t ssl_in_len, char *out, size_t *out_bytes, size_t maxout);

static int mbedtls_close(void *engine, char *out, size_t *out_bytes, size_t maxout);

static void mbedtls_free(tls_engine *engine);

static void mbedtls_free_ctx(tls_context *ctx);

static tls_context_api mbedtls_context_api = {
        .new_engine = new_mbedtls_engine,
        .free_engine = mbedtls_free,
        .free_ctx = mbedtls_free_ctx,
        .set_own_cert = mbedtls_set_own_cert,
        .set_own_cert_pkcs11 = mbedtls_set_own_cert_p11,
};

static tls_engine_api mbedtls_engine_api = {
        .handshake_state = mbedtls_hs_state,
        .handshake = mbedtls_continue_hs,
        .close = mbedtls_close,
        .write = mbedtls_write,
        .read = mbedtls_read,
};


static void init_ssl_context(mbedtls_ssl_config *ssl_config, const char *ca, size_t cabuf_len);

static int mbed_ssl_recv(void *ctx, uint8_t *buf, size_t len);

static int mbed_ssl_send(void *ctx, const uint8_t *buf, size_t len);

static tls_context *new_mbedtls_ctx(const char *ca, size_t ca_len) {
    tls_context *ctx = calloc(1, sizeof(tls_context));
    ctx->api = &mbedtls_context_api;
    struct mbedtls_context *c = calloc(1, sizeof(struct mbedtls_context));
    init_ssl_context(&c->config, ca, ca_len);
    ctx->ctx = c;

    return ctx;
}

tls_context *default_tls_context(const char *ca, size_t ca_len) {
    return new_mbedtls_ctx(ca, ca_len);
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str);

static void init_ssl_context(mbedtls_ssl_config *ssl_config, const char *cabuf, size_t cabuf_len) {
#ifdef _WIN32
#else
    char *tls_debug = getenv("MBEDTLS_DEBUG");
    if (tls_debug != NULL) {
        int level = (int) strtol(tls_debug, NULL, 10);
        mbedtls_debug_set_threshold(level);
    }
#endif

    mbedtls_ssl_config_init(ssl_config);
    mbedtls_ssl_conf_dbg(ssl_config, tls_debug_f, stdout);
    mbedtls_ssl_config_defaults(ssl_config,
                                MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
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
        int rc = mbedtls_x509_crt_parse(ca, (const unsigned char *)cabuf, cabuf_len);
        if (rc < 0) {
            char err[1024];
            mbedtls_strerror(rc, err, sizeof(err));
            fprintf(stderr, "mbedtls_engine: %s\n", err);
            mbedtls_x509_crt_init(ca);

            rc = mbedtls_x509_crt_parse_file(ca, cabuf);
            mbedtls_strerror(rc, err, sizeof(err));
            fprintf(stderr, "mbedtls_engine: %s\n", err);
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

static tls_engine *new_mbedtls_engine(void *ctx, const char *host) {
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

static void mbedtls_free_ctx(tls_context *ctx) {
    struct mbedtls_context *c = ctx->ctx;
    mbedtls_x509_crt_free(c->config.ca_chain);
    free(c->config.ca_chain);
    mbedtls_ctr_drbg_context *drbg = c->config.p_rng;
    mbedtls_entropy_free(drbg->p_entropy);
    free(drbg->p_entropy);
    mbedtls_ctr_drbg_free(drbg);
    free(drbg);

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

static void mbedtls_free(tls_engine *engine) {
    struct mbedtls_engine *e = engine->engine;
    um_BIO_free(e->in);
    um_BIO_free(e->out);

    mbedtls_ssl_free(e->ssl);
    free(e->ssl);
    free(e);
    free(engine);
}

static int mbedtls_set_own_cert(void *ctx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len) {
    struct mbedtls_context *c = ctx;
    c->own_key = calloc(1, sizeof(mbedtls_pk_context));
    int rc = mbedtls_pk_parse_key(c->own_key, (const unsigned char *)key_buf, key_len, NULL, 0);
    if (rc < 0) {
        rc = mbedtls_pk_parse_keyfile(c->own_key, key_buf, NULL);
        if (rc < 0) {
            fprintf(stderr, "failed to load private key");
            mbedtls_pk_free(c->own_key);
            free(c->own_key);
            c->own_key = NULL;
            return TLS_ERR;
        }
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
    if (eng->ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER) {
        return TLS_HS_COMPLETE;
    }
    else {
        return TLS_HS_CONTINUE;
    }
}

static tls_handshake_state
mbedtls_continue_hs(void *engine, char *in, size_t in_bytes, char *out, size_t *out_bytes, size_t maxout) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    if (in_bytes > 0) {
        um_BIO_put(eng->in, (const unsigned char *)in, in_bytes);
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
        return TLS_HS_ERROR;
    }
}

static int mbedtls_write(void *engine, const char *data, size_t data_len, char *out, size_t *out_bytes, size_t maxout) {
    struct mbedtls_engine *eng = (struct mbedtls_engine *) engine;
    size_t wrote = 0;
    while (data_len > wrote) {
        int rc = mbedtls_ssl_write(eng->ssl, (const unsigned char *)(data + wrote), data_len - wrote);
        if (rc < 0) {
            return TLS_ERR;
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
        *out_bytes = total_out;
        return TLS_OK;
    }

    if (rc < 0) {
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
    BIO *out = eng->out;
    um_BIO_put(out, buf, len);
    return (int) len;
}