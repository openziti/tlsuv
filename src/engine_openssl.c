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

#ifndef USE_OPENSSL
#error "USE_OPENSSL must be set to compile this file"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "bio.h"
#include "um_debug.h"
#include <uv_mbed/uv_mbed.h>

#include <openssl/x509.h>

#if _WIN32
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#else

#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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

struct openssl_ctx {
    SSL_CTX *ctx;
    tls_private_key own_key;
    X509 *own_cert;
    int (*cert_verify_f)(void *cert, void *v_ctx);
    void *verify_ctx;
};

struct openssl_engine {
    SSL *ssl;
    SSL_SESSION *session;
    BIO *in;
    BIO *out;
    int error;
};

static void init_ssl_context(SSL_CTX **ssl_ctx, const char *cabuf, size_t cabuf_len);
static int tls_set_own_cert(void *ctx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len);
//static int mbedtls_set_own_cert_p11(void *ctx, const char *cert_buf, size_t cert_len,
//            const char *pkcs11_lib, const char *pin, const char *slot, const char *key_id);

tls_engine *new_openssl_engine(void *ctx, const char *host);


static tls_handshake_state tls_hs_state(void *engine);
static tls_handshake_state
tls_continue_hs(void *engine, char *in, size_t in_bytes, char *out, size_t *out_bytes, size_t maxout);

static int tls_write(void *engine, const char *data, size_t data_len, char *out, size_t *out_bytes, size_t maxout);

static int
tls_read(void *engine, const char *ssl_in, size_t ssl_in_len, char *out, size_t *out_bytes, size_t maxout);

static int tls_close(void *engine, char *out, size_t *out_bytes, size_t maxout);

static int tls_reset(void *engine);

static const char *tls_error(int code);
static const char *tls_eng_error(void *eng);

static void tls_free(tls_engine *engine);
static void tls_free_ctx(tls_context *ctx);
static void tls_free_key(tls_private_key *k);
static void tls_free_cert(tls_cert *cert);

static void tls_set_cert_verify(tls_context *ctx, int (*verify_f)(void *cert, void *v_ctx), void *v_ctx);

static int tls_verify_signature(void *cert, enum hash_algo md, const char *data, size_t datalen, const char *sig,
                                    size_t siglen);

static int parse_pkcs7_certs(tls_cert *chain, const char *pkcs7, size_t pkcs7len);

static int write_cert_pem(tls_cert cert, int full_chain, char **pem, size_t *pemlen);

static int write_key_pem(tls_private_key pk, char **pem, size_t *pemlen);

static int gen_key(tls_private_key *key);
static int load_key(tls_private_key *key, const char* keydata, size_t keydatalen);

static int generate_csr(tls_private_key key, char **pem, size_t *pemlen, ...);

static tls_context_api openssl_context_api = {
        .strerror = tls_error,
        .new_engine = new_openssl_engine,
        .free_engine = tls_free,
        .free_ctx = tls_free_ctx,
        .free_key = tls_free_key,
        .free_cert = tls_free_cert,
        .set_own_cert = tls_set_own_cert,
//        .set_own_cert_pkcs11 = tls_set_own_cert_p11, TODO
        .set_cert_verify = tls_set_cert_verify,
        .verify_signature =  tls_verify_signature,
        .parse_pkcs7_certs = parse_pkcs7_certs,
        .write_cert_to_pem = write_cert_pem,
        .generate_key = gen_key,
        .load_key = load_key,
        .write_key_to_pem = write_key_pem,
        .generate_csr_to_pem = generate_csr,
};


static tls_engine_api openssl_engine_api = {
        .handshake_state = tls_hs_state,
        .handshake = tls_continue_hs,
        .close = tls_close,
        .write = tls_write,
        .read = tls_read,
        .reset = tls_reset,
        .strerror = tls_eng_error
};

static const char *tls_error(int code) {
    static char errbuf[1024];
    ERR_error_string_n(code, errbuf, sizeof(errbuf));
    return errbuf;

}

static const char *tls_eng_error(void *eng) {
    struct openssl_engine *e = eng;
    return tls_error(e->error);
}

tls_context *new_openssl_ctx(const char *ca, size_t ca_len) {
    tls_context *ctx = calloc(1, sizeof(tls_context));
    ctx->api = &openssl_context_api;
    struct openssl_ctx *c = calloc(1, sizeof(struct openssl_ctx));
    init_ssl_context(&c->ctx, ca, ca_len);
    ctx->ctx = c;

    return ctx;
}
static X509_STORE_CTX * load_certs(const char *buf, size_t buf_len) {
    X509_STORE_CTX *store = X509_STORE_CTX_new();
    X509_STORE_CTX_init(store, X509_STORE_new(), NULL, NULL);
    X509_STORE *certs = X509_STORE_CTX_get0_store(store);
    X509 *c;
    // try as file
    FILE *crt_file = fopen(buf, "r");
    if (crt_file != NULL) {
        while((c = PEM_read_X509(crt_file, NULL, NULL, NULL)) != NULL) {
            X509_STORE_add_cert(certs, c);
            X509_free(c);
        }
    } else {
        // try as PEM
        BIO *crt_bio = BIO_new(BIO_s_mem());
        BIO_write(crt_bio, buf, buf_len);
        while((c = PEM_read_bio_X509(crt_bio, NULL, NULL, NULL)) != NULL) {
            X509_STORE_add_cert(certs, c);
            X509_free(c);
        }
        BIO_free(crt_bio);
    }
    return store;
}

static void init_ssl_context(SSL_CTX **ssl_ctx, const char *cabuf, size_t cabuf_len) {
    SSL_library_init();
    char *tls_debug = getenv("TLS_DEBUG");
    if (tls_debug != NULL) {
        int level = (int) strtol(tls_debug, NULL, 10);
        // TODO mbedtls_debug_set_threshold(level);
    }


    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    X509 *c;
    if (cabuf != NULL) {
        X509_STORE_CTX *ca = load_certs(cabuf, cabuf_len);
        SSL_CTX_set1_cert_store(ctx, X509_STORE_CTX_get0_store(ca));
        X509_STORE_CTX_free(ca);
    }
    else { // try loading default CA stores
        SSL_CTX_set_default_verify_paths(ctx);
    }
    *ssl_ctx = ctx;
}


void msg_cb (int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    UM_LOG(TRACE, "%s v[%d], ct[%d], len[%zd]", write_p ? ">" : "<", version, content_type, len);
}

tls_engine *new_openssl_engine(void *ctx, const char *host) {
    struct openssl_ctx *context = ctx;

    tls_engine *engine = calloc(1, sizeof(tls_engine));
    struct openssl_engine *eng = calloc(1, sizeof(struct openssl_engine));
    engine->engine = eng;
    eng->ssl = SSL_new(context->ctx);
    eng->in = BIO_new(BIO_s_mem());
    eng->out = BIO_new(BIO_s_mem());
    SSL_set_bio(eng->ssl, eng->in, eng->out);
    SSL_set1_host(eng->ssl, host);
    SSL_set_connect_state(eng->ssl);
    engine->api = &openssl_engine_api;

    SSL_set_msg_callback(eng->ssl, msg_cb);

    return engine;
}

static int cert_verify_cb(X509_STORE_CTX *certs, void *ctx) {
    struct openssl_ctx *c = ctx;

    X509 *crt = X509_STORE_CTX_get0_cert(certs);
    X509_NAME *name = X509_get_subject_name(crt);

    char n[1024];
    X509_NAME_oneline(name, n, 1024);
    UM_LOG(VERB, "verifying %s", n);

    if (c->cert_verify_f) {
        int rc = c->cert_verify_f(crt, c->verify_ctx);
        if (rc == 0) {
            return 1;
        } else {
            return 0;
        }
    }
    return 0;
}

static void tls_set_cert_verify(tls_context *ctx, int (*verify_f)(void *cert, void *v_ctx), void *v_ctx) {
    struct openssl_ctx *c = ctx->ctx;
    c->cert_verify_f = verify_f;
    c->verify_ctx = v_ctx;
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_cert_verify_callback(c->ctx, cert_verify_cb, c);
}


static int tls_verify_signature(void *cert, enum hash_algo md, const char* data, size_t datalen, const char* sig, size_t siglen) {
    int rc = 0;
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pk = X509_get_pubkey(cert);
    switch (md) {
        case hash_SHA256:
            EVP_DigestVerifyInit(digest, &pctx, EVP_sha256(), NULL, pk);
            break;
        case hash_SHA384:
            EVP_DigestVerifyInit(digest, &pctx, EVP_sha384(), NULL, pk);
            break;
        case hash_SHA512:
            EVP_DigestVerifyInit(digest, &pctx, EVP_sha512(), NULL, pk);
            break;
        default:
            break;
    }

    if (!EVP_DigestVerify(digest, (const uint8_t *) sig, siglen, (const uint8_t *) data, datalen)) {
        rc = -1;
    }
    EVP_PKEY_free(pk);
    EVP_MD_CTX_free(digest);

    return rc;
}

static void tls_free_ctx(tls_context *ctx) {
    struct openssl_ctx *c = ctx->ctx;
    SSL_CTX_free(c->ctx);
    free(c);
    free(ctx);
}

static int tls_reset(void *engine) {
    struct openssl_engine *e = engine;
    if (!SSL_clear(e->ssl)) {
        int err = SSL_get_error(e->ssl, 0);
        UM_LOG(ERR, "error resetting TSL enging: %d(%s)", err, tls_error(err));
        return -1;
    }
    return 0;
}

static void tls_free(tls_engine *engine) {
    struct openssl_engine *e = engine->engine;
    SSL_free(e->ssl);

    free(e);
    free(engine);
}

static void tls_free_key(tls_private_key *k) {
    EVP_PKEY *key = *k;
    EVP_PKEY_free(key);
    *k = NULL;
}

static void tls_free_cert(tls_cert *cert) {
    X509_STORE *s = *cert;
    if (s != NULL)
        X509_STORE_free(s);
    *cert = NULL;
}

static int tls_set_own_cert(void *ctx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len) {
    struct openssl_ctx *c = ctx;
    SSL_CTX *ssl = c->ctx;
    int rc = load_key(&c->own_key, key_buf, key_len);
    if (rc != 0) return rc;

    X509_STORE_CTX *certs = load_certs(cert_buf, cert_len);
    X509_STORE *store = X509_STORE_CTX_get0_store(certs);

    STACK_OF(X509_OBJECT) *stack = X509_STORE_get0_objects(store);

    int code = SSL_CTX_use_PrivateKey(ssl, c->own_key);

    X509_OBJECT *o = sk_X509_OBJECT_value(stack, 0);
    X509 *crt = X509_OBJECT_get0_X509(o);
    code = SSL_CTX_use_certificate(ssl, crt);
    c->own_cert = crt;
    return rc;
}

#if 0

static int tls_set_own_cert_p11(void *ctx, const char *cert_buf, size_t cert_len,
        const char *pkcs11_lib, const char *pin, const char *slot, const char *key_id) {

    struct tls_context *c = ctx;
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
#endif

static tls_handshake_state tls_hs_state(void *engine) {
    struct openssl_engine *eng = (struct openssl_engine *) engine;
    if (SSL_get_state(eng->ssl) == TLS_ST_OK) {
        return TLS_HS_COMPLETE;
    }
    else {
        return TLS_HS_CONTINUE;
    }
}


static tls_handshake_state
tls_continue_hs(void *engine, char *in, size_t in_bytes, char *out, size_t *out_bytes, size_t maxout) {
    struct openssl_engine *eng = (struct openssl_engine *) engine;
    if (in_bytes > 0) {
        BIO_write(eng->in, (const unsigned char *)in, in_bytes);
    }

    int state = SSL_do_handshake(eng->ssl);
    int err = SSL_get_error(eng->ssl, state);
    if (BIO_ctrl_pending(eng->out) > 0) {
        *out_bytes = BIO_read(eng->out, (unsigned char *) out, maxout);
    } else {
        *out_bytes = 0;
    }

    OSSL_HANDSHAKE_STATE hs_state = SSL_get_state(eng->ssl);
    if (hs_state == TLS_ST_OK) {
        return TLS_HS_COMPLETE;
    }
    else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return TLS_HS_CONTINUE;
    }
    else {
        eng->error = state;
        return TLS_HS_ERROR;
    }
}

static int tls_write(void *engine, const char *data, size_t data_len, char *out, size_t *out_bytes, size_t maxout) {
    struct openssl_engine *eng = (struct openssl_engine *) engine;
    size_t wrote = 0;
    while (data_len > wrote) {
        int rc = SSL_write(eng->ssl, (const unsigned char *)(data + wrote), data_len - wrote);
        if (rc < 0) {
            eng->error = rc;
            return rc;
        }
        wrote += rc;
    }
    if (BIO_ctrl_pending(eng->out) > 0)
        *out_bytes = BIO_read(eng->out, (unsigned char *)out, maxout);
    else
        *out_bytes = 0;

    return (int)BIO_ctrl_pending(eng->out);
}


static int
tls_read(void *engine, const char *ssl_in, size_t ssl_in_len, char *out, size_t *out_bytes, size_t maxout) {
    struct openssl_engine *eng = (struct openssl_engine *) engine;
    if (ssl_in_len > 0 && ssl_in != NULL) {
        BIO_write(eng->in, (const unsigned char *)ssl_in, ssl_in_len);
    }

    int rc;
    int err = SSL_ERROR_NONE;
    uint8_t *writep = (uint8_t*)out;
    size_t total_out = 0;

    while((maxout - total_out > 0) && (rc = SSL_read(eng->ssl, writep, maxout - total_out)) > 0) {
        total_out += rc;
        writep += rc;
    }

    if (rc < 0) {
        err = SSL_get_error(eng->ssl, rc);
    }

    *out_bytes = total_out;

    // this indicates that more bytes are needed to complete SSL frame
    if (err == SSL_ERROR_WANT_READ) {
        return BIO_ctrl_pending(eng->out) > 0 ? TLS_HAS_WRITE : TLS_OK;
    }

    if (SSL_get_shutdown(eng->ssl)) {
        return TLS_EOF;
    }

    if (err != SSL_ERROR_NONE) {
        eng->error = rc;
        UM_LOG(ERR, "mbedTLS: %0x(%s)", rc, tls_error(eng->error));
        return TLS_ERR;
    }

    if (BIO_ctrl_pending(eng->in) > 0 || SSL_pending(eng->ssl)) {
        return TLS_MORE_AVAILABLE;
    }

    return BIO_ctrl_pending(eng->out) > 0 ? TLS_HAS_WRITE : TLS_OK;
}

static int tls_close(void *engine, char *out, size_t *out_bytes, size_t maxout) {
    struct openssl_engine *eng = (struct openssl_engine *) engine;
    SSL_shutdown(eng->ssl);
    if (BIO_ctrl_pending(eng->out) > 0)
        *out_bytes = BIO_read(eng->out, (unsigned char *)out, maxout);
    else
        *out_bytes = 0;
    return 0;
}

static int parse_pkcs7_certs(tls_cert *chain, const char *pkcs7buf, size_t pkcs7len) {

    BIO *buf = BIO_new_mem_buf(pkcs7buf, pkcs7len);
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_push(b64, buf);

    PKCS7 *pkcs7 = d2i_PKCS7_bio(b64, NULL);

    STACK_OF(X509) *certs;
    if (PKCS7_type_is_signed(pkcs7)) {
        certs = pkcs7->d.sign->cert;
    }
    else if(PKCS7_type_is_signedAndEnveloped(pkcs7)) {
        certs = pkcs7->d.signed_and_enveloped->cert;
    }
    else {
        BIO_free_all(b64);
        PKCS7_free(pkcs7);
        return -1;
    }
    int count = sk_X509_num(certs);
    X509_STORE *store = X509_STORE_new();
    for (int i = 0; i < count; i++) {
        X509_STORE_add_cert(store, sk_X509_value(certs, i));
    }

    *chain = store;
    PKCS7_free(pkcs7);
    BIO_free_all(b64);
    return 0;
}

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"

static int write_cert_pem(tls_cert cert, int full_chain, char **pem, size_t *pemlen) {
    X509_STORE *store = cert;

    BIO *pembio = BIO_new(BIO_s_mem());
    
    STACK_OF(X509_OBJECT) *objects = X509_STORE_get0_objects(store);
    for (int i = 0; i < sk_X509_OBJECT_num(objects); i++) {
        X509_OBJECT *o = sk_X509_OBJECT_value(objects, i);
        if (X509_OBJECT_get_type(o) == X509_LU_X509) {
            X509 *c = X509_OBJECT_get0_X509(o);
            PEM_write_bio_X509(pembio, c);
        }
    }

    *pemlen = BIO_ctrl_pending(pembio);
    *pem = calloc(1, *pemlen);
    BIO_read(pembio, *pem, *pemlen);

    BIO_free_all(pembio);
    return 0;
}


static int write_key_pem(tls_private_key pk, char **pem, size_t *pemlen) {
    BIO *b = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(b, pk, NULL, NULL, 0, NULL, NULL);
    size_t len = BIO_ctrl_pending(b);
    *pem = calloc(1, len + 1);
    BIO_read(b, *pem, len);
    *pemlen = len;
    return 0;
}

static int load_key(tls_private_key *key, const char* keydata, size_t keydatalen) {
    // try file
    BIO *kb;
    FILE *kf = fopen(keydata, "r");
    if (kf != NULL) {
        kb = BIO_new_fp(kf, 1);
    } else {
        kb = BIO_new_mem_buf(keydata, keydatalen);
    }

    EVP_PKEY *pk = NULL;
    if (!PEM_read_bio_PrivateKey(kb, &pk, NULL, NULL)) {
        return -1;
    }

    *key = pk;
    return 0;
}


static int gen_key(tls_private_key *key) {
    int rc = 0;
    EVP_PKEY *pk = EVP_PKEY_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);

    if (!EVP_PKEY_keygen(pctx, &pk)) {
        uint32_t err = ERR_get_error();
        UM_LOG(ERR, "failed to generate key: %d(%s)", err, tls_error(err));
        rc = -1;
    }

    if (rc == 0)
        *key = pk;

    EVP_PKEY_CTX_free(pctx);
    return rc;
}


static int generate_csr(tls_private_key key, char **pem, size_t *pemlen, ...) {

    EVP_PKEY *pk = key;
    X509_REQ *req = X509_REQ_new();
    X509_NAME *subj = X509_REQ_get_subject_name(req);

    va_list va;
    va_start(va, pemlen);
    bool first = true;
    while (true) {
        char *id = va_arg(va, char*);
        if (id == NULL) { break; }

        const uint8_t *val = va_arg(va, uint8_t*);
        if (val == NULL) { break; }

        X509_NAME_add_entry_by_txt(subj, id, MBSTRING_ASC, val, -1, -1, 0);
    }

    
    X509_REQ_set_pubkey(req, pk);
    X509_REQ_sign(req, pk, EVP_sha1());
    
    BIO *b = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(b, req);

    size_t len = BIO_ctrl_pending(b);
    *pem = calloc(1, len + 1);
    BIO_read(b, *pem, len);

    BIO_free(b);
    X509_REQ_free(req);

    return 0;
}
