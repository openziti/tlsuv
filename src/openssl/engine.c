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

#ifndef USE_OPENSSL
#error "USE_OPENSSL must be set to compile this file"
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "../bio.h"
#include "../um_debug.h"
#include <tlsuv/tlsuv.h>

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "keys.h"

#if _WIN32
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
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
    struct priv_key_s *own_key;
    X509 *own_cert;
    int (*cert_verify_f)(void *cert, void *v_ctx);
    void *verify_ctx;
    unsigned char *alpn_protocols;
};

struct openssl_engine {
    SSL *ssl;
    char *alpn;
    BIO *in;
    BIO *out;
    int error;
};

static void init_ssl_context(SSL_CTX **ssl_ctx, const char *cabuf, size_t cabuf_len);
static int tls_set_own_cert(void *ctx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len);
static int tls_set_own_cert_pkcs11(void *ctx, const char *cert_buf, size_t cert_len,
                               const char *pkcs11_lib, const char *pin, const char *slot, const char *key_id);
tls_engine *new_openssl_engine(void *ctx, const char *host);
static void tls_set_alpn_protocols(void *ctx, const char **protos, int len);

static tls_handshake_state tls_hs_state(void *engine);
static tls_handshake_state
tls_continue_hs(void *engine, char *in, size_t in_bytes, char *out, size_t *out_bytes, size_t maxout);

static const char* tls_get_alpn(void *engine);

static int tls_write(void *engine, const char *data, size_t data_len, char *out, size_t *out_bytes, size_t maxout);

static int
tls_read(void *engine, const char *ssl_in, size_t ssl_in_len, char *out, size_t *out_bytes, size_t maxout);

static int tls_close(void *engine, char *out, size_t *out_bytes, size_t maxout);

static int tls_reset(void *engine);

static const char* tls_lib_version();
static const char *tls_eng_error(void *eng);

static void tls_free(tls_engine *engine);
static void tls_free_ctx(tls_context *ctx);
static void tls_free_cert(tls_cert *cert);

static void tls_set_cert_verify(tls_context *ctx, int (*verify_f)(void *cert, void *v_ctx), void *v_ctx);

static int tls_verify_signature(void *cert, enum hash_algo md, const char *data, size_t datalen, const char *sig,
                                    size_t siglen);

static int parse_pkcs7_certs(tls_cert *chain, const char *pkcs7, size_t pkcs7len);

static int write_cert_pem(tls_cert cert, int full_chain, char **pem, size_t *pemlen);

static int generate_csr(tlsuv_private_key_t key, char **pem, size_t *pemlen, ...);

static void msg_cb (int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
static void info_cb(const SSL *s, int where, int ret);


static tls_context_api openssl_context_api = {
        .version = tls_lib_version,
        .strerror = tls_error,
        .new_engine = new_openssl_engine,
        .free_engine = tls_free,
        .free_ctx = tls_free_ctx,
        .free_cert = tls_free_cert,
        .set_own_cert = tls_set_own_cert,
        .set_own_cert_pkcs11 = tls_set_own_cert_pkcs11,
        .set_cert_verify = tls_set_cert_verify,
        .set_alpn_protocols = tls_set_alpn_protocols,
        .verify_signature =  tls_verify_signature,
        .parse_pkcs7_certs = parse_pkcs7_certs,
        .write_cert_to_pem = write_cert_pem,
        .generate_key = gen_key,
        .load_key = load_key,
        .load_pkcs11_key = (typeof(openssl_context_api.load_pkcs11_key)) load_pkcs11_key,
        .generate_csr_to_pem = generate_csr,
};


static tls_engine_api openssl_engine_api = {
        .handshake_state = tls_hs_state,
        .handshake = tls_continue_hs,
        .get_alpn = tls_get_alpn,
        .close = tls_close,
        .write = tls_write,
        .read = tls_read,
        .reset = tls_reset,
        .strerror = tls_eng_error
};

static const char* tls_lib_version() {
    return OpenSSL_version(OPENSSL_VERSION);
}

const char *tls_error(int code) {
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

#if _WIN32
static X509_STORE_CTX *load_system_certs() {
    X509_STORE_CTX *store = X509_STORE_CTX_new();
    X509_STORE_CTX_init(store, X509_STORE_new(), NULL, NULL);
    X509_STORE *certs = X509_STORE_CTX_get0_store(store);
    X509 *c;

    HCERTSTORE hCertStore;
    PCCERT_CONTEXT pCertContext = NULL;

    if (!(hCertStore = CertOpenSystemStore(0, "ROOT"))) {
        UM_LOG(ERROR, "The first system store did not open.");
        return store;
    }
    
    while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != NULL) {
        c = d2i_X509(NULL, (const uint8_t **)&pCertContext->pbCertEncoded, (long)pCertContext->cbCertEncoded);
        X509_STORE_add_cert(certs, c);
    }
    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hCertStore, 0);

    return store;
}
#endif

static void init_ssl_context(SSL_CTX **ssl_ctx, const char *cabuf, size_t cabuf_len) {
    SSL_library_init();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CONF_CTX *conf = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_flags(conf, SSL_CONF_FLAG_CLIENT);

    SSL_CTX *ctx = SSL_CTX_new(method);

    SSL_CONF_CTX_set_ssl_ctx(conf, ctx);
    SSL_CONF_CTX_finish(conf);
    SSL_CONF_CTX_free(conf);

    if (cabuf != NULL) {
        X509_STORE_CTX *ca = load_certs(cabuf, cabuf_len);
        SSL_CTX_set1_cert_store(ctx, X509_STORE_CTX_get0_store(ca));
        X509_STORE_CTX_free(ca);
    } else {
        // try loading default CA stores
#if _WIN32
        X509_STORE_CTX *ca = load_system_certs();
        SSL_CTX_set1_cert_store(ctx, X509_STORE_CTX_get0_store(ca));
        X509_STORE_CTX_free(ca);
#else
        SSL_CTX_set_default_verify_paths(ctx);
#endif
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    char *tls_debug = getenv("TLS_DEBUG");
    if (tls_debug) {
        SSL_CTX_set_msg_callback(ctx, msg_cb);
        SSL_CTX_set_info_callback(ctx, info_cb);
    }

    *ssl_ctx = ctx;
}

typedef struct string_int_pair_st {
    const char *name;
    int retval;
} OPT_PAIR, STRINT_PAIR;

static const char *lookup(int val, const STRINT_PAIR* list, const char* def)
{
    for ( ; list->name; ++list)
        if (list->retval == val)
            return list->name;
    return def;
}

static STRINT_PAIR handshakes[] = {
    {", HelloRequest", SSL3_MT_HELLO_REQUEST},
    {", ClientHello", SSL3_MT_CLIENT_HELLO},
    {", ServerHello", SSL3_MT_SERVER_HELLO},
    {", HelloVerifyRequest", DTLS1_MT_HELLO_VERIFY_REQUEST},
    {", NewSessionTicket", SSL3_MT_NEWSESSION_TICKET},
    {", EndOfEarlyData", SSL3_MT_END_OF_EARLY_DATA},
    {", EncryptedExtensions", SSL3_MT_ENCRYPTED_EXTENSIONS},
    {", Certificate", SSL3_MT_CERTIFICATE},
    {", ServerKeyExchange", SSL3_MT_SERVER_KEY_EXCHANGE},
    {", CertificateRequest", SSL3_MT_CERTIFICATE_REQUEST},
    {", ServerHelloDone", SSL3_MT_SERVER_DONE},
    {", CertificateVerify", SSL3_MT_CERTIFICATE_VERIFY},
    {", ClientKeyExchange", SSL3_MT_CLIENT_KEY_EXCHANGE},
    {", Finished", SSL3_MT_FINISHED},
    {", CertificateUrl", SSL3_MT_CERTIFICATE_URL},
    {", CertificateStatus", SSL3_MT_CERTIFICATE_STATUS},
    {", SupplementalData", SSL3_MT_SUPPLEMENTAL_DATA},
    {", KeyUpdate", SSL3_MT_KEY_UPDATE},
#ifndef OPENSSL_NO_NEXTPROTONEG
    {", NextProto", SSL3_MT_NEXT_PROTO},
#endif
    {", MessageHash", SSL3_MT_MESSAGE_HASH},
    {NULL}
};


static STRINT_PAIR alert_types[] = {
    {" close_notify", 0},
    {" end_of_early_data", 1},
    {" unexpected_message", 10},
    {" bad_record_mac", 20},
    {" decryption_failed", 21},
    {" record_overflow", 22},
    {" decompression_failure", 30},
    {" handshake_failure", 40},
    {" bad_certificate", 42},
    {" unsupported_certificate", 43},
    {" certificate_revoked", 44},
    {" certificate_expired", 45},
    {" certificate_unknown", 46},
    {" illegal_parameter", 47},
    {" unknown_ca", 48},
    {" access_denied", 49},
    {" decode_error", 50},
    {" decrypt_error", 51},
    {" export_restriction", 60},
    {" protocol_version", 70},
    {" insufficient_security", 71},
    {" internal_error", 80},
    {" inappropriate_fallback", 86},
    {" user_canceled", 90},
    {" no_renegotiation", 100},
    {" missing_extension", 109},
    {" unsupported_extension", 110},
    {" certificate_unobtainable", 111},
    {" unrecognized_name", 112},
    {" bad_certificate_status_response", 113},
    {" bad_certificate_hash_value", 114},
    {" unknown_psk_identity", 115},
    {" certificate_required", 116},
    {NULL}
};

static STRINT_PAIR ssl_versions[] = {
    {"SSL 3.0", SSL3_VERSION},
    {"TLS 1.0", TLS1_VERSION},
    {"TLS 1.1", TLS1_1_VERSION},
    {"TLS 1.2", TLS1_2_VERSION},
    {"TLS 1.3", TLS1_3_VERSION},
    {"DTLS 1.0", DTLS1_VERSION},
    {"DTLS 1.0 (bad)", DTLS1_BAD_VER},
    {NULL}
};

static void msg_cb (int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    const char *str_write_p = write_p ? ">>>" : "<<<";

    const char *str_content_type = "", *str_details1 = "", *str_details2 = "";
    const char *str_version = lookup(version, ssl_versions, "???");

    const unsigned char* bp = buf;

    if (version == SSL3_VERSION ||
        version == TLS1_VERSION ||
        version == TLS1_1_VERSION ||
        version == TLS1_2_VERSION ||
        version == TLS1_3_VERSION ||
        version == DTLS1_VERSION || version == DTLS1_BAD_VER) {
        switch (content_type) {
        case 20:
            str_content_type = ", ChangeCipherSpec";
            break;
        case 21:
            str_content_type = ", Alert";
            str_details1 = ", ???";
            if (len == 2) {
                switch (bp[0]) {
                case 1:
                    str_details1 = ", warning";
                    break;
                case 2:
                    str_details1 = ", fatal";
                    break;
                }
                str_details2 = lookup((int)bp[1], alert_types, " ???");
            }
            break;
        case 22:
            str_content_type = ", Handshake";
            str_details1 = "???";
            if (len > 0)
                str_details1 = lookup((int)bp[0], handshakes, "???");
            break;
        case 23:
            str_content_type = ", ApplicationData";
            break;
        }
    } else if (version == 0 && content_type == SSL3_RT_HEADER) {
        str_version = "";
        str_content_type = "TLS Header";
    }

    UM_LOG(TRACE, "%s %s%s [length %04lx]%s%s", str_write_p, str_version,
               str_content_type, (unsigned long)len, str_details1,
               str_details2);

//    if (len > 0) {
//        size_t num, i;
//
//        fprintf(stderr, "   ");
//        num = len;
//        for (i = 0; i < num; i++) {
//            if (i % 16 == 0 && i > 0)
//                fprintf(stderr, "\n   ");
//            fprintf(stderr, " %02x", ((const unsigned char *)buf)[i]);
//        }
//        if (i < len)
//            fprintf(stderr, " ...");
//        fprintf(stderr, "\n");
//    }

}

void info_cb(const SSL *s, int where, int ret) {
    const char *str;
    int w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
        str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
        str = "SSL_accept";
    else
        str = "undefined";

    if (where & SSL_CB_LOOP) {
        UM_LOG(TRACE, "%s:%s", str, SSL_state_string_long(s));
    } else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        UM_LOG(VERB, "SSL3 alert %s:%s:%s",
                   str,
                   SSL_alert_type_string_long(ret),
                   SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0)
            UM_LOG(VERB, "%s:failed in %s", str, SSL_state_string_long(s));
        else if (ret < 0)
            UM_LOG(VERB, "%s:error in %s", str, SSL_state_string_long(s));
    }
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
    SSL_set_tlsext_host_name(eng->ssl, host);
    SSL_set1_host(eng->ssl, host);
    SSL_set_connect_state(eng->ssl);
    engine->api = &openssl_engine_api;

    if (context->alpn_protocols) {
        SSL_set_alpn_protos(eng->ssl, context->alpn_protocols, strlen(context->alpn_protocols));
    }

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
    return verify_signature(X509_get_pubkey(cert), md, data, datalen, sig, siglen);
}

static void tls_free_ctx(tls_context *ctx) {
    struct openssl_ctx *c = ctx->ctx;
    if (c->alpn_protocols) {
        free(c->alpn_protocols);
    }
    if (c->own_key) {
        c->own_key->free(c->own_key);
        c->own_key = NULL;
    }
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

    if (e->alpn) {
        free(e->alpn);
    }
    free(e);
    free(engine);
}

static void tls_free_cert(tls_cert *cert) {
    X509_STORE *s = *cert;
    if (s != NULL)
        X509_STORE_free(s);
    *cert = NULL;
}

static void tls_set_alpn_protocols(void *ctx, const char **protos, int len) {
    struct openssl_ctx *c = ctx;

    if (c->alpn_protocols) {
        free(c->alpn_protocols);
    }

    size_t protolen = 0;
    for (int i=0; i < len; i++) {
        protolen += strlen(protos[i]) + 1;
    }

    c->alpn_protocols = malloc(protolen + 1);
    unsigned char *p = c->alpn_protocols;
    for (int i=0; i < len; i++) {
        size_t plen = strlen(protos[i]);
        *p++ = (unsigned char)plen;
        strncpy(p, protos[i], plen);
        p += plen;
    }
    *p = 0;
}

#define SSL_OP_CHECK(op, desc) do{ \
if ((op) != 1) { \
        uint32_t err = ERR_get_error(); \
        UM_LOG(ERR, "failed to " desc ": %d(%s)", err, tls_error(err)); \
        return TLS_ERR; \
    }} while(0)

static int tls_set_own_cert(void *ctx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len) {
    struct openssl_ctx *c = ctx;
    SSL_CTX *ssl = c->ctx;
    int rc = load_key((tlsuv_private_key_t *) &c->own_key, key_buf, key_len);
    if (rc != 0) return rc;

    X509_STORE_CTX *certs = load_certs(cert_buf, cert_len);
    X509_STORE *store = X509_STORE_CTX_get0_store(certs);

    STACK_OF(X509_OBJECT) *stack = X509_STORE_get0_objects(store);

    X509_OBJECT *o = sk_X509_OBJECT_value(stack, 0);
    X509 *crt = X509_OBJECT_get0_X509(o);
    SSL_OP_CHECK(SSL_CTX_use_certificate(ssl, crt), "set own cert");
    c->own_cert = crt;

    SSL_OP_CHECK(SSL_CTX_use_PrivateKey(ssl, c->own_key->pkey), "set own key");
    SSL_OP_CHECK(SSL_CTX_check_private_key(ssl), "verify key/cert combo");

    X509_STORE_CTX_free(certs);
    X509_STORE_free(store);
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
    OSSL_HANDSHAKE_STATE state = SSL_get_state(eng->ssl);
    switch (state) {
        case TLS_ST_OK: return TLS_HS_COMPLETE;
        case TLS_ST_BEFORE: return TLS_HS_BEFORE;
        default: return TLS_HS_CONTINUE;
    }
}


static tls_handshake_state
tls_continue_hs(void *engine, char *in, size_t in_bytes, char *out, size_t *out_bytes, size_t maxout) {
    struct openssl_engine *eng = (struct openssl_engine *) engine;
    if (in_bytes > 0) {
        BIO_write(eng->in, (const unsigned char *)in, (int)in_bytes);
    }

    int state = SSL_do_handshake(eng->ssl);
    int err = SSL_get_error(eng->ssl, state);
    if (BIO_ctrl_pending(eng->out) > 0) {
        *out_bytes = BIO_read(eng->out, (unsigned char *) out, (int)maxout);
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

static const char* tls_get_alpn(void *engine) {
    struct openssl_engine *eng = (struct openssl_engine *) engine;
    const unsigned char *proto;
    unsigned int protolen;
    SSL_get0_alpn_selected(eng->ssl, &proto, &protolen);

    eng->alpn = calloc(1, protolen + 1);
    strncpy(eng->alpn, (const char*)proto, protolen);
    return eng->alpn;
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
        BIO_write(eng->in, (const unsigned char *)ssl_in, (int)ssl_in_len);
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






static int generate_csr(tlsuv_private_key_t key, char **pem, size_t *pemlen, ...) {
    struct priv_key_s *privkey = (struct priv_key_s *) key;
    int ret = 0;
    const char* op = "";
    EVP_PKEY *pk = privkey->pkey;
    X509_REQ *req = X509_REQ_new();
    X509_NAME *subj = X509_REQ_get_subject_name(req);
    BIO *b = BIO_new(BIO_s_mem());


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

#define ssl_check(OP) do{ \
op = #OP;                 \
if((OP) == 0) {           \
ret = ERR_get_error();    \
goto on_error;            \
}}while(0)
    
    ssl_check(X509_REQ_set_pubkey(req, pk));
    ssl_check(X509_REQ_sign(req, pk, EVP_sha1()));
    ssl_check(PEM_write_bio_X509_REQ(b, req));

    on_error:
    if (ret) {
        UM_LOG(WARN, "%s => %s", op, tls_error(ret));
    } else {
        size_t len = BIO_ctrl_pending(b);
        *pem = calloc(1, len + 1);
        BIO_read(b, *pem, len);
    }

    BIO_free(b);
    X509_REQ_free(req);

    return ret;
}

static int tls_set_own_cert_pkcs11(void *ctx, const char *cert_buf, size_t cert_len,
                               const char *pkcs11_lib, const char *pin, const char *slot, const char *key_id) {
    UM_LOG(ERR, "pkcs11 support not implemented by this engine");
    return TLS_ERR;
}