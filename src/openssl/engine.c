// Copyright (c) 2024. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef USE_OPENSSL
#error "USE_OPENSSL must be set to compile this file"
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "../alloc.h"
#include "../um_debug.h"
#include <tlsuv/tlsuv.h>

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include <openssl/crypto.h>

#include "keys.h"
#include "../keychain.h"

#if _WIN32
#include <windows.h>
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif
#endif

struct openssl_ctx {
    tls_context api;
    SSL_CTX *ctx;
    int (*cert_verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx);
    void *verify_ctx;
    unsigned char *alpn_protocols;
};

struct openssl_engine {
    struct tlsuv_engine_s api;
    SSL *ssl;
    char *alpn;

    BIO *bio;
    io_ctx io;
    io_read read_f;
    io_write write_f;

    unsigned long error;
};

static int is_self_signed(X509 *cert);
static const char* name_str(const X509_NAME *n);
static void init_ssl_context(struct openssl_ctx *c, const char *cabuf, size_t cabuf_len);
static int tls_set_own_cert(tls_context *ctx, tlsuv_private_key_t key,
                            tlsuv_certificate_t cert);

static int set_ca_bundle(tls_context *tls, const char *ca, size_t ca_len);

tlsuv_engine_t new_openssl_engine(void *ctx, const char *host);
static void set_io(tlsuv_engine_t , io_ctx , io_read , io_write);
static void set_io_fd(tlsuv_engine_t , uv_os_fd_t);
static void set_protocols(tlsuv_engine_t self, const char** protocols, int len);

static tls_handshake_state tls_hs_state(tlsuv_engine_t engine);
static tls_handshake_state
tls_continue_hs(tlsuv_engine_t self);

static const char* tls_get_alpn(tlsuv_engine_t self);

static int tls_write(tlsuv_engine_t self, const char *data, size_t data_len);

static int tls_read(tlsuv_engine_t self, char *, size_t *, size_t );

static int tls_close(tlsuv_engine_t self);

static int tls_reset(tlsuv_engine_t self);

static const char* tls_lib_version();
static const char *tls_eng_error(tlsuv_engine_t self);

static void tls_free(tlsuv_engine_t self);
static void tls_free_ctx(tls_context *ctx);

static void tls_set_cert_verify(tls_context *ctx,
                                int (*verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx),
                                void *v_ctx);

static int parse_pkcs7_certs(tlsuv_certificate_t *chain, const char *pkcs7, size_t pkcs7len);

static int load_cert(tlsuv_certificate_t *cert, const char *buf, size_t buflen);

static int generate_csr(tlsuv_private_key_t key, char **pem, size_t *pemlen, ...);

static void msg_cb (int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
static void info_cb(const SSL *s, int where, int ret);

static int tls_set_partial_vfy(tls_context *ctx, int allow);

static BIO_METHOD *BIO_s_engine(void);

static X509_LOOKUP_METHOD * old_hash_lookup(void);

#if _WIN32
static X509_STORE *load_system_certs();
#endif

static tls_context openssl_context_api = {
        .version = tls_lib_version,
        .strerror = (const char *(*)(long)) tls_error,
        .new_engine = new_openssl_engine,
        .free_ctx = tls_free_ctx,
        .set_ca_bundle = set_ca_bundle,
        .set_own_cert = tls_set_own_cert,
        .allow_partial_chain = tls_set_partial_vfy,
        .set_cert_verify = tls_set_cert_verify,
//        .verify_signature =  tls_verify_signature,
        .parse_pkcs7_certs = parse_pkcs7_certs,
//        .write_cert_to_pem = write_cert_pem,
        .generate_key = gen_key,
        .load_key = load_key,
        .load_pkcs11_key = load_pkcs11_key,
        .generate_pkcs11_key = gen_pkcs11_key,
//        .generate_keychain_key = gen_keychain_key,
//        .load_keychain_key = load_keychain_key,
//        .remove_keychain_key = remove_keychain_key,
        .load_cert = load_cert,
        .generate_csr_to_pem = generate_csr,
};


static struct tlsuv_engine_s openssl_engine_api = {
        .set_io = set_io,
        .set_io_fd = set_io_fd,
        .set_protocols = set_protocols,
        .handshake_state = tls_hs_state,
        .handshake = tls_continue_hs,
        .get_alpn = tls_get_alpn,
        .close = tls_close,
        .write = tls_write,
        .read = tls_read,
        .reset = tls_reset,
        .free = tls_free,
        .strerror = tls_eng_error,
};

static const char* tls_lib_version() {
    static char version[128];
    static OSSL_LIB_CTX *libctx = NULL;
    if (libctx == NULL) {
        libctx = OSSL_LIB_CTX_get0_global_default();
        int fips = EVP_default_properties_is_fips_enabled(libctx);
        snprintf(version, sizeof(version), "%s%s",
                 OpenSSL_version(OPENSSL_VERSION), fips ? " [FIPS]" : "");
    }
    return version;
}

const char *tls_error(unsigned long code) {
    static char errbuf[1024];
    ERR_error_string_n(code, errbuf, sizeof(errbuf));
    return errbuf;
}

static const char *tls_eng_error(tlsuv_engine_t self) {
    struct openssl_engine *e = (struct openssl_engine *)self;
    return tls_error(e->error);
}

tls_context *new_openssl_ctx(const char *ca, size_t ca_len) {

    struct openssl_ctx *c = tlsuv__calloc(1, sizeof(struct openssl_ctx));
    c->api = openssl_context_api;
    if (tlsuv_keychain() != NULL) {
        c->api.generate_keychain_key = gen_keychain_key;
        c->api.load_keychain_key = load_keychain_key;
        c->api.remove_keychain_key = remove_keychain_key;
    }
    init_ssl_context(c, ca, ca_len);

    return &c->api;
}

static X509_STORE * load_certs(const char *buf, size_t buf_len) {
    X509_STORE *certs = X509_STORE_new();
    X509 *c;

    // try as file
    struct stat fstat;
    if (stat(buf, &fstat) == 0) {
        if (fstat.st_mode & S_IFREG) {
            if (!X509_STORE_load_locations(certs, buf, NULL)) {
                UM_LOG(ERR, "failed to load certs from [%s]", buf);
            }
        } else if (fstat.st_mode & S_IFDIR) {
            X509_STORE_load_path(certs, buf);
            X509_LOOKUP *lu = X509_STORE_add_lookup(certs, old_hash_lookup());
            X509_LOOKUP_set_method_data(lu, (void*)buf);
        } else {
            UM_LOG(ERR, "cert bundle[%s] is not a regular file", buf);
        }
    } else {
        // try as PEM
        BIO *crt_bio = BIO_new_mem_buf(buf, (int)buf_len);
        while((c = PEM_read_bio_X509(crt_bio, NULL, NULL, NULL)) != NULL) {
            int root = is_self_signed(c);
            UM_LOG(VERB, "%s root[%s]",
                   name_str(X509_get_subject_name(c)), root? "true" : "false");
            X509_STORE_add_cert(certs, c);
            X509_free(c);
        }
        BIO_free(crt_bio);
    }
    return certs;
}

static int load_cert(tlsuv_certificate_t *cert, const char *buf, size_t buflen) {
    X509_STORE *store = load_certs(buf, buflen);

    STACK_OF(X509_OBJECT) *certs = X509_STORE_get0_objects(store);
    int count = sk_X509_OBJECT_num(certs);
    if (count == 0) {
        X509_STORE_free(store);
        return -1;
    }

    struct cert_s *crt = tlsuv__calloc(1, sizeof(*crt));
    cert_init(crt);
    crt->cert = store;
    *cert = (tlsuv_certificate_t) crt;
    return 0;
}

static int is_self_signed(X509 *cert) {
#if OPENSSL_API_LEVEL >= 30000
    return X509_self_signed(cert, 1);
#else
    X509_NAME *subj = X509_get_subject_name(cert);
    X509_NAME *issuer = X509_get_issuer_name(cert);
    if (X509_NAME_cmp(subj, issuer) != 0) {
        return 0;
    }

    EVP_PKEY *pub = X509_get0_pubkey(cert);
    return X509_verify(cert, pub);
#endif
}

static const char* name_str(const X509_NAME *n) {
    static char buf[1024];
    BIO *b = BIO_new(BIO_s_mem());
    X509_NAME_print(b, n, 0);
    BIO_read(b, buf, sizeof(buf));
    BIO_free(b);
    return buf;
}

static int by_subj_old_hash(X509_LOOKUP *lu, X509_LOOKUP_TYPE t, const X509_NAME *name, X509_OBJECT *obj){
    if (t != X509_LU_X509) return 0;

    const char *dir = X509_LOOKUP_get_method_data(lu);
    if (dir == NULL) return 0;

    char path[PATH_MAX];
    unsigned long h[] = {
            X509_NAME_hash_old(name),
            X509_NAME_hash(name),
    };
    int count = 0;
    for (int i = 0; i < sizeof(h)/sizeof(h[0]); i++) {
        for (int idx = 0; ; idx ++) {
            snprintf(path, sizeof(path), "%s/%08lx.%d", dir, h[i], idx);
            struct stat s;
            if (stat(path, &s) != 0) break;
            if ((s.st_mode & S_IFREG) == 0) {
                continue;
            }

            if (X509_load_cert_file(lu, path, X509_FILETYPE_PEM) == 0) break;
            count++;
        }
    }
    if (count == 0) return 0;

    X509_STORE *store = X509_LOOKUP_get_store(lu);
    STACK_OF(X509_OBJECT) *objs = X509_STORE_get1_objects(store);
    X509_OBJECT *res = X509_OBJECT_retrieve_by_subject(objs, X509_LU_X509, name);
    sk_X509_OBJECT_free(objs);
    if (res) {
        X509_OBJECT_set1_X509(obj, X509_OBJECT_get0_X509(res));
        return 1;
    } else {
        return 0;
    }
}

static X509_LOOKUP_METHOD * old_hash_lookup(void) {
    static X509_LOOKUP_METHOD *method = NULL;
    if (method == NULL) {
        method = X509_LOOKUP_meth_new("old-hash-lookup");
        X509_LOOKUP_meth_set_get_by_subject(method, by_subj_old_hash);
    }
    return method;
}

static int set_ca_bundle(tls_context *tls, const char *ca, size_t ca_len) {
    struct openssl_ctx *c = (struct openssl_ctx *) tls;
    SSL_CTX *ctx = c->ctx;

    if (ca != NULL) {
        X509_STORE *store = load_certs(ca, ca_len);
        SSL_CTX_set0_verify_cert_store(ctx, store);
    } else {
        // try loading default CA stores
#if _WIN32
        X509_STORE *ca = load_system_certs();
        SSL_CTX_set0_verify_cert_store(ctx, ca);
#elif defined(ANDROID) || defined(__ANDROID__)
        X509_STORE *ca = SSL_CTX_get_cert_store(ctx);
        X509_LOOKUP *lu = X509_STORE_add_lookup(ca, old_hash_lookup());
        X509_LOOKUP_set_method_data(lu, (void*)"/etc/security/cacerts");
#else
        SSL_CTX_set_default_verify_paths(ctx);
#endif
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return 0;
}

static void init_ssl_context(struct openssl_ctx *c, const char *cabuf, size_t cabuf_len) {
    SSL_library_init();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CONF_CTX *conf = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_flags(conf, SSL_CONF_FLAG_CLIENT);

    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        UM_LOG(ERR, "FATAL: failed to create SSL_CTX: %s", tls_error(ERR_get_error()));
        abort();
    }
    SSL_CTX_set_app_data(ctx, c);
    c->ctx = ctx;

    SSL_CONF_CTX_set_ssl_ctx(conf, ctx);
    SSL_CONF_CTX_finish(conf);
    SSL_CONF_CTX_free(conf);

    set_ca_bundle((tls_context *) c, cabuf, cabuf_len);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    char *tls_debug = getenv("TLS_DEBUG");
    if (tls_debug) {
        SSL_CTX_set_msg_callback(ctx, msg_cb);
        SSL_CTX_set_info_callback(ctx, info_cb);
    }
}

typedef struct string_int_pair_st {
    const char *name;
    int retval;
} OPT_PAIR, STRINT_PAIR;

typedef struct openssl_ctx openssl_ctx;
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

tlsuv_engine_t new_openssl_engine(void *ctx, const char *host) {
    struct openssl_ctx *context = ctx;

    struct openssl_engine *engine = tlsuv__calloc(1, sizeof(struct openssl_engine));
    engine->api = openssl_engine_api;

    engine->ssl = SSL_new(context->ctx);

    SSL_set_tlsext_host_name(engine->ssl, host);
    SSL_set1_host(engine->ssl, host);
    SSL_set_connect_state(engine->ssl);

    SSL_set_app_data(engine->ssl, engine);

    return &engine->api;
}

static void set_io(tlsuv_engine_t self, io_ctx io, io_read rdf, io_write wrtf) {
    struct openssl_engine *e = (struct openssl_engine *) self;
    assert(e->bio == NULL);

    e->bio = BIO_new(BIO_s_engine());
    BIO_set_data(e->bio, e);
    BIO_set_init(e->bio, true);
    SSL_set_bio(e->ssl, e->bio, e->bio);

    e->io = io;
    e->read_f = rdf;
    e->write_f = wrtf;
}

static void set_io_fd(tlsuv_engine_t self, uv_os_fd_t fd) {
    struct openssl_engine *e = (struct openssl_engine *) self;
    assert(e->bio == NULL);

    e->bio = BIO_new_socket(fd, false);
    SSL_set_bio(e->ssl, e->bio, e->bio);
}

static void set_protocols(tlsuv_engine_t self, const char** protocols, int len) {
    struct openssl_engine *e = (struct openssl_engine *)self;

    size_t protolen = 0;
    for (int i=0; i < len; i++) {
        protolen += strlen(protocols[i]) + 1;
    }

    unsigned char *alpn_protocols = tlsuv__malloc(protolen + 1);
    unsigned char *p = alpn_protocols;
    for (int i=0; i < len; i++) {
        size_t plen = strlen(protocols[i]);
        *p++ = (unsigned char)plen;
        strncpy((char*)p, protocols[i], plen);
        p += plen;
    }
    *p = 0;
    SSL_set_alpn_protos(e->ssl, alpn_protocols, strlen((char*)alpn_protocols));
    tlsuv__free(alpn_protocols);
}

static int cert_verify_cb(X509_STORE_CTX *certs, void *ctx) {
    struct openssl_ctx *c = ctx;

    X509_STORE *store = X509_STORE_new();
    X509 *crt = X509_STORE_CTX_get0_cert(certs);
    X509_STORE_add_cert(store, crt);

    char n[1024];
    X509_NAME_oneline(X509_get_subject_name(crt), n, 1024);
    UM_LOG(VERB, "verifying %s", n);

    int rc = 1;
    struct cert_s cert;
    cert_init(&cert);
    cert.cert = store;
    if (c->cert_verify_f && c->cert_verify_f((const struct tlsuv_certificate_s *) &cert, c->verify_ctx) != 0) {
        UM_LOG(WARN, "verify failed for certificate[%s]", n);
        rc = 0;
    }
    X509_STORE_free(store);
    return rc;
}

int tls_set_partial_vfy(tls_context *ctx, int allow) {
    struct openssl_ctx *c = (struct openssl_ctx*)ctx;
    X509_VERIFY_PARAM *vfy = SSL_CTX_get0_param(c->ctx);
    if (allow) {
        X509_VERIFY_PARAM_set_flags(vfy, X509_V_FLAG_PARTIAL_CHAIN);
    } else {
        X509_VERIFY_PARAM_clear_flags(vfy, X509_V_FLAG_PARTIAL_CHAIN);
    }
    return 0;
}

static void tls_set_cert_verify(tls_context *ctx,
                                int (*verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx),
                                void *v_ctx) {
    struct openssl_ctx *c = (struct openssl_ctx*)ctx;
    c->cert_verify_f = verify_f;
    c->verify_ctx = v_ctx;
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_cert_verify_callback(c->ctx, cert_verify_cb, c);
}


static void tls_free_ctx(tls_context *ctx) {
    struct openssl_ctx *c = (struct openssl_ctx*)ctx;
    if (c->alpn_protocols) {
        tlsuv__free(c->alpn_protocols);
    }

    SSL_CTX_free(c->ctx);
    tlsuv__free(c);
}

static int tls_reset(tlsuv_engine_t self) {
    struct openssl_engine *e = (struct openssl_engine *)self;
    ERR_clear_error();

    e->bio = NULL;

    if (!SSL_clear(e->ssl)) {
        int err = SSL_get_error(e->ssl, 0);
        UM_LOG(ERR, "error resetting TSL enging: %d(%s)", err, tls_error(err));
        return -1;
    }
    return 0;
}

static void tls_free(tlsuv_engine_t self) {
    struct openssl_engine *e = (struct openssl_engine *)self;
    SSL_free(e->ssl);

    if (e->alpn) {
        tlsuv__free(e->alpn);
    }
    tlsuv__free(e);
}


#define SSL_OP_CHECK(op, desc) do{ \
if ((op) != 1) { \
        uint32_t err = ERR_get_error(); \
        UM_LOG(ERR, "failed to " desc ": %d(%s)", err, tls_error(err)); \
        return TLS_ERR; \
    }} while(0)


static X509* tls_set_cert_internal (SSL_CTX* ssl, X509_STORE *store) {
    STACK_OF(X509_OBJECT) *certs = X509_STORE_get0_objects(store);
    X509 *crt = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(certs, 0));
    SSL_CTX_use_certificate(ssl, crt);

    // rest of certs go to chain
    for (int i = 1; i < sk_X509_OBJECT_num(certs); i++) {
        X509 *x509 = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(certs, i));
        X509_up_ref(x509);
        SSL_CTX_add_extra_chain_cert(ssl, x509);
    }
    return crt;
}

static int tls_set_own_cert(tls_context *ctx, tlsuv_private_key_t key,
                            tlsuv_certificate_t cert) {
    struct openssl_ctx *c = (struct openssl_ctx*)ctx;
    SSL_CTX *ssl = c->ctx;

    SSL_CTX_use_PrivateKey(ssl, NULL);
    SSL_CTX_use_certificate(ssl, NULL);
    SSL_CTX_clear_chain_certs(ssl);

    if (key == NULL) {
        return 0;
    }

    struct cert_s *crt = (struct cert_s *) cert;
    X509_STORE *store = NULL;
    if (crt == NULL) {
        if(key->get_certificate) {
            if (key->get_certificate(key, (tlsuv_certificate_t *) &crt) != 0) {
                return -1;
            }
            store = crt->cert;
            free(crt);
        }
    } else {
        // owned by the caller
        store = crt->cert;
        X509_STORE_up_ref(crt->cert);
    }

    if (store == NULL) {
        return -1;
    }

    // OpenSSL requires setting certificate before private key
    // https://www.openssl.org/docs/man3.0/man3/SSL_CTX_use_PrivateKey.html
    struct priv_key_s *pk = (struct priv_key_s*)key;
    X509 *certs = tls_set_cert_internal(ssl, store);
    X509_STORE_free(store);

    SSL_OP_CHECK(X509_check_private_key(certs, pk->pkey), "verify key/cert combo");
    SSL_OP_CHECK(SSL_CTX_use_PrivateKey(ssl, pk->pkey), "set private key");
    return 0;
}


static tls_handshake_state tls_hs_state(tlsuv_engine_t engine) {
    struct openssl_engine *eng = (struct openssl_engine *) engine;
    OSSL_HANDSHAKE_STATE state = SSL_get_state(eng->ssl);
    switch (state) {
        case TLS_ST_OK: return TLS_HS_COMPLETE;
        case TLS_ST_BEFORE: return TLS_HS_BEFORE;
        default: return TLS_HS_CONTINUE;
    }
}

static int print_err_cb(const char *e, size_t len, void* v) {
    UM_LOG(WARN, "%.*s", (int)len, e);
    return 1;
}

static tls_handshake_state
tls_continue_hs(tlsuv_engine_t self) {
    struct openssl_engine *eng = (struct openssl_engine *) self;
    ERR_clear_error();

    int rc = SSL_do_handshake(eng->ssl);

    if (rc != 1) {
        ERR_print_errors_cb(print_err_cb, NULL);
    }

    if (rc == 1) { // handshake completed
        return TLS_HS_COMPLETE;
    }

    int err = SSL_get_error(eng->ssl, rc);

    if (rc == 0) { // handshake encountered an error and was shutdown
        eng->error = ERR_get_error();
        UM_LOG(ERR, "openssl: handshake was terminated: %s", tls_error(eng->error));
        return TLS_HS_ERROR;
    }

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return TLS_HS_CONTINUE;
    } else { // something else is wrong
        eng->error = err;
        UM_LOG(ERR, "openssl: handshake was terminated: %s", tls_error(eng->error));
        return TLS_HS_ERROR;
    }
}

static const char* tls_get_alpn(tlsuv_engine_t self) {
    struct openssl_engine *eng = (struct openssl_engine *) self;
    const unsigned char *proto;
    unsigned int protolen;
    SSL_get0_alpn_selected(eng->ssl, &proto, &protolen);

    eng->alpn = tlsuv__calloc(1, protolen + 1);
    strncpy(eng->alpn, (const char*)proto, protolen);
    return eng->alpn;
}

static int tls_write(tlsuv_engine_t self, const char *data, size_t data_len) {
    struct openssl_engine *eng = (struct openssl_engine *) self;
    ERR_clear_error();

    if (data_len > INT_MAX) {
        data_len = INT_MAX;
    }

    size_t wrote = 0;
    while (data_len > wrote) {
        size_t written = 0;
        int ret = SSL_write_ex(eng->ssl, (const unsigned char *) (data + wrote), data_len - wrote, &written);
        if (ret == 0) {
            int err = SSL_get_error(eng->ssl, 0);
            if (err == SSL_ERROR_WANT_WRITE) {
                if (wrote > 0) {
                    return (int)wrote;
                } else {
                    return TLS_AGAIN;
                }
            } else {
                eng->error = err;
                UM_LOG(ERR, "openssl: write error: %s", tls_error(eng->error));
                return -1;
            }
        }
        wrote += written;
    }

    return (int)wrote;
}


static int
tls_read(tlsuv_engine_t self, char *out, size_t *out_bytes, size_t maxout) {
    struct openssl_engine *eng = (struct openssl_engine *) self;

    int err = SSL_ERROR_NONE;
    uint8_t *writep = (uint8_t*)out;
    size_t total_out = 0;

    ERR_clear_error();
    while(maxout - total_out > 0) {

        size_t read_bytes;
        if (!SSL_read_ex(eng->ssl, writep, maxout - total_out, &read_bytes)) {
            err = SSL_get_error(eng->ssl, 0);
            break;
        }

        total_out += read_bytes;
        writep += read_bytes;
    }

    if (total_out > 0) {
        *out_bytes = total_out;
        return SSL_pending(eng->ssl) ? TLS_MORE_AVAILABLE : TLS_OK;
    }

    *out_bytes = 0;
    if (err == SSL_ERROR_WANT_READ) {
        return TLS_AGAIN;
    }

    if (SSL_get_shutdown(eng->ssl)) {
        return TLS_EOF;
    }

    if (err != SSL_ERROR_NONE) {
        eng->error = ERR_get_error();
        UM_LOG(ERR, "openssl read: %s", tls_error(eng->error));
        return TLS_ERR;
    }
    return TLS_OK;
}

static int tls_close(tlsuv_engine_t self) {
    struct openssl_engine *eng = (struct openssl_engine *) self;
    ERR_clear_error();

    int rc = SSL_shutdown(eng->ssl);
    if (rc < 0) {
        int err = SSL_get_error(eng->ssl, rc);
        UM_LOG(WARN, "openssl shutdown: %s", tls_error(err));
    }
    return 0;
}

static int parse_pkcs7_certs(tlsuv_certificate_t *chain, const char *pkcs7buf, size_t pkcs7len) {

    BIO *buf = BIO_new_mem_buf(pkcs7buf, (int)pkcs7len);
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

    X509_STORE *store = X509_STORE_new();
    for (int i = 0; i < sk_X509_num(certs); i++) {
        X509 *c = sk_X509_value(certs, i);
        X509_STORE_add_cert(store, c);
    }

    struct cert_s *c = tlsuv__calloc(1, sizeof(*c));
    cert_init(c);
    c->cert = store;
    *chain = (tlsuv_certificate_t) c;
    PKCS7_free(pkcs7);
    BIO_free_all(b64);
    return 0;
}


static int generate_csr(tlsuv_private_key_t key, char **pem, size_t *pemlen, ...) {
    struct priv_key_s *privkey = (struct priv_key_s *) key;
    int ret = 0;
    const char* op;
    EVP_PKEY *pk = privkey->pkey;
    X509_REQ *req = X509_REQ_new();
    X509_NAME *subj = X509_REQ_get_subject_name(req);
    BIO *b = BIO_new(BIO_s_mem());


    va_list va;
    va_start(va, pemlen);
    while (true) {
        char *id = va_arg(va, char*);
        if (id == NULL) { break; }

        const uint8_t *val = va_arg(va, uint8_t*);
        if (val == NULL) { break; }

        X509_NAME_add_entry_by_txt(subj, id, MBSTRING_ASC, val, -1, -1, 0);
    }
    va_end(va);

#define ssl_check(OP) do{ \
op = #OP;                 \
if((OP) == 0) {           \
ret = ERR_get_error();    \
goto on_error;            \
}}while(0)
    
    ssl_check(X509_REQ_set_pubkey(req, pk));
    ssl_check(X509_REQ_sign(req, pk, EVP_sha256()));
    ssl_check(PEM_write_bio_X509_REQ(b, req));

    on_error:
    if (ret) {
        UM_LOG(WARN, "%s => %s", op, tls_error(ret));
    } else {
        size_t len = BIO_ctrl_pending(b);
        *pem = tlsuv__calloc(1, len + 1);
        BIO_read(b, *pem, (int)len);
        if (pemlen) {
            *pemlen = len;
        }
    }

    BIO_free(b);
    X509_REQ_free(req);

    return ret;
}

#if _WIN32
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")

static X509_STORE *load_system_certs() {
    X509_STORE *store = X509_STORE_new();
    X509 *c;

    HCERTSTORE hCertStore;
    PCCERT_CONTEXT pCertContext = NULL;

    if (!(hCertStore = CertOpenSystemStore(0, "ROOT"))) {
        UM_LOG(ERR, "The first system store did not open.");
        return store;
    }

    while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != NULL) {
        c = d2i_X509(NULL, (const uint8_t **)&pCertContext->pbCertEncoded, (long)pCertContext->cbCertEncoded);
        X509_STORE_add_cert(store, c);
    }
    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hCertStore, 0);

    return store;
}
#endif


static int engine_bio_write(BIO *b, const char *data, size_t len, size_t *written) {
    struct openssl_engine *e = BIO_get_data(b);
    assert(e);
    assert(e->write_f);

    ssize_t r = e->write_f(e->io, data, len);
    if (r > 0) {
        *written = r;
        return 1;
    }

    if (r == TLS_AGAIN) {
        *written = 0;
        BIO_set_retry_write(b);
        return -1;
    }

    return (int)r;
}

static int engine_bio_read(BIO *b, char *data, size_t len, size_t *len_out) {
    struct openssl_engine *e = BIO_get_data(b);

    assert(e->read_f);

    ssize_t rc = e->read_f(e->io, data, len);
    if (rc > 0) {
        *len_out = rc;
        return 1;
    } else if (rc == TLS_AGAIN) {
        *len_out = rc;
        BIO_set_retry_read(b);
        return 0;
    } else if (rc == 0) {
        *len_out = 0;
        return 0;
    }
    return 0;
}

static long engine_bio_ctrl(BIO *b, int cmd, long larg, void *pargs) {
    long ret = 0;

    fflush(stderr);

    switch(cmd)
    {
        case BIO_CTRL_FLUSH: // 11
        case BIO_CTRL_DGRAM_SET_CONNECTED: // 32
        case BIO_CTRL_DGRAM_SET_PEER: // 44
        case BIO_CTRL_DGRAM_GET_PEER: // 46
            ret = 1;
            break;
        case BIO_CTRL_WPENDING: // 13
            ret = 0;
            break;
        case BIO_CTRL_DGRAM_QUERY_MTU: // 40
        case BIO_CTRL_DGRAM_GET_FALLBACK_MTU: // 47
            ret = 1500;
//             ret = 9000; // jumbo?
            break;
        case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD: // 49
            ret = 96; // random guess
            break;
        case BIO_CTRL_DGRAM_SET_PEEK_MODE: // 71
        case BIO_CTRL_PUSH: // 6
        case BIO_CTRL_POP: // 7
        case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT: // 45
            ret = 0;
            break;
        default:
            UM_LOG(WARN, "unknown cmd: BIO[%p], cmd[%d], larg[%ld]", b, cmd, larg);
            ret = 0;
            break;
    }

    return ret;
}

static int engine_bio_create(BIO *b) {
    return 1;
}
static int engine_bio_destroy(BIO *b) {
    return 1;
}

static BIO_METHOD *engine_bio_meth = NULL;
BIO_METHOD *BIO_s_engine(void)
{
    if (engine_bio_meth == NULL) {

        engine_bio_meth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "BIO_s_engine");

        BIO_meth_set_write_ex(engine_bio_meth, engine_bio_write);
        BIO_meth_set_read_ex(engine_bio_meth, engine_bio_read);
        BIO_meth_set_ctrl(engine_bio_meth, engine_bio_ctrl);
        BIO_meth_set_create(engine_bio_meth, engine_bio_create);
        BIO_meth_set_destroy(engine_bio_meth, engine_bio_destroy);

    }
    return engine_bio_meth;
}

