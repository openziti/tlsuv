

#include "tlsuv/tls_engine.h"
#include "bio.h"
#include "um_debug.h"
#include <Security/Security.h>
#include <uv.h>

struct sectransport_ctx {
    tls_context api;

    CFArrayRef ca_bundle;
};

struct sectransport_engine {
    struct tlsuv_engine_s api;
    CFArrayRef ca_bundle;
    SSLContextRef ssl;
    tls_handshake_state hs_state;
    tlsuv_BIO *in;
    tlsuv_BIO *out;
    char *protocol;
    OSStatus error;
};

// tls context funcs
static const char* tls_lib_version(void);
static tlsuv_engine_t new_engine(tls_context *ctx, const char *hostname);
static void tls_free_ctx(tls_context *ctx);

// tls engine funcs
static void set_protocols(tlsuv_engine_t, const char **protos, int count);
static tls_handshake_state
tls_continue_hs(tlsuv_engine_t, char *in, size_t inlen, char *out, size_t *outlen, size_t outmax);
static tls_handshake_state tls_hs_state(tlsuv_engine_t);
static OSStatus engine_read(SSLConnectionRef, void *data, size_t *len);
static OSStatus engine_write(SSLConnectionRef, const void *data, size_t *len);
static const char * tls_get_alpn(tlsuv_engine_t);
static int tls_read(tlsuv_engine_t, const char *in, size_t inlen, char *out, size_t *outlen, size_t outmax);
static int tls_write(tlsuv_engine_t, const char *data, size_t datalen, char *out, size_t *outlen, size_t outmax);
static int tls_close(tlsuv_engine_t, char *out, size_t *outlen, size_t outmax);
static void tls_free(tlsuv_engine_t);
static const char * tls_eng_error(tlsuv_engine_t);

static tls_context ctx_api = {
        .version = tls_lib_version,
//        .strerror = (const char *(*)(long)) tls_error,
        .new_engine = new_engine,
        .free_ctx = tls_free_ctx,
//        .free_cert = tls_free_cert,
//        .set_own_cert = tls_set_own_cert,
//        .set_cert_verify = tls_set_cert_verify,
//        .verify_signature =  tls_verify_signature,
//        .parse_pkcs7_certs = parse_pkcs7_certs,
//        .write_cert_to_pem = write_cert_pem,
//        .generate_key = gen_key,
//        .load_key = load_key,
//        .load_pkcs11_key = load_pkcs11_key,
//        .generate_pkcs11_key = gen_pkcs11_key,
//        .load_cert = load_cert,
//        .generate_csr_to_pem = generate_csr,
};

static struct tlsuv_engine_s engine_api = {
        .set_protocols = set_protocols,
        .handshake_state = tls_hs_state,
        .handshake = tls_continue_hs,
        .get_alpn = tls_get_alpn,
        .close = tls_close,
        .write = tls_write,
        .read = tls_read,
//        .reset = tls_reset,
        .free = tls_free,
        .strerror = tls_eng_error,
};

static const char* applesec_error(OSStatus code) {
    static char errorbuf[1024];
    CFStringRef err = SecCopyErrorMessageString(code, NULL);
    CFStringGetCString(err, errorbuf, sizeof(errorbuf), kCFStringEncodingUTF8);
    return errorbuf;

}

tls_context* new_applesec_ctx(const char* ca, size_t ca_len) {
    struct sectransport_ctx *ctx = calloc(1, sizeof(*ctx));
    ctx->api = ctx_api;

    if (ca && ca_len > 0) {
        SecExternalItemType type = 0;
        CFArrayRef certs = NULL;
        
        CFDataRef bundle = CFDataCreate(kCFAllocatorDefault, ca, ca_len);
        OSStatus rc = SecItemImport(bundle, NULL, NULL, &type, 0, NULL, NULL, &ctx->ca_bundle);
        
        if (rc != errSecSuccess) {
            CFRelease(bundle);

            uv_fs_t req;
            uv_file ca_file;
            if (uv_fs_stat(NULL, &req, ca, NULL) == 0) {
                uv_buf_t ca_buf = uv_buf_init(malloc(req.statbuf.st_size), req.statbuf.st_size);
                uv_fs_req_cleanup(&req);

                ca_file = uv_fs_open(NULL, &req, ca, 0, 0, NULL);
                uv_fs_req_cleanup(&req);

                size_t len = uv_fs_read(NULL, &req, ca_file, &ca_buf, 1, 0, NULL);
                uv_fs_req_cleanup(&req);

                uv_fs_close(NULL, &req, ca_file, NULL);
                bundle = CFDataCreate(kCFAllocatorDefault, ca_buf.base, len);

                rc = SecItemImport(bundle, NULL, NULL, &type, 0, NULL, NULL, &ctx->ca_bundle);
                CFRelease(bundle);
                free(ca_buf.base);
            }
            uv_fs_req_cleanup(&req);
        }

        if (rc != errSecSuccess) {
            UM_LOG(WARN, "failed to load CA bundle: %d/%s", rc, applesec_error(rc));
        }
    }

    return &ctx->api;
}

void tls_free_ctx(tls_context *ctx) {
    free(ctx);
}

static const char *tls_lib_version(void) {
    static char version[64] = {0};
    if (*version == 0) {
        CFBundleRef secBundle = CFBundleGetBundleWithIdentifier(CFSTR("com.apple.security"));
        CFDictionaryRef info = CFBundleGetInfoDictionary(secBundle);
        CFStringRef v1 = CFDictionaryGetValue(info, CFSTR("CFBundleShortVersionString"));
        CFStringRef v2  = CFDictionaryGetValue(info, CFSTR("CFBundleVersion"));

        CFMutableStringRef v = CFStringCreateMutable(kCFAllocatorDefault, 64);
        CFStringAppend(v, CFBundleGetIdentifier(secBundle));
        CFStringAppend(v, CFSTR(" "));
        CFStringAppend(v, v1);
        CFStringAppend(v, CFSTR("/"));
        CFStringAppend(v, v2);

        CFStringGetCString(v, version, sizeof(version), kCFStringEncodingASCII);
        CFRelease(v);
    }
    return version;
}

static tlsuv_engine_t new_engine(tls_context *ctx, const char *hostname) {
    struct sectransport_ctx *c = (struct sectransport_ctx *) ctx;
    struct sectransport_engine *e = calloc(1, sizeof(*e));

    e->ssl = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
    e->hs_state = TLS_HS_BEFORE;
    e->in = tlsuv_BIO_new();
    e->out = tlsuv_BIO_new();

    SSLSetPeerDomainName(e->ssl, hostname, strlen(hostname));
    if (c->ca_bundle != NULL) {
        e->ca_bundle = CFRetain(c->ca_bundle);
        SSLSetSessionOption(e->ssl, kSSLSessionOptionBreakOnServerAuth, true);
    }
    SSLSetConnection(e->ssl, e);
    SSLSetIOFuncs(e->ssl, engine_read, engine_write);

    e->api = engine_api;
    return &e->api;
}

static const char * tls_eng_error(tlsuv_engine_t e) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;
    return applesec_error(engine->error);
}

static void tls_free(tlsuv_engine_t e) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;
    free(engine->protocol);
    CFRelease(engine->ssl);
    tlsuv_BIO_free(engine->in);
    tlsuv_BIO_free(engine->out);

    free(engine);
}


static void set_protocols(tlsuv_engine_t e, const char **protos, int count) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;
    CFMutableArrayRef protocols = CFArrayCreateMutable(kCFAllocatorDefault, count, &kCFTypeArrayCallBacks);
    for (int i = 0; i < count; i++) {
        CFStringRef p = CFStringCreateWithCString(kCFAllocatorDefault,
                                                  protos[i], kCFStringEncodingASCII);
        CFArrayAppendValue(protocols, p);
        CFRelease(p);
    }
    SSLSetALPNProtocols(engine->ssl, protocols);
    CFRelease(protocols);
}

static tls_handshake_state
tls_continue_hs(tlsuv_engine_t e, char *in, size_t inlen, char *out, size_t *outlen, size_t outmax) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;

    tlsuv_BIO_put(engine->in, in, inlen);
    OSStatus rc = SSLHandshake(engine->ssl);
    *outlen = tlsuv_BIO_read(engine->out, out, outmax);

    if (rc == errSecSuccess) {
        engine->hs_state = TLS_HS_COMPLETE;
        CFArrayRef pr = NULL;
        rc = SSLCopyALPNProtocols(engine->ssl, &pr);
        if (rc == errSecSuccess) {
            CFStringRef protocol = CFArrayGetValueAtIndex(pr, 0);
            size_t len = CFStringGetLength(protocol) + 1;
            engine->protocol = malloc(len);
            CFStringGetCString(protocol, engine->protocol, len, kCFStringEncodingUTF8);
            CFRelease(protocol);
            CFRelease(pr);
        }
    } else if (rc == errSSLWouldBlock) {
        engine->hs_state = TLS_HS_CONTINUE;
    } else if (rc == errSSLPeerAuthCompleted) {
        SecTrustRef trust = NULL;
        SSLCopyPeerTrust(engine->ssl, &trust);


        SecPolicyRef p1 = SecPolicyCreateSSL(true, CFSTR("foo.bar"));

        CFArrayRef policies = NULL;
        SecTrustCopyPolicies(trust, &policies);

        SecPolicyRef p0 = CFArrayGetValueAtIndex(policies, 0);

        CFArrayRef peerCerts = NULL;
        SSLCopyPeerCertificates(engine->ssl, &peerCerts);
        SecTrustRef t1 = NULL;
        CFMutableArrayRef myp = CFArrayCreateMutable(kCFAllocatorDefault, 1, &kCFTypeArrayCallBacks);
        SecPolicyRef p2 = SecPolicyCreateBasicX509();
        CFArrayAppendValue(myp,p2);
        SecPolicyRef sslPolicy = SecPolicyCreateSSL(true,
                                                    CFSTR("fd200fd3-a2d9-457f-bc0b-f9b8ee7d2898.production.netfoundry.io"));

        CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 1,
                                                                &kCFCopyStringDictionaryKeyCallBacks,
                                                                &kCFTypeDictionaryValueCallBacks);

        CFDictionaryAddValue(dict,CFSTR("TemporalValidity"), CFSTR("0"));
        OSStatus s1 = SecPolicySetProperties(sslPolicy, dict);
        
        CFArrayAppendValue(myp, sslPolicy);
        SecTrustCreateWithCertificates(peerCerts, myp, &t1);
        SecTrustSetAnchorCertificates(t1, engine->ca_bundle);

        CFArrayRef policies2;
        SecTrustCopyPolicies(t1, &policies2);
        CFErrorRef err;
        OSStatus s = SecTrustEvaluateWithError(t1, &err);

        CFStringRef reason = CFErrorCopyFailureReason(err);

        CFIndex code = CFErrorGetCode(err);

        CFStringRef desc = CFErrorCopyDescription(err);


        //SecTrustSetAnchorCertificates(trust, engine->ca_bundle);
        //SecTrustSetAnchorCertificatesOnly(trust, true);

        s = SecTrustEvaluateWithError(trust, &err);

//        reason = CFErrorCopyFailureReason(err);
//
//        CFIndex code = CFErrorGetCode(err);
////
//        CFStringRef desc = CFErrorCopyDescription(err);
//
//        SecTrustResultType result;
//        SecTrustEvaluate(trust, &result);


        engine->error = rc;
        engine->hs_state = TLS_HS_ERROR;
    } else {
        engine->error = rc;
        engine->hs_state = TLS_HS_ERROR;
    }
    return engine->hs_state;
}

static tls_handshake_state tls_hs_state(tlsuv_engine_t e) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;
    return engine->hs_state;
}

static const char * tls_get_alpn(tlsuv_engine_t e) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;
    return engine->protocol;
}

static int tls_read(tlsuv_engine_t e, const char *in, size_t inlen, char *out, size_t *outlen, size_t outmax) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;
    if (in != NULL && inlen > 0) {
        tlsuv_BIO_put(engine->in, in, inlen);
    }

    size_t read;
    OSStatus rc = SSLRead(engine->ssl, out, outmax, &read);
    if (rc == errSSLClosedGraceful) {
        return TLS_EOF;
    }

    if (rc != errSecSuccess) {
        engine->error = rc;
        return TLS_ERR;
    }

    *outlen = read;
    if (tlsuv_BIO_available(engine->in)) {
        return TLS_READ_AGAIN;
    }

    return TLS_OK;
}

static int tls_write(tlsuv_engine_t e, const char *data, size_t datalen, char *out, size_t *outlen, size_t outmax) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;

    if (data != NULL & datalen > 0) {
        size_t wrote = 0;
        const char *p = data;
        while (p < data + datalen) {
            OSStatus rc = SSLWrite(engine->ssl, p, datalen - (p - data), &wrote);
            if (rc != errSecSuccess) {
                engine->error = rc;
                return TLS_ERR;
            }
            p += wrote;
        }
    }

    *outlen = tlsuv_BIO_read(engine->out, out, outmax);

    return (int)tlsuv_BIO_available(engine->out);
}

static int tls_close(tlsuv_engine_t e, char *out, size_t *outlen, size_t outmax) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;

    SSLClose(engine->ssl);
    *outlen = tlsuv_BIO_read(engine->out, out, outmax);

    if (tlsuv_BIO_available(engine->out) > 0) {
        return TLS_MORE_AVAILABLE;
    }
    return TLS_OK;

}



static OSStatus engine_read(SSLConnectionRef c, void *data, size_t *len) {
    struct sectransport_engine *engine = (struct sectransport_engine *) c;
    size_t requested = *len;
    size_t count = tlsuv_BIO_read(engine->in, data, *len);
    *len = count;

    return count < requested ? errSSLWouldBlock : errSecSuccess;
}

static OSStatus engine_write(SSLConnectionRef c, const void *data, size_t *len) {
    struct sectransport_engine *engine = (struct sectransport_engine *) c;
    tlsuv_BIO_put(engine->out, data, *len);
    return errSecSuccess;
}





