

#include "tlsuv/tls_engine.h"
#include "um_debug.h"
#include "context.h"
#include <uv.h>

#include <security/Security.h>
#include <security/SecureTransport.h>

struct sectransport_engine {
    struct tlsuv_engine_s api;
    CFArrayRef policies;
    CFArrayRef ca_bundle;
    SSLContextRef ssl;
    tls_handshake_state hs_state;
    char *protocol;
    OSStatus error;

    int socket;
    void *io;
    io_read read_f;
    io_write write_f;
};

// tls context funcs
static const char* tls_lib_version(void);
static void tls_free_ctx(tls_context *ctx);

// tls engine funcs
static void set_protocols(tlsuv_engine_t, const char **protos, int count);
static tls_handshake_state tls_continue_hs(tlsuv_engine_t);
static tls_handshake_state tls_hs_state(tlsuv_engine_t);
static OSStatus engine_read(SSLConnectionRef, void *data, size_t *len);
static OSStatus engine_write(SSLConnectionRef, const void *data, size_t *len);
static const char * tls_get_alpn(tlsuv_engine_t);
static int tls_read(tlsuv_engine_t, char *out, size_t *outlen, size_t outmax);
static int tls_write(tlsuv_engine_t, const char *data, size_t datalen);
static int tls_close(tlsuv_engine_t);
static void tls_free(tlsuv_engine_t);
static const char * tls_eng_error(tlsuv_engine_t);
static void tls_set_socket(tlsuv_engine_t, uv_os_fd_t sock);
static void tls_set_io(tlsuv_engine_t e, io_ctx ctx, io_read read_f, io_write write_f);


static struct tlsuv_engine_s engine_api = {
        .set_io = tls_set_io,
        .set_io_fd = tls_set_socket,
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



tlsuv_engine_t new_engine(tls_context *ctx, const char *hostname) {
    struct sectransport_ctx *c = (struct sectransport_ctx *) ctx;
    struct sectransport_engine *e = calloc(1, sizeof(*e));
    OSStatus rc = 0;
    e->ssl = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
    e->hs_state = TLS_HS_BEFORE;

    rc = SSLSetPeerDomainName(e->ssl, hostname, strlen(hostname));

    if (c->ca_bundle != NULL) {
        e->ca_bundle = CFRetain(c->ca_bundle);

        CFMutableArrayRef policies = CFArrayCreateMutable(kCFAllocatorDefault, 2, &kCFTypeArrayCallBacks);
        CFStringRef host = CFStringCreateWithCString(kCFAllocatorDefault, hostname, kCFStringEncodingUTF8);
        CFArrayAppendValue(policies, SecPolicyCreateSSL(false, host));
        CFArrayAppendValue(policies, SecPolicyCreateBasicX509());

        e->policies = policies;
        SSLSetSessionOption(e->ssl, kSSLSessionOptionBreakOnServerAuth, true);
    }

    e->socket = -1;
    SSLSetConnection(e->ssl, e);
    SSLSetIOFuncs(e->ssl, engine_read, engine_write);

    e->api = engine_api;
    return &e->api;
}

static void tls_set_io(tlsuv_engine_t e, io_ctx ctx, io_read read_f, io_write write_f) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;
    engine->io = ctx;
    engine->read_f = read_f;
    engine->write_f = write_f;
}

static void tls_set_socket(tlsuv_engine_t e, uv_os_fd_t sock) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;
    engine->socket = sock;
}

static const char * tls_eng_error(tlsuv_engine_t e) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;
    return applesec_error(engine->error);
}

static void tls_free(tlsuv_engine_t e) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;
    free(engine->protocol);
    CFRelease(engine->ssl);

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

static tls_handshake_state tls_continue_hs(tlsuv_engine_t e) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;
    OSStatus rc;

    hs_continue:
    rc = SSLHandshake(engine->ssl);
    fprintf(stderr, "\n>>> %d\n", rc);
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
        UM_LOG(INFO, "custom CA verify");
        SecTrustRef trust = NULL;
        SSLCopyPeerTrust(engine->ssl, &trust);
        SecTrustSetPolicies(trust, engine->policies);
        SecTrustSetAnchorCertificates(trust, engine->ca_bundle);

        CFErrorRef trust_error;
        if (!SecTrustEvaluateWithError(trust, &trust_error)) {
            CFStringRef reason = CFErrorCopyFailureReason(trust_error);
            CFIndex code = CFErrorGetCode(trust_error);
            CFStringRef desc = CFErrorCopyDescription(trust_error);
            engine->error = rc;
            engine->hs_state = TLS_HS_ERROR;
        } else {
            engine->error = TLS_OK;
            engine->hs_state == TLS_HS_CONTINUE;
            goto hs_continue;
        }
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

static int tls_read(tlsuv_engine_t e, char *out, size_t *outlen, size_t outmax) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;

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
    return TLS_OK;
}

static int tls_write(tlsuv_engine_t e, const char *data, size_t datalen) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;

    size_t total = 0;
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
            total += wrote;
        }
    }

    return (int)total;
}

static int tls_close(tlsuv_engine_t e) {
    struct sectransport_engine *engine = (struct sectransport_engine *) e;

    SSLClose(engine->ssl);
    return TLS_OK;
}

static OSStatus engine_read(SSLConnectionRef c, void *data, size_t *len) {
    struct sectransport_engine *engine = (struct sectransport_engine *) c;
    size_t requested = *len;

    fprintf(stderr, "reading %zd\n", *len);
    int err = errSecSuccess;
    ssize_t count;
    if (engine->socket != -1) {
        fprintf(stderr, "reading socket[%d]\n", engine->socket);
        count = read(engine->socket, data, *len);
        int e = errno;
        if (count == 0) {
            err = errSSLClosedNoNotify;
        } else if (count < 0) {
            if (e == EWOULDBLOCK) {
                *len = 0;
                err = errSSLWouldBlock;
            } else {
                err = errSSLInternal;
            }
        } else if (count < *len) {
            err = errSSLWouldBlock;
        }
    } else if (engine->read_f) {
        count = engine->read_f(engine->io, data, *len);
        if (count == TLS_AGAIN) {
            *len = 0;
            err = errSSLWouldBlock;
        } else if (count == TLS_EOF) {
            err = errSSLClosedNoNotify;
        } else if (count < 0) {
            err = errSSLInternal;
        }
    } else {
        return errSSLInternal;
    }
    if (err == errSecSuccess) {
        fprintf(stderr, "\nread %zd bytes\n", count);
        *len = count;
    } else {
        fprintf(stderr, ">>>> error[%d]\n", err);
    }
    fflush(stderr);

    return err;
}

static OSStatus engine_write(SSLConnectionRef c, const void *data, size_t *len) {
    struct sectransport_engine *engine = (struct sectransport_engine *) c;
    fprintf(stderr, "\nwriting: %zd bytes\n", *len);
    ssize_t count = 0;
    if (engine->socket != -1) {
        count = write(engine->socket, data, *len);
        fprintf(stderr, "\nwrote: %zd bytes\n", count);

        if (count < 0) {
            if (errno == EAGAIN) {
                return errSSLWouldBlock;
            } else {
                return errSSLInternal;
            }
        }
    } else if (engine->write_f) {
        count = engine->write_f(engine->io, data, *len);
        if (count == TLS_AGAIN) {
            return errSSLWouldBlock;
        } else if (count < 0){
            return errSSLInternal;
        }
    } else {
        return errSSLInternal;
    }
    *len = count;
    return errSecSuccess;
}





