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

//
// Apple SecureTransport engine.
//
// SecureTransport is deprecated, but it is the only Apple TLS API that lets the
// caller own the transport: SSLSetIOFuncs() maps directly onto the engine's
// set_io()/set_io_fd() callbacks. Network.framework owns its own socket and
// cannot be driven this way.
//
// Note SecureTransport tops out at TLS 1.2 -- there is no TLS 1.3 support.
//

#include "context.h"
#include "tlsuv/tls_engine.h"
#include "um_debug.h"
#include "util.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <Network/Network.h>

// larger than a max TLS record (16437) plus the largest chunk we hand SSLWrite
#define ST_OUTBOUND_SZ (32 * 1024)
#define ST_WRITE_CHUNK (16 * 1024)

struct sectransport_engine {
    struct tlsuv_engine_s api;

    SSLContextRef ssl;

    // everything below is needed to rebuild `ssl` in reset(): a SecureTransport
    // context cannot be reused across sessions.
    char *host;
    CFArrayRef ca_bundle;
    CFArrayRef policies;
    CFArrayRef own_chain;
    char **protocols;
    int protocols_len;
    int (*cert_verify_f)(const struct tlsuv_certificate_s *cert, void *v_ctx);
    void *verify_ctx;

    // per-session
    tls_handshake_state hs_state;
    bool peer_auth_done;
    char *alpn;
    OSStatus error;

    io_ctx io;
    io_read read_f;
    io_write write_f;

    char outbound[ST_OUTBOUND_SZ];
    size_t out_len;
};

static void tls_set_io(tlsuv_engine_t e, io_ctx ctx, io_read read_f, io_write write_f);
static void tls_set_io_fd(tlsuv_engine_t e, tlsuv_sock_t fd);
static void tls_set_protocols(tlsuv_engine_t e, const char **protos, int count);
static tls_handshake_state tls_hs_state(tlsuv_engine_t e);
static tls_handshake_state tls_continue_hs(tlsuv_engine_t e);
static const char *tls_get_alpn(tlsuv_engine_t e);
static int tls_close(tlsuv_engine_t e);
static int tls_write(tlsuv_engine_t e, const char *data, size_t datalen);
static int tls_read(tlsuv_engine_t e, char *out, size_t *outlen, size_t outmax);
static const char *tls_eng_error(tlsuv_engine_t e);
static int tls_reset(tlsuv_engine_t e);
static void tls_free(tlsuv_engine_t e);

static OSStatus st_io_read(SSLConnectionRef c, void *data, size_t *len);
static OSStatus st_io_write(SSLConnectionRef c, const void *data, size_t *len);

static struct tlsuv_engine_s engine_api = {
        .set_io = tls_set_io,
        .set_io_fd = tls_set_io_fd,
        .set_protocols = tls_set_protocols,
        .handshake_state = tls_hs_state,
        .handshake = tls_continue_hs,
        .get_alpn = tls_get_alpn,
        .close = tls_close,
        .write = tls_write,
        .read = tls_read,
        .strerror = tls_eng_error,
        .reset = tls_reset,
        .free = tls_free,
};

// ------------------------------------------------------------------ helpers

static bool is_ip_literal(const char *host) {
    struct in6_addr addr;
    return inet_pton(AF_INET, host, &addr) == 1 || inet_pton(AF_INET6, host, &addr) == 1;
}

static void free_protocols(struct sectransport_engine *e) {
    for (int i = 0; i < e->protocols_len; i++) {
        tlsuv__free(e->protocols[i]);
    }
    tlsuv__free(e->protocols);
    e->protocols = NULL;
    e->protocols_len = 0;
}

static OSStatus apply_protocols(struct sectransport_engine *e) {
    if (e->protocols_len == 0) return errSecSuccess;

    CFMutableArrayRef protos =
            CFArrayCreateMutable(kCFAllocatorDefault, e->protocols_len, &kCFTypeArrayCallBacks);
    for (int i = 0; i < e->protocols_len; i++) {
        CFStringRef p = CFStringCreateWithCString(kCFAllocatorDefault, e->protocols[i],
                                                  kCFStringEncodingUTF8);
        CFArrayAppendValue(protos, p);
        CFRelease(p);
    }
    OSStatus rc = SSLSetALPNProtocols(e->ssl, protos);
    CFRelease(protos);
    if (rc != errSecSuccess) {
        UM_LOG(WARN, "failed to set ALPN protocols: %s", applesec_error(rc));
    }
    return rc;
}

// creates and configures the SSLContextRef. called by new_engine() and reset().
static int st_init_ssl(struct sectransport_engine *e) {
    e->ssl = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
    if (e->ssl == NULL) {
        UM_LOG(ERR, "failed to create SSL context");
        return -1;
    }

    // SNI. SecureTransport rejects IP literals here.
    if (e->host != NULL && !is_ip_literal(e->host)) {
        OSStatus rc = SSLSetPeerDomainName(e->ssl, e->host, strlen(e->host));
        if (rc != errSecSuccess) {
            UM_LOG(WARN, "failed to set peer domain name: %s", applesec_error(rc));
        }
    }

    SSLSetConnection(e->ssl, e);
    SSLSetIOFuncs(e->ssl, st_io_read, st_io_write);

    // break out of the handshake to do our own verification whenever the caller
    // supplied either anchors or a verify callback; otherwise let SecureTransport
    // validate against the system trust store.
    if (e->ca_bundle != NULL || e->cert_verify_f != NULL) {
        SSLSetSessionOption(e->ssl, kSSLSessionOptionBreakOnServerAuth, true);
    }

    if (e->own_chain != NULL) {
        OSStatus rc = SSLSetCertificate(e->ssl, e->own_chain);
        if (rc != errSecSuccess) {
            UM_LOG(ERR, "failed to set client certificate: %s", applesec_error(rc));
            return -1;
        }
    }

    apply_protocols(e);

    e->hs_state = TLS_HS_BEFORE;
    e->peer_auth_done = false;
    e->error = 0;
    e->out_len = 0;
    tlsuv__free(e->alpn);
    e->alpn = NULL;
    return 0;
}

tlsuv_engine_t applesec_new_engine(tls_context *ctx, const char *hostname) {
    struct sectransport_ctx *c = (struct sectransport_ctx *) ctx;
    struct sectransport_engine *e = tlsuv__calloc(1, sizeof(*e));

    e->api = engine_api;
    e->host = hostname ? tlsuv__strdup(hostname) : NULL;
    e->cert_verify_f = c->cert_verify_f;
    e->verify_ctx = c->verify_ctx;

    if (c->ca_bundle != NULL) {
        e->ca_bundle = CFRetain(c->ca_bundle);
    }
    if (c->ssl_chain != NULL) {
        e->own_chain = CFRetain(c->ssl_chain);
    }

    if (e->host != NULL) {
        CFStringRef host = CFStringCreateWithCString(kCFAllocatorDefault, e->host,
                                                     kCFStringEncodingUTF8);
        // `true` = we are evaluating a server certificate
        SecPolicyRef ssl_policy = SecPolicyCreateSSL(true, host);
        SecPolicyRef x509_policy = SecPolicyCreateBasicX509();

        CFMutableArrayRef policies =
                CFArrayCreateMutable(kCFAllocatorDefault, 2, &kCFTypeArrayCallBacks);
        CFArrayAppendValue(policies, ssl_policy);
        CFArrayAppendValue(policies, x509_policy);

        CFRelease(ssl_policy);
        CFRelease(x509_policy);
        CFRelease(host);
        e->policies = policies;
    }

    if (st_init_ssl(e) != 0) {
        tls_free(&e->api);
        return NULL;
    }
    return &e->api;
}

// ----------------------------------------------------------------------- IO

static ssize_t sock_read(io_ctx io, char *buf, size_t len) {
    int fd = (int) (intptr_t) io;
    ssize_t n;
    do {
        n = recv(fd, buf, len, 0);
    } while (n < 0 && errno == EINTR);

    if (n == 0) return TLS_EOF;
    if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? TLS_AGAIN : TLS_ERR;
    return n;
}

static ssize_t sock_write(io_ctx io, const char *buf, size_t len) {
    int fd = (int) (intptr_t) io;
    ssize_t n;
    do {
        n = send(fd, buf, len, 0);
    } while (n < 0 && errno == EINTR);

    if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? TLS_AGAIN : TLS_ERR;
    return n;
}

static void tls_set_io(tlsuv_engine_t self, io_ctx ctx, io_read read_f, io_write write_f) {
    struct sectransport_engine *e = (struct sectransport_engine *) self;
    e->io = ctx;
    e->read_f = read_f;
    e->write_f = write_f;
}

static void tls_set_io_fd(tlsuv_engine_t self, tlsuv_sock_t fd) {
    // one IO path for the rest of the engine
    tls_set_io(self, (io_ctx) (intptr_t) fd, sock_read, sock_write);
}

// drains any ciphertext parked by st_io_write().
// returns 0 when empty, TLS_AGAIN when bytes remain, TLS_ERR on failure.
static int st_flush(struct sectransport_engine *e) {
    while (e->out_len > 0) {
        ssize_t n = e->write_f(e->io, e->outbound, e->out_len);
        if (n == TLS_AGAIN) return TLS_AGAIN;
        if (n < 0) {
            UM_LOG(WARN, "failed to write to transport");
            return TLS_ERR;
        }
        if ((size_t) n < e->out_len) {
            memmove(e->outbound, e->outbound + n, e->out_len - n);
        }
        e->out_len -= n;
    }
    return 0;
}

// SecureTransport requires *len to be set to the number of bytes actually
// transferred on EVERY return, including errSSLWouldBlock.
static OSStatus st_io_read(SSLConnectionRef c, void *data, size_t *len) {
    struct sectransport_engine *e = (struct sectransport_engine *) c;
    size_t want = *len, got = 0;
    *len = 0;

    if (e->read_f == NULL) return errSSLInternal;

    while (got < want) {
        ssize_t n = e->read_f(e->io, (char *) data + got, want - got);
        if (n > 0) {
            got += (size_t) n;
            continue;
        }
        *len = got;
        if (n == TLS_AGAIN) return errSSLWouldBlock;
        if (n == TLS_EOF) {
            // a real close_notify is something only SecureTransport can see;
            // this is just the socket going away.
            return got > 0 ? errSSLWouldBlock : errSSLClosedNoNotify;
        }
        return got > 0 ? errSSLWouldBlock : errSSLInternal;
    }

    *len = got;
    return errSecSuccess;
}

static OSStatus st_io_write(SSLConnectionRef c, const void *data, size_t *len) {
    struct sectransport_engine *e = (struct sectransport_engine *) c;
    size_t want = *len, sent = 0;
    *len = 0;

    if (e->write_f == NULL) return errSSLInternal;

    // only bypass the buffer while it is empty, or ciphertext would reorder
    if (e->out_len == 0) {
        while (sent < want) {
            ssize_t n = e->write_f(e->io, (const char *) data + sent, want - sent);
            if (n > 0) {
                sent += (size_t) n;
                continue;
            }
            if (n == TLS_AGAIN) break;
            *len = sent;
            return errSSLInternal;
        }
        if (sent == want) {
            *len = want;
            return errSecSuccess;
        }
    }

    // park the rest so SSLWrite/SSLHandshake never see a would-block
    size_t rem = want - sent;
    if (e->out_len + rem > sizeof(e->outbound)) {
        *len = sent;
        return errSSLWouldBlock;
    }
    memcpy(e->outbound + e->out_len, (const char *) data + sent, rem);
    e->out_len += rem;
    *len = want;
    return errSecSuccess;
}

// ---------------------------------------------------------------- handshake

static void capture_alpn(struct sectransport_engine *e) {
    CFArrayRef protos = NULL;
    if (SSLCopyALPNProtocols(e->ssl, &protos) != errSecSuccess || protos == NULL) {
        return;
    }
    if (CFArrayGetCount(protos) > 0) {
        // borrowed reference -- must not be released
        CFStringRef p = CFArrayGetValueAtIndex(protos, 0);
        CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(p),
                                                        kCFStringEncodingUTF8) + 1;
        e->alpn = tlsuv__calloc(1, max);
        CFStringGetCString(p, e->alpn, max, kCFStringEncodingUTF8);
    }
    CFRelease(protos);
}

// runs at the kSSLSessionOptionBreakOnServerAuth break
static int st_verify_peer(struct sectransport_engine *e) {
    SecTrustRef trust = NULL;
    OSStatus rc = SSLCopyPeerTrust(e->ssl, &trust);
    if (rc != errSecSuccess || trust == NULL) {
        UM_LOG(ERR, "failed to get peer trust: %s", applesec_error(rc));
        e->error = rc;
        return -1;
    }

    int result;
    if (e->cert_verify_f != NULL) {
        // a caller-supplied callback replaces trust evaluation entirely, the
        // same way it does for the other backends
        CFArrayRef chain = SecTrustCopyCertificateChain(trust);
        if (chain == NULL) {
            e->error = errSSLXCertChainInvalid;
            CFRelease(trust);
            return -1;
        }
        tlsuv_certificate_t cert = applesec_cert_new(chain); // takes ownership
        result = e->cert_verify_f(cert, e->verify_ctx) == 0 ? 0 : -1;
        cert->free(cert);
        if (result != 0) {
            e->error = errSSLXCertChainInvalid;
        }
    } else {
        SecTrustSetPolicies(trust, e->policies);
        SecTrustSetAnchorCertificates(trust, e->ca_bundle);
        // without this the system anchors are trusted in addition to ours
        SecTrustSetAnchorCertificatesOnly(trust, true);

        CFErrorRef err = NULL;
        if (SecTrustEvaluateWithError(trust, &err)) {
            result = 0;
        } else {
            CFStringRef desc = err ? CFErrorCopyDescription(err) : NULL;
            char buf[512] = "<unknown>";
            if (desc) {
                CFStringGetCString(desc, buf, sizeof(buf), kCFStringEncodingUTF8);
                CFRelease(desc);
            }
            UM_LOG(ERR, "server certificate rejected: %s", buf);
            e->error = err ? (OSStatus) CFErrorGetCode(err) : errSSLXCertChainInvalid;
            result = -1;
        }
        if (err) CFRelease(err);
    }

    CFRelease(trust);
    return result;
}

static tls_handshake_state tls_hs_state(tlsuv_engine_t self) {
    struct sectransport_engine *e = (struct sectransport_engine *) self;
    return e->hs_state;
}

static tls_handshake_state tls_continue_hs(tlsuv_engine_t self) {
    struct sectransport_engine *e = (struct sectransport_engine *) self;

    if (e->hs_state == TLS_HS_COMPLETE || e->hs_state == TLS_HS_ERROR) {
        return e->hs_state;
    }
    if (e->read_f == NULL || e->write_f == NULL) {
        UM_LOG(ERR, "handshake started before IO was set");
        e->hs_state = TLS_HS_ERROR;
        return e->hs_state;
    }
    if (st_flush(e) == TLS_ERR) {
        e->hs_state = TLS_HS_ERROR;
        return e->hs_state;
    }

    e->hs_state = TLS_HS_CONTINUE;
    for (;;) {
        OSStatus rc = SSLHandshake(e->ssl);
        switch (rc) {
            case errSecSuccess:
                capture_alpn(e);
                st_flush(e);
                e->hs_state = TLS_HS_COMPLETE;
                return e->hs_state;

            case errSSLWouldBlock:
                st_flush(e);
                e->hs_state = TLS_HS_CONTINUE;
                return e->hs_state;

            case errSSLPeerAuthCompleted:
                if (e->peer_auth_done) {
                    UM_LOG(ERR, "peer auth signalled twice in one session");
                    e->error = rc;
                    e->hs_state = TLS_HS_ERROR;
                    return e->hs_state;
                }
                e->peer_auth_done = true;
                if (st_verify_peer(e) != 0) {
                    e->hs_state = TLS_HS_ERROR;
                    return e->hs_state;
                }
                continue;

            case errSSLClosedGraceful:
            case errSSLClosedAbort:
            case errSSLClosedNoNotify:
                UM_LOG(ERR, "peer closed during handshake: %s", applesec_error(rc));
                e->error = rc;
                e->hs_state = TLS_HS_ERROR;
                return e->hs_state;

            default:
                UM_LOG(ERR, "handshake failed: %s", applesec_error(rc));
                e->error = rc;
                e->hs_state = TLS_HS_ERROR;
                return e->hs_state;
        }
    }
}

static void tls_set_protocols(tlsuv_engine_t self, const char **protos, int count) {
    struct sectransport_engine *e = (struct sectransport_engine *) self;

    free_protocols(e);
    if (protos == NULL || count <= 0) return;

    // kept so reset() can re-apply them to the rebuilt SSL context
    e->protocols = tlsuv__calloc(count, sizeof(char *));
    for (int i = 0; i < count; i++) {
        e->protocols[i] = tlsuv__strdup(protos[i]);
    }
    e->protocols_len = count;

    apply_protocols(e);
}

static const char *tls_get_alpn(tlsuv_engine_t self) {
    struct sectransport_engine *e = (struct sectransport_engine *) self;
    return e->alpn ? e->alpn : "";
}

// -------------------------------------------------------------- read/write

static int tls_read(tlsuv_engine_t self, char *out, size_t *outlen, size_t outmax) {
    struct sectransport_engine *e = (struct sectransport_engine *) self;

    // callers pass an uninitialized *outlen, so set it on every path
    *outlen = 0;

    if (e->hs_state != TLS_HS_COMPLETE) {
        UM_LOG(ERR, "read before handshake completed");
        return TLS_ERR;
    }
    if (st_flush(e) == TLS_ERR) {
        return TLS_ERR;
    }

    size_t got = 0;
    OSStatus rc = SSLRead(e->ssl, out, outmax, &got);
    *outlen = got;

    size_t buffered = 0;
    SSLGetBufferedReadSize(e->ssl, &buffered);

    switch (rc) {
        case errSecSuccess:
        case errSSLWouldBlock:
            // never return TLS_OK with 0 bytes: callers loop on it
            if (got == 0) return TLS_AGAIN;
            return buffered > 0 ? TLS_MORE_AVAILABLE : TLS_OK;

        case errSSLClosedGraceful:
        case errSSLClosedNoNotify:
            // hand over what we have; the next call reports EOF
            return got > 0 ? TLS_MORE_AVAILABLE : TLS_EOF;

        default:
            UM_LOG(ERR, "read failed: %s", applesec_error(rc));
            e->error = rc;
            return TLS_ERR;
    }
}

static int tls_write(tlsuv_engine_t self, const char *data, size_t datalen) {
    struct sectransport_engine *e = (struct sectransport_engine *) self;

    if (e->hs_state != TLS_HS_COMPLETE) {
        UM_LOG(ERR, "write before handshake completed");
        return TLS_ERR;
    }

    int f = st_flush(e);
    if (f != 0) return f;

    if (data == NULL || datalen == 0) return 0;

    size_t total = 0;
    while (total < datalen) {
        size_t chunk = datalen - total;
        if (chunk > ST_WRITE_CHUNK) chunk = ST_WRITE_CHUNK;

        size_t wrote = 0;
        OSStatus rc = SSLWrite(e->ssl, data + total, chunk, &wrote);
        total += wrote;

        if (rc == errSecSuccess) {
            if (st_flush(e) == TLS_ERR) {
                e->error = errSSLInternal;
                return total > 0 ? (int) total : TLS_ERR;
            }
            continue;
        }
        if (rc == errSSLWouldBlock) break;

        UM_LOG(ERR, "write failed: %s", applesec_error(rc));
        e->error = rc;
        return total > 0 ? (int) total : TLS_ERR;
    }

    st_flush(e);
    return total > 0 ? (int) total : TLS_AGAIN;
}

static int tls_close(tlsuv_engine_t self) {
    struct sectransport_engine *e = (struct sectransport_engine *) self;
    st_flush(e);
    SSLClose(e->ssl);
    st_flush(e);
    return TLS_OK;
}

static const char *tls_eng_error(tlsuv_engine_t self) {
    struct sectransport_engine *e = (struct sectransport_engine *) self;
    return applesec_error(e->error);
}

static int tls_reset(tlsuv_engine_t self) {
    struct sectransport_engine *e = (struct sectransport_engine *) self;

    // a SecureTransport context cannot be reused, so rebuild it. The IO
    // callbacks are deliberately kept: set_io() is only called once, at init.
    if (e->ssl) {
        CFRelease(e->ssl);
        e->ssl = NULL;
    }
    if (st_init_ssl(e) != 0) {
        e->hs_state = TLS_HS_ERROR;
        return -1;
    }
    return 0;
}

static void tls_free(tlsuv_engine_t self) {
    struct sectransport_engine *e = (struct sectransport_engine *) self;
    if (e == NULL) return;

    if (e->ssl) CFRelease(e->ssl);
    if (e->policies) CFRelease(e->policies);
    if (e->ca_bundle) CFRelease(e->ca_bundle);
    if (e->own_chain) CFRelease(e->own_chain);
    free_protocols(e);
    tlsuv__free(e->host);
    tlsuv__free(e->alpn);
    tlsuv__free(e);
}
