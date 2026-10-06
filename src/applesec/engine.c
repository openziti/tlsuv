//  Copyright (c) NetFoundry Inc
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//
//  You may obtain a copy of the License at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

// Apple Network.framework TLS backend
//

#include <pthread.h>
#include <stdatomic.h>

#include "context.h"
#include <os/lock.h>

#include "../alloc.h"
#include "../um_debug.h"
#include "../util.h"

#include <Network/Network.h>
#include <Security/SecBase.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/poll.h>

static int engine_flush(tlsuv_engine_t self);

// max plaintext handed to NW but not yet sent, plus ciphertext not yet flushed to
// the peer; engine_write() accepts no more than this is in flight
#define NW_WRITE_LIMIT (256 * 1024)
// max ciphertext from the peer handed to NW (queued on the relay) but not yet taken
// by it; forward_inbound() leaves the rest in the socket, so TCP slows the peer down.
// Without it the engine drains the socket as fast as the loop can read, and a peer
// faster than NW's decryption fills memory (a 256 MiB download held ~250 MiB here)
#define NW_READ_LIMIT (256 * 1024)
// max plaintext received from NW but not yet read by the owner. More than one 64 KiB
// read: with NW_READ_LIMIT keeping NW's backlog short, a 32 KiB limit left each
// stream read about half full (twice the callbacks, and less throughput)
#define DECODED_LIMIT (128 * 1024)
// how long a client engine waits for NW to connect to its loopback listener. That
// normally takes about a millisecond; this only bounds NW neither connecting nor
// failing
#define ACCEPT_TIMEOUT_NS (1 * NSEC_PER_SEC)

struct applesec_engine_s;
static void set_error(struct applesec_engine_s *e, CFErrorRef err);
static void fail(struct applesec_engine_s *e, int posix_code);
static CFErrorRef posix_error(int code);
static void wake(struct applesec_engine_s *e);
static void release_listener(struct applesec_engine_s *e);
static void cancel_accept(struct applesec_engine_s *e);
static void engine_release(struct applesec_engine_s *e);

static inline void log_frame(const char *dir, const char *bytes, size_t len) {
    const char *end = bytes + len;
    const char *tag = "???";
    while (bytes < end - 5) {
        uint8_t t = bytes[0];
        switch (t) {
        case 20: tag = "ChangeCipherSpec"; break;
        case 21: tag = "Alert"; break;
        case 22: tag = "Handshake";
            if (end - bytes > 5) {
                uint8_t hs_kind = bytes[5];
                switch (hs_kind) {
                    case 1: tag = "ClientHello"; break;
                    case 2: tag = "ServerHello"; break;
                    case 11: tag = "Certificate"; break;
                    case 12: tag = "ServerKeyExchange"; break;
                    case 13: tag = "CertificateRequest"; break;
                    case 14: tag = "ServerHelloDone"; break;
                    case 15: tag = "CertificateVerify"; break;
                    case 16: tag = "ClientKeyExchange"; break;
                    case 20: tag = "Finished"; break;
                    default: break;
                }
            }
            break;
        case 23: tag = "AppData"; break;
        default: break;
        }

        size_t l = ((uint8_t)bytes[3] << 8 | (uint8_t)bytes[4]);
        UM_LOG(TRACE, "%s frame[%d/%s]: %zu bytes", dir, t, tag, l);
        bytes += (5 + l);
    }
}

// lifecycle of one TLS session (one connection); engine_reset() starts a new one.
// Written on the queue, except IDLE -> STARTING (handshake) and -> IDLE (reset).
enum session_state {
    SESSION_IDLE,     // nothing created yet
    SESSION_STARTING, // client connection / server listener created, relay not ready
    SESSION_RELAYING, // tls_channel exists: peer ciphertext is forwarded to NW
    SESSION_CLOSING,  // engine_close(): the queue flushes close_notify, then stops IO
    SESSION_CLOSED,   // IO stopped (closed or freed); callbacks only drop references
};

// per-connection engine
struct applesec_engine_s {
    struct tlsuv_engine_s api;
    bool server;
    // the context had require_fips() called: restrict the cipher suites
    bool fips_required;
    _Atomic(enum session_state) session;
    // guards async_cb/async_ctx: lets close/free/setup_async swap them without the queue
    pthread_mutex_t async_mutex;
    // server engines: TLS listener on 127.0.0.1 the relay connects to
    nw_listener_t listener;
    // client engines: wait on e->queue for NW's connection to the loopback listener,
    // and time it out. Sources, not a blocking poll(): NW reports the connection's
    // state on the same queue, so a failure reaches the state handler at once.
    // e->queue only.
    dispatch_source_t accept_src;
    dispatch_source_t accept_timer;
    // written on e->queue (state handler, accept source), read on the loop thread
    _Atomic(tls_handshake_state) hs_state;

    bool io_is_socket;
    io_ctx io;
    io_read read_f;
    io_write write_f;
    int sock;
    // peer closed its side; EOF has been passed on to NW
    bool read_eof;
    // NW finished writing; shut down the peer socket once outbound_buf is flushed.
    // guarded by outbound_mutex
    bool shutdown_pending;

    // owner + each NW object (connection, listener) + pending accept source;
    // the engine is deallocated when the last one lets go (see engine_release())
    _Atomic int refs;
    // bumped by engine_reset(): completions from a replaced connection compare
    // against it and leave the new session alone
    _Atomic uint32_t conn_gen;

    dispatch_queue_t queue;
    nw_connection_t connection;

    pthread_mutex_t decode_mutex;
    bool reading_conn;
    bool conn_eof;
    // plaintext NW delivered and the owner has not read yet, kept as the data NW
    // hands over (no copy, nothing held while idle). guarded by decode_mutex
    dispatch_data_t decoded;
    // dispatch_data_get_size(decoded), set whenever decoded changes (under
    // decode_mutex); a copy because wake() reads it without the lock
    _Atomic size_t decoded_len;

    char inbound_buf[32 * 1024];
    size_t inbound_len;

    pthread_mutex_t outbound_mutex;
    dispatch_data_t outbound_buf;
    // size of outbound_buf: modified under outbound_mutex, read by wake() without it
    _Atomic size_t outbound_len;
    // plaintext passed to nw_connection_send() whose completion has not run yet
    _Atomic size_t nw_pending;
    // engine_write() turned a writer away (fully or partially): wake it when space frees up
    _Atomic bool write_blocked;
    // peer ciphertext forwarded to NW (forward_record) whose relay write has not
    // completed yet; bounded by NW_READ_LIMIT
    _Atomic size_t nw_inbound;
    // forward_inbound() stopped at NW_READ_LIMIT: wake the owner when NW catches up,
    // since records may wait in inbound_buf with nothing new on the socket to signal it
    _Atomic bool read_blocked;

    void (*async_cb)(void *async_ctx, size_t in, size_t out);
    void *async_ctx;

    nw_parameters_t protocol_parameters;
    dispatch_io_t tls_channel;
    CFErrorRef error;
    char err_buf[256];
    // negotiated ALPN protocol, owned by the engine (ALPN names are at most 255 bytes)
    char alpn[256];
    // the peer's certificate chain (SecCertificateRef), NULL if it presented none.
    // Both set by capture_session() when the connection is ready, before hs_state
    CFArrayRef peer_chain;

    CFMutableArrayRef policies;
    CFTypeRef ca;
    sec_identity_t identity;
    int(* cert_verify_f)(const struct tlsuv_certificate_s* cert, void* v_ctx);
    void *verify_ctx;
};

// engine

static void engine_set_io(tlsuv_engine_t self, io_ctx io, io_read rd, io_write wr) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    assert(rd != NULL);
    assert(wr != NULL);
    e->io = io;
    e->read_f = rd;
    e->write_f = wr;
}

static ssize_t engine_socket_read(void *io, char *buf, size_t len) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) io;
    struct pollfd pfd = { e->sock, POLLIN, 0 };
    if (poll(&pfd, 1, 0) <= 0) {
        return TLS_AGAIN;
    }
    ssize_t res = recv(e->sock, buf, len, 0);
    if (res == 0) {
        return TLS_EOF;
    }
    if (res < 0) {
        int err = errno;
        UM_LOG(TRACE, "engine_socket_read: errno=%d", err);
        if (err == EWOULDBLOCK) {
            return TLS_AGAIN;
        }
        UM_LOG(WARN, "read from peer failed: %s", strerror(err));
        set_error(e, posix_error(err));
        return TLS_ERR;
    }
    return res;
}

static ssize_t engine_socket_write(void *io, const char *buf, size_t len) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) io;
    ssize_t res = send(e->sock, buf, len, 0);
    if (res == -1) {
        int err = errno;
        UM_LOG(TRACE, "engine_socket_write: %zd/%zd errno=%d", res, len, err);
        switch (err) {
            case EWOULDBLOCK:
            // tlsuv_stream_connect_addr() hands over a socket whose connect() may
            // still be in progress; retry once it is writable (same as OpenSSL's
            // BIO_sock_non_fatal_error)
            case ENOTCONN:
            case EINPROGRESS:
            case EALREADY:
                return TLS_AGAIN;
            default:
                UM_LOG(WARN, "write to peer failed: %s", strerror(err));
                set_error(e, posix_error(err));
                return TLS_ERR;
        }
    }
    UM_LOG(TRACE, "engine_socket_write: %zd/%zd", res, len);
    return res;
}

static void close_tls_channel(struct applesec_engine_s *e);

// length of the complete TLS record at the front of inbound_buf (reading more from
// the peer if needed), or TLS_AGAIN / TLS_EOF / TLS_ERR
static ssize_t read_inbound_record(struct applesec_engine_s *e) {
    for (;;) {
        if (e->inbound_len >= 5) {
            size_t payload_len = ((uint8_t) e->inbound_buf[3]) << 8 | (uint8_t) e->inbound_buf[4];
            // RFC 8446 5.2: TLSCiphertext is at most 2^14 + 256 bytes
            if (payload_len > (1 << 14) + 256) {
                UM_LOG(WARN, "invalid TLS record length[%zu]", payload_len);
                fail(e, EBADMSG);
                return TLS_ERR;
            }
            size_t len = payload_len + 5;
            if (e->inbound_len >= len) {
                log_frame("<<< ", e->inbound_buf, len);
                return (ssize_t) len;
            }
        }

        if (e->read_eof) {
            if (e->inbound_len > 0) {
                UM_LOG(WARN, "EOF with incomplete frame");
            }
            return TLS_EOF;
        }
        // recv() with a zero length returns 0, which would look like EOF
        if (e->inbound_len == sizeof(e->inbound_buf)) {
            return TLS_AGAIN;
        }

        ssize_t rc = e->read_f(e->io, e->inbound_buf + e->inbound_len, sizeof(e->inbound_buf) - e->inbound_len);
        if (rc == TLS_EOF) {
            // peer closed: NW sees EOF once the records forwarded before it are written
            e->read_eof = true;
            close_tls_channel(e);
            continue;
        }
        if (rc < 0) {
            if (rc == TLS_ERR) {
                fail(e, EIO); // io callback failed (engine_socket_read recorded errno)
            }
            return rc;
        }
        e->inbound_len += rc;
    }
}

static void engine_set_io_fd(tlsuv_engine_t self, tlsuv_sock_t fd) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    e->io_is_socket = true;
    // set again after engine_reset() for a new connection: drop the old dup
    if (e->sock != -1) {
        close(e->sock);
    }
    int sock = dup(fd);
    e->sock = sock;
    engine_set_io(self, e, engine_socket_read, engine_socket_write);
}

static void engine_set_protocols(tlsuv_engine_t self, const char **protocols, int len) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    nw_protocol_definition_t tls = nw_protocol_copy_tls_definition();
    nw_protocol_stack_t stack = nw_parameters_copy_default_protocol_stack(e->protocol_parameters);
    nw_protocol_stack_iterate_application_protocols(stack, ^(nw_protocol_options_t opts) {
        nw_protocol_definition_t def = nw_protocol_options_copy_definition(opts);
        if (nw_protocol_definition_is_equal(def, tls)) {
            sec_protocol_options_t sec_opts = nw_tls_copy_sec_protocol_options(opts);
            for (int i = 0; i < len; i++) {
                sec_protocol_options_add_tls_application_protocol(sec_opts, protocols[i]);
            }
            nw_release(sec_opts);
        }
        nw_release(def);
    });
    nw_release(stack);
    nw_release(tls);
}

static tls_handshake_state engine_handshake_state(tlsuv_engine_t self) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    return e->hs_state;
}

static void wake(struct applesec_engine_s *e) {
    pthread_mutex_lock(&e->async_mutex);
    if (e->async_cb) {
        // callers hold at most one of decode_mutex/outbound_mutex, so read the
        // atomic sizes rather than the buffers themselves
        e->async_cb(e->async_ctx, e->decoded_len, e->outbound_len);
    }
    pthread_mutex_unlock(&e->async_mutex);
}

// once this returns the previous callback/ctx is never used again (the caller may
// free it). Only waits for a wake() in progress, never for the queue.
static void set_async(struct applesec_engine_s *e, void (*cb)(void *, size_t, size_t), void *ctx) {
    pthread_mutex_lock(&e->async_mutex);
    e->async_cb = cb;
    e->async_ctx = ctx;
    pthread_mutex_unlock(&e->async_mutex);
}

// takes ownership of `err`
// Keeps the first error: later ones are consequences of it (e.g. NW's generic
// -9808 after the verify block rejected a certificate). engine_reset() clears it.
static void set_error(struct applesec_engine_s *e, CFErrorRef err) {
    if (err == NULL) return;
    pthread_mutex_lock(&e->decode_mutex);
    if (e->error == NULL) {
        e->error = err;
        err = NULL;
    }
    pthread_mutex_unlock(&e->decode_mutex);
    if (err) CFRelease(err);
}

// record a failure unless one is recorded already (the first error is the cause:
// later ones are usually consequences of it). Every TLS_ERR / TLS_HS_ERROR the
// engine returns has an error behind it, so engine_strerror() can report it.
static void fail(struct applesec_engine_s *e, int posix_code) {
    set_error(e, posix_error(posix_code));
}

// an error with its own description (shown by engine_strerror())
static CFErrorRef describe_error(CFIndex code, const char *desc) {
    CFStringRef msg = CFStringCreateWithCString(kCFAllocatorDefault, desc, kCFStringEncodingUTF8);
    const void *keys[] = {kCFErrorLocalizedDescriptionKey};
    const void *values[] = {msg};
    CFErrorRef err = CFErrorCreateWithUserInfoKeysAndValues(kCFAllocatorDefault, kCFErrorDomainOSStatus,
                                                            code, keys, values, 1);
    CFRelease(msg);
    return err;
}

// e->queue only; takes ownership of `err`
static void handshake_failed(struct applesec_engine_s *e, CFErrorRef err) {
    set_error(e, err);
    cancel_accept(e); // NW failed before connecting: stop waiting for it
    if (e->hs_state != TLS_HS_COMPLETE) {
        e->hs_state = TLS_HS_ERROR;
        if (e->tls_channel) {
            dispatch_io_close(e->tls_channel, 0);
        }
    }
    wake(e);
}

static CFErrorRef posix_error(int code) {
    return CFErrorCreate(kCFAllocatorDefault, kCFErrorDomainPOSIX, code, NULL);
}

// e->queue only: a callback from session `gen` may still act (not replaced by
// engine_reset(), not closed/freed)
static bool is_current(struct applesec_engine_s *e, uint32_t gen) {
    return gen == e->conn_gen && e->session != SESSION_CLOSED;
}

// hand a copy of the record at the front of inbound_buf to NW (via tls_channel)
// e->queue only: a forwarded record is no longer pending (written, failed or dropped)
static void inbound_done(struct applesec_engine_s *e, uint32_t gen, size_t len) {
    if (gen != e->conn_gen) {
        // from a session replaced by engine_reset(); nw_inbound was reset with it
        return;
    }
    size_t left = (e->nw_inbound -= len);
    // hysteresis: resume forwarding once half the window is free
    if (e->read_blocked && left < NW_READ_LIMIT / 2 && atomic_exchange(&e->read_blocked, false)) {
        wake(e);
    }
}

static void forward_record(struct applesec_engine_s *e, size_t len) {
    dispatch_data_t frame = dispatch_data_create(e->inbound_buf, len,
                                                 e->queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    e->nw_inbound += len;
    uint32_t gen = e->conn_gen;
    dispatch_async(e->queue, ^{
        if (e->tls_channel) {
            dispatch_io_write(e->tls_channel, 0, frame, e->queue, ^(bool done, dispatch_data_t d, int err){
                if (err != 0) {
                    UM_LOG(WARN, "Write error: %s", strerror(err));
                }
                if (done) {
                    inbound_done(e, gen, len);
                }
            });
        } else {
            inbound_done(e, gen, len);
        }
        dispatch_release((dispatch_object_t)frame);
    });
}

static void close_tls_channel(struct applesec_engine_s *e) {
    dispatch_async(e->queue, ^{
        if (e->tls_channel) {
            dispatch_io_close(e->tls_channel, 0);
        }
    });
}

// forward the complete records received from the peer, up to NW_READ_LIMIT in flight:
// a record that decodes to no plaintext (e.g. NewSessionTicket) triggers no async
// wakeup, so records left behind in inbound_buf are only forwarded on the next
// read/handshake call; at the limit, inbound_done() wakes the owner for that.
// Returns why it stopped: TLS_AGAIN, TLS_EOF or TLS_ERR.
static int forward_inbound(struct applesec_engine_s *e) {
    ssize_t len = TLS_AGAIN;
    for (;;) {
        if (e->nw_inbound >= NW_READ_LIMIT) {
            e->read_blocked = true;
            // a relay write may have completed between the check and the flag
            if (e->nw_inbound >= NW_READ_LIMIT) {
                UM_LOG(TRACE, "engine[%p] read limit reached: %zu in flight", e, (size_t) e->nw_inbound);
                return TLS_AGAIN;
            }
            e->read_blocked = false;
        }
        if ((len = read_inbound_record(e)) <= 0) {
            break;
        }
        forward_record(e, (size_t) len);
        memmove(e->inbound_buf, e->inbound_buf + len, e->inbound_len - len);
        e->inbound_len -= len;
    }
    if (len == TLS_ERR) {
        close_tls_channel(e);
    }
    return (int) len;
}

// stop all IO and callbacks into the stream; waits for queued work to drain.
// idempotent, loop thread only.
// e->queue only: stop the relay and close the engine's dup of the caller's socket
static void stop_io(struct applesec_engine_s *e) {
    release_listener(e);
    cancel_accept(e);
    if (e->tls_channel) {
        dispatch_io_close(e->tls_channel, DISPATCH_IO_STOP);
        dispatch_release((dispatch_object_t)e->tls_channel);
        e->tls_channel = NULL;
    }
    if (e->sock != -1) {
        close(e->sock);
        e->sock = -1;
    }
}

// e->queue only: a graceful close is done (close_notify flushed) or timed out
static void finish_close(struct applesec_engine_s *e) {
    if (e->session != SESSION_CLOSING) {
        return;
    }
    e->session = SESSION_CLOSED;
    stop_io(e);
    engine_release(e); // the reference taken by engine_close()
}

static void engine_dealloc(struct applesec_engine_s *e);

static void engine_retain(struct applesec_engine_s *e) {
    e->refs++;
}

static void engine_release(struct applesec_engine_s *e) {
    if (--e->refs == 0) {
        engine_dealloc(e);
    }
}

static void engine_dealloc(struct applesec_engine_s *e) {
    // released here, not in engine_free(): late NW callbacks may still use them
    if (e->ca) CFRelease(e->ca);
    if (e->identity) sec_release(e->identity);
    if (e->protocol_parameters) nw_release(e->protocol_parameters);
    if (e->error) CFRelease(e->error);
    if (e->policies) CFRelease(e->policies);
    if (e->peer_chain) CFRelease(e->peer_chain);
    dispatch_release((dispatch_object_t)e->outbound_buf);
    dispatch_release((dispatch_object_t)e->decoded);
    pthread_mutex_destroy(&e->outbound_mutex);
    pthread_mutex_destroy(&e->decode_mutex);
    pthread_mutex_destroy(&e->async_mutex);
    // may run on the queue itself (last reference dropped by a callback): the queue
    // stays alive until that block returns
    dispatch_release(e->queue);
    tlsuv__free(e);
}

static void write_to_peer (struct applesec_engine_s *e, dispatch_data_t data) {
    size_t avail = dispatch_data_get_size(data);
    UM_LOG(TRACE, "tls_to_socket: %zu bytes", avail);

    pthread_mutex_lock(&e->outbound_mutex);
    dispatch_data_t orig = e->outbound_buf;
    e->outbound_buf = dispatch_data_create_concat(orig, data);
    e->outbound_len = dispatch_data_get_size(e->outbound_buf);
    dispatch_release((dispatch_object_t)orig);
    wake(e);
    pthread_mutex_unlock(&e->outbound_mutex);
}

static void tls_to_socket(struct applesec_engine_s *e, int socket) {
    assert(e->tls_channel == NULL);
    UM_LOG(TRACE, "staring dispatch tls_sock[%d]", socket);
    // the cleanup handler runs once the channel is closed and all its handlers have
    // run, so the channel holds an engine reference until then
    engine_retain(e);
    uint32_t gen = e->conn_gen;
    e->tls_channel = dispatch_io_create(DISPATCH_IO_STREAM, socket, e->queue, ^(int er){
        if (er != 0) {
            UM_LOG(ERR, "tls_to_socket: error %d", er);
        }
        close(socket);
        engine_release(e);
    });

    dispatch_io_set_low_water(e->tls_channel, 6);
    // dispatch_io_set_high_water(e->tls_channel, 1024);
    dispatch_io_read(e->tls_channel, 0, SIZE_MAX, e->queue,
                     ^(bool done, dispatch_data_t data, int error) {
                         UM_LOG(TRACE, "done[%d] error[%d] d[%zd]",
                             done, error, data ? dispatch_data_get_size(data) : -1);
                         if (error == ECANCELED) {
                             // stopped by stop_io()/engine_reset()
                             return;
                         }
                         if (!is_current(e, gen)) {
                             return;
                         }
                         if (error) {
                             UM_LOG(WARN, "tls read error: %s", strerror(error));
                             if (e->tls_channel) {
                                 dispatch_io_close(e->tls_channel, DISPATCH_IO_STOP);
                             }
                             return;
                         }
                         if (data) {
                             write_to_peer(e, data);
                         }
                         if (e->session == SESSION_CLOSING) {
                             // engine_close(): the owner no longer drives IO, so the queue
                             // flushes close_notify itself (socket IO only, see engine_close)
                             engine_flush((tlsuv_engine_t) e);
                             if (done) {
                                 finish_close(e);
                             }
                             return;
                         }
                         if (done && e->io_is_socket) {
                             // outbound_buf may still hold ciphertext (e.g. close_notify):
                             // engine_flush() does the shutdown once it has been written
                             pthread_mutex_lock(&e->outbound_mutex);
                             e->shutdown_pending = true;
                             wake(e);
                             pthread_mutex_unlock(&e->outbound_mutex);
                         }
                     });

    // handshake() holds peer ciphertext back until now (it would otherwise be dropped)
    e->session = SESSION_RELAYING;
    wake(e);
}

// e->queue only: what the owner may ask about the session once it is ready: the ALPN
// protocol NW negotiated (e->alpn, "" if none) and the peer's certificate chain.
// Read here, in the ready state handler, and not by engine_get_alpn()/get_peer_cert()
// on the owner's thread: queried from there, the metadata sometimes lacked a protocol
// or chain the handshake did produce (seen on the iOS simulator), and reported it
// again moments later.
static void capture_session(struct applesec_engine_s *e, nw_connection_t conn) {
    e->alpn[0] = 0;
    if (e->peer_chain) {
        CFRelease(e->peer_chain);
        e->peer_chain = NULL;
    }
    nw_protocol_definition_t definition = nw_protocol_copy_tls_definition();
    nw_protocol_metadata_t metadata = nw_connection_copy_protocol_metadata(conn, definition);
    if (metadata) {
        sec_protocol_metadata_t sec_metadata = nw_tls_copy_sec_protocol_metadata(metadata);
        if (sec_metadata) {
            // the string belongs to sec_metadata: copy it before releasing
            const char *negotiated = sec_protocol_metadata_get_negotiated_protocol(sec_metadata);
            if (negotiated) {
                strlcpy(e->alpn, negotiated, sizeof(e->alpn));
            }

            CFMutableArrayRef chain = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
            sec_protocol_metadata_access_peer_certificate_chain(sec_metadata, ^(sec_certificate_t c) {
                SecCertificateRef ref = sec_certificate_copy_ref(c);
                if (ref) {
                    CFArrayAppendValue(chain, ref);
                    CFRelease(ref);
                }
            });
            if (CFArrayGetCount(chain) > 0) {
                e->peer_chain = chain;
            } else {
                CFRelease(chain);
            }
            sec_release(sec_metadata);
        }
        nw_release(metadata);
    }
    nw_release(definition);
}

// state handler shared by client connections and connections accepted by the server listener
static void set_connection_handler(struct applesec_engine_s *e, nw_connection_t conn) {
    // held until the cancelled state, which is the connection's last callback
    engine_retain(e);
    uint32_t gen = e->conn_gen;
    nw_connection_set_state_changed_handler(conn, ^(nw_connection_state_t state, nw_error_t error) {
        if (state == nw_connection_state_cancelled) {
            UM_LOG(DEBG, "Connection cancelled");
            engine_release(e);
            return;
        }
        if (!is_current(e, gen)) {
            // replaced by engine_reset(), or closed/freed: nothing to report to
            return;
        }
        if (error) {
            UM_LOG(WARN, "connection error: %d", nw_error_get_error_code(error));
            // wakes the stream so process_connect/process_inbound sees the failure
            handshake_failed(e, nw_error_copy_cf_error(error));
        }
        switch (state) {
        case nw_connection_state_preparing: {
            // don't clobber TLS_HS_ERROR set by a failed accept
            tls_handshake_state expected = TLS_HS_BEFORE;
            atomic_compare_exchange_strong(&e->hs_state, &expected, TLS_HS_CONTINUE);
            break;
        }
        case nw_connection_state_ready:
            // before hs_state: the owner reads these once it sees the handshake complete
            capture_session(e, conn);
            e->hs_state = TLS_HS_COMPLETE;
            UM_LOG(DEBG, "Handshake completed successfully!");
            wake(e);
            break;
        case nw_connection_state_failed:
            UM_LOG(DEBG, "Connection failed");
            break;
        default:
            UM_LOG(WARN, "unhandled state: %d", state);
            break;
        }
    });
}

// e->queue only: stop waiting for NW's connection (accepted, failed, timed out,
// reset or closed). The cancel handler closes the listening socket.
static void cancel_accept(struct applesec_engine_s *e) {
    if (e->accept_timer) {
        dispatch_source_cancel(e->accept_timer);
        dispatch_release((dispatch_object_t)e->accept_timer);
        e->accept_timer = NULL;
    }
    if (e->accept_src) {
        dispatch_source_cancel(e->accept_src);
        dispatch_release((dispatch_object_t)e->accept_src);
        e->accept_src = NULL;
    }
}

// e->queue only: wait for NW to connect to `lsoc` (engine_create_client) without
// blocking the queue; owns `lsoc` and one engine reference
static void start_accept(struct applesec_engine_s *e, uint32_t gen, int lsoc) {
    if (!is_current(e, gen) || e->hs_state == TLS_HS_ERROR) {
        // reset/closed/freed, or NW already failed, before this ran
        close(lsoc);
        engine_release(e);
        return;
    }

    dispatch_source_t src = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, lsoc, 0, e->queue);
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, e->queue);
    e->accept_src = src;
    e->accept_timer = timer;

    dispatch_source_set_cancel_handler(src, ^{
        close(lsoc);
        engine_release(e);
    });

    // both are cancelled together (cancel_accept) before any of these could run
    // for a replaced session, so they only ever act for session `gen`
    dispatch_source_set_event_handler(src, ^{
        int tls_sock = accept(lsoc, NULL, 0);
        int accept_err = errno;
        cancel_accept(e);
        if (tls_sock < 0) {
            UM_LOG(WARN, "accept failed: %s", strerror(accept_err));
            handshake_failed(e, posix_error(accept_err));
            return;
        }
        int true_val = 1;
        setsockopt(tls_sock, SOL_SOCKET, SO_NOSIGPIPE, &true_val, sizeof(true_val));
        setsockopt(tls_sock, IPPROTO_TCP, TCP_NODELAY, &true_val, sizeof(true_val));
        tls_to_socket(e, tls_sock);
    });

    // backstop for NW neither connecting nor reporting a failure
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, ACCEPT_TIMEOUT_NS),
                              DISPATCH_TIME_FOREVER, ACCEPT_TIMEOUT_NS / 10);
    dispatch_source_set_event_handler(timer, ^{
        UM_LOG(WARN, "nw_connection did not connect in time");
        handshake_failed(e, posix_error(ETIMEDOUT)); // cancels the accept
    });

    dispatch_resume((dispatch_object_t)src);
    dispatch_resume((dispatch_object_t)timer);
}

static enum tls_handshake_st engine_create_client(struct applesec_engine_s *e) {
    assert(e);
    assert(e->connection == NULL);
    assert(e->server == false);

    int lsoc = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr = htonl(INADDR_LOOPBACK),
    };
    if (bind(lsoc, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        listen(lsoc, 1) < 0) {
        int err = errno;
        UM_LOG(WARN, "failed to bind or listen: %s", strerror(err));
        close(lsoc);
        set_error(e, posix_error(err));
        return TLS_HS_ERROR;
    }

    socklen_t len = sizeof(addr);
    getsockname(lsoc, (struct sockaddr *) &addr, &len);

    char port[10];
    snprintf(port, sizeof(port), "%d", ntohs(addr.sin_port));
    nw_endpoint_t ep = nw_endpoint_create_host("127.0.0.1", port);
    nw_connection_t conn = nw_connection_create(ep, e->protocol_parameters);
    nw_release(ep);

    set_connection_handler(e, conn);

    nw_connection_set_queue(conn, e->queue);
    nw_connection_start(conn);
    e->connection = conn;

    // the listening socket and the engine reference belong to the accept source
    // (released by its cancel handler); it is set up on the queue, which owns it
    engine_retain(e);
    uint32_t gen = e->conn_gen;
    dispatch_async(e->queue, ^{
        start_accept(e, gen, lsoc);
    });

    return TLS_HS_BEFORE;
}

// server engines: the relay socket connects to a TLS listener on 127.0.0.1, and
// the connection the listener accepts is the TLS session (the mirror image of the
// client, where NW connects to our listener)
static enum tls_handshake_st engine_create_server(struct applesec_engine_s *e) {
    assert(e);
    assert(e->server);
    assert(e->listener == NULL);

    nw_listener_t listener = nw_listener_create(e->protocol_parameters);
    if (listener == NULL) {
        UM_LOG(WARN, "failed to create TLS listener");
        set_error(e, posix_error(errno ? errno : EIO));
        return TLS_HS_ERROR;
    }

    nw_listener_set_queue(listener, e->queue);
    // held until the listener's cancelled state, its last callback
    engine_retain(e);
    uint32_t gen = e->conn_gen;
    nw_listener_set_state_changed_handler(listener, ^(nw_listener_state_t state, nw_error_t error) {
        if (state == nw_listener_state_cancelled) {
            engine_release(e);
            return;
        }
        if (!is_current(e, gen)) {
            return;
        }
        if (state == nw_listener_state_failed) {
            UM_LOG(WARN, "TLS listener failed: %d", error ? nw_error_get_error_code(error) : 0);
            handshake_failed(e, error ? nw_error_copy_cf_error(error) : posix_error(EIO));
            return;
        }
        if (state != nw_listener_state_ready) {
            return;
        }

        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(nw_listener_get_port(listener)),
            .sin_addr = htonl(INADDR_LOOPBACK),
        };
        int tls_sock = socket(AF_INET, SOCK_STREAM, 0);
        // blocking connect: the listener is ready on loopback, so this completes
        // from the kernel's backlog without waiting for the accept handler
        if (tls_sock < 0 || connect(tls_sock, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
            int err = errno;
            UM_LOG(WARN, "failed to connect to TLS listener: %s", strerror(err));
            if (tls_sock >= 0) close(tls_sock);
            handshake_failed(e, posix_error(err));
            return;
        }
        int true_val = 1;
        setsockopt(tls_sock, SOL_SOCKET, SO_NOSIGPIPE, &true_val, sizeof(true_val));
        setsockopt(tls_sock, IPPROTO_TCP, TCP_NODELAY, &true_val, sizeof(true_val));
        tls_to_socket(e, tls_sock);
    });

    nw_listener_set_new_connection_handler(listener, ^(nw_connection_t conn) {
        if (!is_current(e, gen) || e->connection != NULL) {
            // stale, or a second peer on the port (not our relay)
            nw_connection_cancel(conn);
            return;
        }
        nw_retain(conn);
        e->connection = conn;
        set_connection_handler(e, conn);
        nw_connection_set_queue(conn, e->queue);
        nw_connection_start(conn);

        // the accepted connection lives on without the listener
        nw_listener_cancel(listener);
    });

    e->listener = listener;
    nw_listener_start(listener);
    return TLS_HS_BEFORE;
}

// e->queue only
static void release_listener(struct applesec_engine_s *e) {
    if (e->listener) {
        // handlers stay: they ignore stale events, and the cancelled state drops
        // the listener's engine reference
        nw_listener_cancel(e->listener);
        nw_release(e->listener);
        e->listener = NULL;
    }
}

static tls_handshake_state engine_handshake(tlsuv_engine_t self) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    assert(e->read_f != NULL);
    assert(e->write_f != NULL);

    if (engine_flush(self) == TLS_ERR) {
        e->hs_state = TLS_HS_ERROR;
    }

    tls_handshake_state state = e->hs_state;
    UM_LOG(TRACE, "engine_handshake: %d", state);

    if (state == TLS_HS_ERROR || state == TLS_HS_COMPLETE) {
        return state;
    }

    if (e->session == SESSION_IDLE) {
        e->session = SESSION_STARTING;
        tls_handshake_state rc = e->server ? engine_create_server(e) : engine_create_client(e);
        if (rc == TLS_HS_ERROR) {
            e->hs_state = TLS_HS_ERROR;
        }
        return e->hs_state;
    }

    // until the relay exists, leave peer ciphertext in the socket / inbound_buf
    if (e->session == SESSION_RELAYING) {
        forward_inbound(e);
    }

    return e->hs_state;
}

static const char* engine_get_alpn(tlsuv_engine_t self) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    // NULL: not known yet; "" once the handshake completed with nothing negotiated,
    // like the other backends. e->alpn is set by capture_session() before hs_state.
    if (e->hs_state != TLS_HS_COMPLETE) {
        return NULL;
    }
    return e->alpn;
}

// the chain the peer sent, leaf first, as recorded by Network.framework
static int engine_get_peer_cert(tlsuv_engine_t self, tlsuv_certificate_t *cert) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    if (cert == NULL) return TLS_ERR;
    *cert = NULL;

    // e->peer_chain is set by capture_session() before hs_state
    if (e->hs_state != TLS_HS_COMPLETE) {
        return TLS_ERR;
    }
    if (e->peer_chain == NULL) {
        UM_LOG(VERB, "peer presented no certificate");
        return TLS_ERR;
    }

    // a copy: the certificate outlives neither the engine nor a reset
    *cert = applesec_cert_new(CFArrayCreateCopy(kCFAllocatorDefault, e->peer_chain)); // takes ownership
    return 0;
}

// Does not block: IO is stopped on the queue. On a completed connection over a
// socket, NW sends close_notify on a graceful cancel (a final send does not); it
// comes back through the relay, is flushed to the socket from the queue, and IO
// stops once NW is done (or after 200 ms). With set_io the io callbacks are the
// owner's and not thread safe, so close_notify cannot be flushed and is skipped.
static int engine_close(tlsuv_engine_t self) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    set_async(e, NULL, NULL); // no wakeups into the owner after this

    engine_retain(e); // held by the close until IO is stopped
    dispatch_async(e->queue, ^{
        if (e->session == SESSION_CLOSING || e->session == SESSION_CLOSED) {
            engine_release(e);
            return;
        }

        bool graceful = e->session == SESSION_RELAYING && e->connection != NULL &&
                        e->hs_state == TLS_HS_COMPLETE && e->io_is_socket;
        if (!graceful) {
            e->session = SESSION_CLOSED;
            stop_io(e);
            engine_release(e);
            return;
        }

        e->session = SESSION_CLOSING; // keeps the close's reference until finish_close()
        nw_connection_cancel(e->connection);

        engine_retain(e); // for the timer
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC), e->queue, ^{
            if (e->session == SESSION_CLOSING) {
                UM_LOG(DEBG, "engine[%p] close_notify was not flushed in time", e);
            }
            finish_close(e);
            engine_release(e);
        });
    });
    return TLS_OK;
}

static int engine_flush(tlsuv_engine_t self) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    __block int result = TLS_OK;

    pthread_mutex_lock(&e->outbound_mutex);
    dispatch_data_t buf = e->outbound_buf;
    bool had_data = dispatch_data_get_size(buf) > 0;
    if (had_data) {
        __block size_t total = 0;
        bool complete = dispatch_data_apply(buf, ^bool(dispatch_data_t slice, size_t offset, const void *b, size_t len) {
            ssize_t wrote = e->write_f(e->io, b, len);
            if (wrote < 0) {
                result = (int)wrote;
                if (wrote == TLS_ERR) {
                    fail(e, EIO); // io callback failed (engine_socket_write recorded errno)
                }
                return false;
            }
            total += wrote;
            if (wrote < len) {
                result = TLS_AGAIN;
                return false;
            }
            return true;
        });
        if (complete) {
            e->outbound_buf = dispatch_data_empty;
            e->outbound_len = 0;
        } else {
            e->outbound_buf = dispatch_data_create_subrange(buf, total, dispatch_data_get_size(buf) - total);
            e->outbound_len = dispatch_data_get_size(e->outbound_buf);
        }
        dispatch_release((dispatch_object_t)buf);
    }

    if (result == TLS_OK && e->shutdown_pending) {
        e->shutdown_pending = false;
        if (e->sock != -1) {
            shutdown(e->sock, SHUT_WR);
        }
    }

    // drained: tell the stream, so it stops polling for writability
    if (had_data && result == TLS_OK) {
        wake(e);
    }

    pthread_mutex_unlock(&e->outbound_mutex);
    return result;
}

static int engine_write(tlsuv_engine_t self, const char *data, size_t data_len) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    if (e->connection == NULL || e->hs_state != TLS_HS_COMPLETE) {
        UM_LOG(WARN, "engine[%p] write before the handshake completed", e);
        fail(e, ENOTCONN);
        return TLS_ERR;
    }

    pthread_mutex_lock(&e->decode_mutex);
    bool failed = e->error != NULL;
    pthread_mutex_unlock(&e->decode_mutex);
    if (failed) {
        return TLS_ERR;
    }

    int flush_rc = engine_flush(self);
    if (flush_rc == TLS_ERR) {
        UM_LOG(WARN, "flush to peer failed");
        return flush_rc;
    }
    if (flush_rc == TLS_AGAIN) {
        UM_LOG(DEBG, "peer is stalled");
        return flush_rc;
    }
    if (data_len == 0) {
        return 0;
    }

    // NW encrypts asynchronously, so an empty outbound_buf does not mean the peer
    // keeps up: bound what is in flight, not just what is already encrypted
    size_t in_flight = e->nw_pending + e->outbound_len;
    if (in_flight >= NW_WRITE_LIMIT) {
        e->write_blocked = true;
        // a send completion may have freed space between the check and the flag
        in_flight = e->nw_pending + e->outbound_len;
        if (in_flight >= NW_WRITE_LIMIT) {
            UM_LOG(TRACE, "engine[%p] write limit reached: %zu in flight", e, in_flight);
            return TLS_AGAIN;
        }
        e->write_blocked = false;
    }

    size_t n = MIN(data_len, NW_WRITE_LIMIT - in_flight);
    if (n < data_len) {
        // the caller queues the rest and waits for a wakeup
        e->write_blocked = true;
    }
    e->nw_pending += n;

    UM_LOG(TRACE, "engine[%p] write: %zu/%zu", e, n, data_len);
    dispatch_data_t dd = dispatch_data_create(data, n, e->queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    uint32_t gen = e->conn_gen;
    nw_connection_send(e->connection, dd, NW_CONNECTION_DEFAULT_STREAM_CONTEXT, false, ^(nw_error_t error) {
        // ECANCELED: engine_free()/engine_reset() cancelled the connection, `e` may be gone
        if (error && nw_error_get_error_code(error) == ECANCELED) {
            return;
        }
        if (gen != e->conn_gen) {
            // from a connection replaced by engine_reset(); nw_pending was reset with it
            return;
        }

        e->nw_pending -= n;
        if (error) {
            UM_LOG(WARN, "send failed: %d", nw_error_get_error_code(error));
            // report through read/write; the stream still owns the engine, so don't cancel here
            set_error(e, nw_error_copy_cf_error(error));
            wake(e);
            return;
        }

        // hysteresis: wake a blocked writer once half the window is free
        if (e->write_blocked && e->nw_pending + e->outbound_len < NW_WRITE_LIMIT / 2 &&
            atomic_exchange(&e->write_blocked, false)) {
            wake(e);
        }
    });
    dispatch_release((dispatch_object_t)dd);

    return (int) n;
}

static bool process_decoded(struct applesec_engine_s *e, uint32_t gen, dispatch_data_t dd, nw_content_context_t ctx, bool done, nw_error_t er){
    UM_LOG(TRACE, "dd[%p] done[%d] er[%d]", dd, done, er ? nw_error_get_error_code(er) : 0);
    // ECANCELED: the connection was cancelled (engine_free/engine_reset), `e` may be gone
    if (er != NULL && nw_error_get_error_code(er) == ECANCELED) {
        return false;
    }
    if (gen != e->conn_gen) {
        // from a connection replaced by engine_reset()
        return false;
    }
    if (er != NULL) {
        int code = nw_error_get_error_code(er);

        set_error(e, nw_error_copy_cf_error(er));
        switch (nw_error_get_error_domain(er)) {
        case nw_error_domain_tls: UM_LOG(WARN, "tls error[%d]", code); break;
        case nw_error_domain_posix: UM_LOG(WARN, "posix error[%d/%s]", code, strerror(code)); break;
        default:
            UM_LOG(WARN, "unexpected error domain[%d] error[%d]",
                nw_error_get_error_domain(er), nw_error_get_error_code(er));
        }
    }

    pthread_mutex_lock(&e->decode_mutex);
    if (dd && dispatch_data_get_size(dd) > 0) {
        UM_LOG(TRACE, "engine[%p] decoded %zd bytes", e, dispatch_data_get_size(dd));
        dispatch_data_t orig = e->decoded;
        e->decoded = dispatch_data_create_concat(orig, dd);
        e->decoded_len = dispatch_data_get_size(e->decoded);
        dispatch_release((dispatch_object_t)orig);
    }
    if (done) {
        e->conn_eof = true;
    }
    e->reading_conn = false;

    if (er == NULL && !done && e->decoded_len < DECODED_LIMIT) {
        e->reading_conn = true;
        nw_connection_receive(
            e->connection, 0, DECODED_LIMIT - e->decoded_len,
            ^(dispatch_data_t d, nw_content_context_t c, bool done1, nw_error_t er1){
                process_decoded(e, gen, d, c, done1, er1);
            });
    }
    // EOF and errors too, even without data: the owner may have drained the socket
    // and wait only for this wakeup to learn the stream ended
    if (e->decoded_len > 0 || done || er != NULL) {
        wake(e);
    }
    pthread_mutex_unlock(&e->decode_mutex);
    return done;
}

static int engine_read(tlsuv_engine_t self, char *out, size_t *out_bytes, size_t maxout) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    int rc;
    // async wakeups always come through here; this also carries out a pending shutdown
    // when there is nothing left to flush (the stream only flushes on UV_WRITABLE)
    engine_flush(self);

    rc = forward_inbound(e);

    *out_bytes = 0;
    pthread_mutex_lock(&e->decode_mutex);
    if (e->decoded_len > 0) {
        size_t to_copy = MIN(e->decoded_len, maxout);
        __block size_t copied = 0;
        dispatch_data_apply(e->decoded, ^bool(dispatch_data_t r, size_t off, const void *bytes, size_t len) {
            size_t n = MIN(len, to_copy - copied);
            memcpy(out + copied, bytes, n);
            copied += n;
            return copied < to_copy;
        });
        // the rest stays where NW put it
        dispatch_data_t rest = dispatch_data_create_subrange(e->decoded, to_copy, e->decoded_len - to_copy);
        dispatch_release((dispatch_object_t)e->decoded);
        e->decoded = rest;
        e->decoded_len = dispatch_data_get_size(rest);

        *out_bytes = to_copy;
        rc = e->decoded_len > 0 ? TLS_MORE_AVAILABLE : TLS_OK;
    }

    // re-arm whenever no receive is pending: process_decoded stops once `decoded` is full,
    // and the remaining plaintext may already be inside NW with no new ciphertext coming
    if (e->connection != NULL && e->error == NULL && !e->reading_conn && !e->conn_eof &&
        e->decoded_len < DECODED_LIMIT) {
        UM_LOG(TRACE, "engine[%p] starting decode receive", e);
        e->reading_conn = true;
        uint32_t gen = e->conn_gen;
        nw_connection_receive(e->connection, 0, DECODED_LIMIT - e->decoded_len,
                              ^(dispatch_data_t dd, nw_content_context_t ctx, bool done, nw_error_t er){
                                  process_decoded(e, gen, dd, ctx, done, er);
                              });
    }

    int result = TLS_OK;
    if (*out_bytes > 0) {
        if (e->decoded_len > 0 || e->conn_eof)
            result = TLS_MORE_AVAILABLE;
    } else if (e->conn_eof) {
        result = TLS_EOF;
    } else if (e->error != NULL) {
        result = TLS_ERR;
    } else {
        // nothing decoded yet: either a receive is pending (async_cb will wake us)
        // or we need more ciphertext from the socket
        result = TLS_AGAIN;
    }

    pthread_mutex_unlock(&e->decode_mutex);
    return result;
}

static const char* engine_strerror(tlsuv_engine_t self) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    const char *res = NULL;

    // e->error is replaced by set_error() on e->queue
    pthread_mutex_lock(&e->decode_mutex);
    if (e->error != NULL) {
        CFStringRef msg = CFErrorCopyDescription(e->error);
        if (!CFStringGetCString(msg, e->err_buf, sizeof(e->err_buf), kCFStringEncodingUTF8)) {
            snprintf(e->err_buf, sizeof(e->err_buf), "error %ld", (long) CFErrorGetCode(e->error));
        }
        CFRelease(msg);
        res = e->err_buf;
    }
    pthread_mutex_unlock(&e->decode_mutex);
    return res;
}

// drop the current connection and all per-session state, so the next
// engine_handshake() starts a fresh handshake over the same io
static int engine_reset(tlsuv_engine_t self) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;

    // everything tied to the connection runs on e->queue: detach it there
    __block nw_connection_t old = NULL;
    dispatch_sync(e->queue, ^{
        old = e->connection;
        e->connection = NULL;
        e->conn_gen++;
        release_listener(e);
        cancel_accept(e);
        if (e->peer_chain) {
            CFRelease(e->peer_chain);
            e->peer_chain = NULL;
        }
        e->session = SESSION_IDLE;
        if (e->tls_channel) {
            dispatch_io_close(e->tls_channel, DISPATCH_IO_STOP);
            dispatch_release((dispatch_object_t)e->tls_channel);
            e->tls_channel = NULL;
        }

        pthread_mutex_lock(&e->outbound_mutex);
        dispatch_release((dispatch_object_t)e->outbound_buf);
        e->outbound_buf = dispatch_data_empty;
        e->outbound_len = 0;
        e->shutdown_pending = false;
        pthread_mutex_unlock(&e->outbound_mutex);

        pthread_mutex_lock(&e->decode_mutex);
        dispatch_release((dispatch_object_t)e->decoded);
        e->decoded = dispatch_data_empty;
        e->decoded_len = 0;
        e->conn_eof = false;
        e->reading_conn = false;
        if (e->error) {
            CFRelease(e->error);
            e->error = NULL;
        }
        pthread_mutex_unlock(&e->decode_mutex);
    });

    if (old) {
        nw_connection_cancel(old);
        nw_release(old);
    }

    // loop-thread state
    e->inbound_len = 0;
    e->read_eof = false;
    e->nw_pending = 0;
    e->write_blocked = false;
    e->nw_inbound = 0;
    e->read_blocked = false;
    e->alpn[0] = 0;
    e->hs_state = TLS_HS_BEFORE;
    return 0;
}

static void engine_free(tlsuv_engine_t self) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    if (e == NULL) return;

    set_async(e, NULL, NULL); // no wakeups into the owner after this

    // the rest runs on the queue; from there on, callbacks still in flight only
    // drop their references
    dispatch_async(e->queue, ^{
        if (e->session != SESSION_CLOSING) {
            // (a graceful close stops IO itself once close_notify is out)
            e->session = SESSION_CLOSED;
            stop_io(e);
        }

        nw_connection_t conn = e->connection;
        e->connection = NULL;
        if (conn != NULL) {
            // its cancelled state releases the connection's engine reference
            nw_connection_cancel(conn);
            nw_release(conn);
        }
        engine_release(e); // the owner's reference: `e` may be gone after this
    });
}

static void engine_setup_async(tlsuv_engine_t self, void (*cb)(void *, size_t, size_t), void *async_ctx) {
    struct applesec_engine_s *e = (struct applesec_engine_s *) self;
    set_async(e, cb, async_ctx);
}

static struct tlsuv_engine_s applesec_engine_api = {
        .set_io = engine_set_io,
        .set_io_fd = engine_set_io_fd,
        .set_protocols = engine_set_protocols,
        .handshake_state = engine_handshake_state,
        .handshake = engine_handshake,
        .get_alpn = engine_get_alpn,
        .get_peer_cert = engine_get_peer_cert,
        .close = engine_close,
        .write = engine_write,
        .read = engine_read,
        .strerror = engine_strerror,
        .reset = engine_reset,
        .free = engine_free,
        .setup_async = engine_setup_async,
};

// Apple's SSL server policy caps certificate lifetime (825 days, check key
// "OtherTrustValidityPeriod") even for private CAs. Ziti controllers use long-lived
// certificates and the other backends don't enforce the cap, so when the chain is
// anchored to the configured CA bundle, a failure is tolerated if that cap is the
// only check that failed. Hostname, EKU, key size, expiry etc. are still enforced.
// "StatusCodes" accompanies every failure and carries no check of its own.
// The TrustResultDetails keys are not public API: anything unrecognised is a failure.
static bool only_validity_cap_failed(SecTrustRef trust) {
    bool cap_failed = false;
    bool other_failed = false;

    CFDictionaryRef result = SecTrustCopyResult(trust);
    CFArrayRef details = result ? CFDictionaryGetValue(result, CFSTR("TrustResultDetails")) : NULL;
    if (details == NULL || CFGetTypeID(details) != CFArrayGetTypeID()) {
        if (result) CFRelease(result);
        return false;
    }

    for (CFIndex i = 0; i < CFArrayGetCount(details) && !other_failed; i++) {
        CFDictionaryRef checks = CFArrayGetValueAtIndex(details, i);
        if (CFGetTypeID(checks) != CFDictionaryGetTypeID()) {
            other_failed = true;
            break;
        }
        CFIndex n = CFDictionaryGetCount(checks);
        if (n == 0) continue;

        const void **keys = tlsuv__calloc(n, sizeof(*keys));
        CFDictionaryGetKeysAndValues(checks, keys, NULL);
        for (CFIndex k = 0; k < n; k++) {
            CFStringRef keyName = (CFStringRef)keys[k];
            if (CFEqual(keys[k], CFSTR("OtherTrustValidityPeriod"))) {
                cap_failed = true;
            } else if (!CFEqual(keys[k], CFSTR("StatusCodes"))) {
                other_failed = true;
            }
        }
        tlsuv__free(keys);
    }
    CFRelease(result);
    return cap_failed && !other_failed;
}

// Installs the verify block that validates the peer's certificate chain: the verify
// callback if there is one, else the configured CA bundle as the only trust anchors.
// Does nothing when neither is set, which leaves the decision to Network.framework
// (system trust on a client, and no client authentication on a server).
// `what` ("server"/"client") names the peer's certificate in logs and errors.
// e->policies must hold the policies for that peer.
static void set_peer_verify(struct applesec_engine_s *e, sec_protocol_options_t sec_options,
                            const char *what) {
    if (e->cert_verify_f) {
        sec_protocol_options_set_verify_block(sec_options,
            ^(sec_protocol_metadata_t metadata, sec_trust_t trust_ref, sec_protocol_verify_complete_t complete){
                CFMutableArrayRef certs = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
                sec_protocol_metadata_access_peer_certificate_chain(metadata, ^(sec_certificate_t cert){
                    SecCertificateRef ref = sec_certificate_copy_ref(cert);
                    CFArrayAppendValue(certs, ref);
                    CFRelease(ref);
                });
                tlsuv_certificate_t tlsuv_cert = applesec_cert_new(certs);
                int rc = e->cert_verify_f(tlsuv_cert, e->verify_ctx);
                tlsuv_cert->free(tlsuv_cert);
                if (rc != 0) {
                    char msg[96];
                    snprintf(msg, sizeof(msg), "%s certificate rejected by the verify callback", what);
                    UM_LOG(WARN, "%s: %d", msg, rc);
                    set_error(e, describe_error(errSSLBadCert, msg));
                }
                complete(rc == 0);
            },
            e->queue);
    } else if (e->ca) {
        sec_protocol_options_set_verify_block(sec_options,
            ^(sec_protocol_metadata_t metadata, sec_trust_t trust_ref, sec_protocol_verify_complete_t complete){
                SecTrustRef ref = sec_trust_copy_ref(trust_ref);
                SecTrustSetPolicies(ref, e->policies);
                SecTrustSetAnchorCertificates(ref, e->ca);
                SecTrustSetAnchorCertificatesOnly(ref, true);
                CFErrorRef err = NULL;
                if (SecTrustEvaluateWithError(ref, &err)) {
                    complete(true);
                } else if (only_validity_cap_failed(ref)) {
                    UM_LOG(DEBG, "accepting %s certificate over Apple's max validity period"
                                 " (anchored to configured CA bundle)", what);
                    if (err) CFRelease(err);
                    complete(true);
                } else {
                    char msg[256] = "unknown error";
                    if (err) {
                        CFStringRef desc = CFErrorCopyDescription(err);
                        CFStringGetCString(desc, msg, sizeof(msg), kCFStringEncodingUTF8);
                        CFRelease(desc);
                    } else {
                        char text[96];
                        snprintf(text, sizeof(text), "%s certificate verification failed", what);
                        err = describe_error(errSSLXCertChainInvalid, text);
                    }
                    UM_LOG(WARN, "%s certificate verification failed: %s", what, msg);
                    // the reason for engine_strerror(): NW's own error after this
                    // is a generic -9808
                    set_error(e, err);
                    complete(false);
                }
                CFRelease(ref);
            },
            e->queue);
    }
}

// ctx->ssl_chain is [SecIdentityRef, intermediates...] (built by tls_set_own_cert).
// sec_identity_create_with_certificates() takes the chain to send, leaf first.
static sec_identity_t new_client_identity(struct applesec_ctx *ctx) {
    if (ctx->ssl_chain == NULL || CFArrayGetCount(ctx->ssl_chain) == 0) {
        return NULL;
    }
    // the handshake signs with this key: its keychain must not be locked by then
    applesec_unlock_identity(ctx);

    SecIdentityRef id_ref = (SecIdentityRef) CFArrayGetValueAtIndex(ctx->ssl_chain, 0);
    CFIndex n = CFArrayGetCount(ctx->ssl_chain);
    if (n == 1) {
        return sec_identity_create(id_ref);
    }

    SecCertificateRef leaf = NULL;
    OSStatus rc = SecIdentityCopyCertificate(id_ref, &leaf);
    if (rc != errSecSuccess) {
        UM_LOG(WARN, "failed to get client certificate: %s", applesec_error(rc));
        return NULL;
    }

    CFMutableArrayRef certs = CFArrayCreateMutable(kCFAllocatorDefault, n, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(certs, leaf);
    CFRelease(leaf);
    for (CFIndex i = 1; i < n; i++) {
        CFArrayAppendValue(certs, CFArrayGetValueAtIndex(ctx->ssl_chain, i));
    }
    sec_identity_t identity = sec_identity_create_with_certificates(id_ref, certs);
    CFRelease(certs);
    return identity;
}

// TLS 1.3 AES-GCM plus TLS 1.2 ECDHE AES-GCM. Appending any suite replaces the default set.
static void apply_fips_suites(sec_protocol_options_t opts) {
    static const tls_ciphersuite_t suites[] = {
        tls_ciphersuite_AES_256_GCM_SHA384,
        tls_ciphersuite_AES_128_GCM_SHA256,
        tls_ciphersuite_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls_ciphersuite_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls_ciphersuite_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        tls_ciphersuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    };
    for (size_t i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
        sec_protocol_options_append_tls_ciphersuite(opts, suites[i]);
    }
}

// state shared by client and server engines
static struct applesec_engine_s *engine_alloc(struct applesec_ctx *sec_ctx) {
    struct applesec_engine_s *e = tlsuv__calloc(1, sizeof(*e));
    e->api = applesec_engine_api;
    e->refs = 1; // the owner's, dropped by engine_free()
    e->hs_state = TLS_HS_BEFORE;
    e->ca = sec_ctx->ca_bundle ? CFRetain(sec_ctx->ca_bundle) : NULL;
    e->identity = new_client_identity(sec_ctx);
    e->sock = -1;
    e->fips_required = sec_ctx->fips_required;
    e->cert_verify_f = sec_ctx->cert_verify_f;
    e->verify_ctx = sec_ctx->verify_ctx;
    e->outbound_buf = dispatch_data_empty;
    e->decoded = dispatch_data_empty;

    dispatch_queue_t global = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    e->queue = dispatch_queue_create_with_target(
        "tlsuv.queue", DISPATCH_QUEUE_SERIAL, global);

    pthread_mutex_init(&e->outbound_mutex, NULL);
    pthread_mutex_init(&e->decode_mutex, NULL);
    pthread_mutex_init(&e->async_mutex, NULL);
    return e;
}

static tls_protocol_version_t min_tls_version(const struct applesec_ctx *ctx) {
    return ctx->min_version == TLSUV_TLS13 ? tls_protocol_version_TLSv13 : tls_protocol_version_TLSv12;
}

tlsuv_engine_t applesec_new_engine(tls_context *ctx, const char *host) {
    struct applesec_ctx* sec_ctx = (struct applesec_ctx *) ctx;
    struct applesec_engine_s *e = engine_alloc(sec_ctx);

    // no host (e.g. tlsuv_stream_connect_addr() without a hostname): the SSL policy
    // then skips the name check
    CFStringRef hostname = host ? CFStringCreateWithCString(kCFAllocatorDefault, host,
                                                            kCFStringEncodingUTF8) : NULL;
    // `true` = we are evaluating a server certificate
    SecPolicyRef ssl_policy = SecPolicyCreateSSL(true, hostname);
    SecPolicyRef x509_policy = SecPolicyCreateBasicX509();

    CFMutableArrayRef policies =
            CFArrayCreateMutable(kCFAllocatorDefault, 2, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(policies, ssl_policy);
    CFArrayAppendValue(policies, x509_policy);

    CFRelease(ssl_policy);
    CFRelease(x509_policy);
    if (hostname) CFRelease(hostname);

    e->policies = policies;

    e->protocol_parameters = nw_parameters_create_secure_tcp(
        ^(nw_protocol_options_t opts){
            sec_protocol_options_t sec_options = nw_tls_copy_sec_protocol_options(opts);
            sec_protocol_options_set_min_tls_protocol_version(sec_options, min_tls_version(sec_ctx));
            sec_protocol_options_set_max_tls_protocol_version(sec_options, tls_protocol_version_TLSv13);
            if (e->fips_required) {
                apply_fips_suites(sec_options);
            }
            sec_protocol_options_set_tls_server_name(sec_options, host);
            if (e->identity) {
                sec_protocol_options_set_local_identity(sec_options, e->identity);
            }
            set_peer_verify(e, sec_options, "server");
            nw_release(sec_options);
        },
        ^(nw_protocol_options_t opts) {
            nw_tcp_options_set_no_delay(opts, true);
        }
    );

    return (tlsuv_engine_t) e;
}

// Client certificates are required (and validated) when the context has a CA bundle or a
// verify callback, and not requested otherwise. Network.framework only offers "required"
// publicly (the optional mode is not public API), which is also what the other backends do.
tlsuv_engine_t applesec_new_server_engine(tls_context *ctx) {
    struct applesec_ctx* sec_ctx = (struct applesec_ctx *) ctx;
    if (sec_ctx->ssl_chain == NULL) {
        UM_LOG(WARN, "server engine requires own certificate (set_own_cert)");
        return NULL;
    }

    struct applesec_engine_s *e = engine_alloc(sec_ctx);
    e->server = true;
    if (e->identity == NULL) {
        UM_LOG(WARN, "failed to create server identity");
        e->api.free((tlsuv_engine_t) e);
        return NULL;
    }

    // required mode needs a verify block of ours: without one Network.framework would
    // fall back to evaluating the client certificate against the system trust store
    bool client_auth = e->cert_verify_f != NULL || e->ca != NULL;
    if (client_auth) {
        // `false` = we are evaluating a client certificate
        SecPolicyRef ssl_policy = SecPolicyCreateSSL(false, NULL);
        SecPolicyRef x509_policy = SecPolicyCreateBasicX509();
        CFMutableArrayRef policies =
                CFArrayCreateMutable(kCFAllocatorDefault, 2, &kCFTypeArrayCallBacks);
        CFArrayAppendValue(policies, ssl_policy);
        CFArrayAppendValue(policies, x509_policy);
        CFRelease(ssl_policy);
        CFRelease(x509_policy);
        e->policies = policies;
    }

    e->protocol_parameters = nw_parameters_create_secure_tcp(
        ^(nw_protocol_options_t opts){
            sec_protocol_options_t sec_options = nw_tls_copy_sec_protocol_options(opts);
            sec_protocol_options_set_min_tls_protocol_version(sec_options, min_tls_version(sec_ctx));
            sec_protocol_options_set_max_tls_protocol_version(sec_options, tls_protocol_version_TLSv13);
            if (e->fips_required) {
                apply_fips_suites(sec_options);
            }
            sec_protocol_options_set_local_identity(sec_options, e->identity);
            if (client_auth) {
                sec_protocol_options_set_peer_authentication_required(sec_options, true);
                set_peer_verify(e, sec_options, "client");
            }
            nw_release(sec_options);
        },
        ^(nw_protocol_options_t opts) {
            nw_tcp_options_set_no_delay(opts, true);
        }
    );

    // listen on loopback only, ephemeral port: only the engine's own relay connects
    nw_endpoint_t local = nw_endpoint_create_host("127.0.0.1", "0");
    nw_parameters_set_local_endpoint(e->protocol_parameters, local);
    nw_release(local);

    return (tlsuv_engine_t) e;
}


