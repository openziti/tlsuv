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

#define NOT_IMPLEMENTED(...) UM_LOG(WARN, "applenw: " __VA_ARGS__)

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

struct tls_frame {
    uint16_t len;
    uint16_t recv;
    char *frame;
};

// per-connection engine
struct applenw_engine_s {
    struct tlsuv_engine_s api;

    tls_handshake_state hs_state;

    bool io_is_socket;
    io_ctx io;
    io_read read_f;
    io_write write_f;
    int sock;
    bool read_eof;
    bool eof_forwarded;

    int tls_sock;
    dispatch_queue_t queue;
    nw_connection_t connection;

    pthread_mutex_t decode_mutex;
    pthread_cond_t decode_cond;
    bool reading_conn;
    bool conn_eof;
    uint8_t decoded[32 * 1024];
    size_t decoded_len;

    char inbound_buf[32 * 1024];
    size_t inbound_len;
    struct tls_frame inbound_frame;

    int (*async_cb)(void *async_ctx);
    void *async_ctx;

    nw_parameters_t protocol_parameters;
    dispatch_io_t tls_channel;
    CFErrorRef error;
    CFTypeRef ca;
    sec_identity_t identity;
    int(* cert_verify_f)(const struct tlsuv_certificate_s* cert, void* v_ctx);
    void *verify_ctx;
};

// engine

static void engine_set_io(tlsuv_engine_t self, io_ctx io, io_read rd, io_write wr) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
    assert(rd != NULL);
    assert(wr != NULL);
    e->io = io;
    e->read_f = rd;
    e->write_f = wr;
}

static ssize_t engine_socket_read(void *io, char *buf, size_t len) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) io;
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
        return TLS_ERR;
    }
    return res;
}

static ssize_t engine_socket_write(void *io, const char *buf, size_t len) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) io;
    ssize_t res = send(e->sock, buf, len, 0);
    UM_LOG(TRACE, "engine_socket_write: %zd/%zd", res, len);
    if (res == -1) {
        int err = errno;
        if (err == EWOULDBLOCK) {
            return TLS_AGAIN;
        }
        return TLS_ERR;
    }
    return res;
}

static int read_inbound_frame(struct applenw_engine_s *e) {
    ssize_t rc;
    if (e->inbound_len < 5) goto do_read;

    uint16_t payload_len = ((uint8_t)e->inbound_buf[3]) << 8 | (uint8_t)e->inbound_buf[4];
    // RFC 8446 5.2: TLSCiphertext is at most 2^14 + 256 bytes
    if (payload_len > (1 << 14) + 256) {
        UM_LOG(WARN, "invalid TLS record length[%u]", payload_len);
        return TLS_ERR;
    }
    e->inbound_frame.len = payload_len + 5;
    e->inbound_frame.frame = e->inbound_buf;
    e->inbound_frame.recv = MIN(e->inbound_len, e->inbound_frame.len);

    if (e->inbound_frame.recv == e->inbound_frame.len) {
        log_frame("<<< ", e->inbound_buf, e->inbound_frame.len);
        return TLS_OK;
    }

do_read:
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
    rc = e->read_f(e->io, e->inbound_buf + e->inbound_len, sizeof(e->inbound_buf) - e->inbound_len);
    if (rc == TLS_EOF) {
        e->read_eof = true;
    }
    if (rc == TLS_ERR || rc == TLS_AGAIN || rc == TLS_EOF) {
        return (int)rc;
    }
    e->inbound_len += rc;

    return read_inbound_frame(e);
}

static bool discard_inbound_frame(struct applenw_engine_s *e) {
    UM_LOG(TRACE, "discarding %d bytes out of %zd", e->inbound_frame.len, e->inbound_len);
    memmove(e->inbound_buf, e->inbound_buf + e->inbound_frame.len, e->inbound_len - e->inbound_frame.len);
    e->inbound_len -= e->inbound_frame.len;
    e->inbound_frame.len = 0;
    e->inbound_frame.recv = 0;

    if (e->inbound_len < 5) return false;
    e->inbound_frame.len = 5 + (((uint8_t)e->inbound_buf[3] << 8) | (uint8_t)e->inbound_buf[4]);
    e->inbound_frame.recv = MIN(e->inbound_frame.len, e->inbound_len);
    return e->inbound_frame.len == e->inbound_frame.recv;
}

static void engine_set_io_fd(tlsuv_engine_t self, tlsuv_sock_t fd) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
    e->io_is_socket = true;
    int sock = dup(fd);
    e->sock = sock;
    engine_set_io(self, e, engine_socket_read, engine_socket_write);
}

static void engine_set_protocols(tlsuv_engine_t self, const char **protocols, int len) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
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
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
    return e->hs_state;
}

static void write_dispatch_data(struct applenw_engine_s *e, dispatch_data_t data) {
    if (data == NULL) return;

    dispatch_data_apply(data, ^bool(dispatch_data_t reg, size_t off, const void *d, size_t l) {
        e->write_f(e->io, d, l);
        return true;
    });
    dispatch_release((dispatch_object_t)data);
}
// Threading: tls_channel and tls_sock are created by the accept block on e->queue, so every
// other use of them also runs on e->queue. The queue is serial and the accept block is
// enqueued first, so anything queued after it sees the channel in its final state
// (or NULL if accept failed).

static void wake(struct applenw_engine_s *e) {
    if (e->async_cb) {
        e->async_cb(e->async_ctx);
    }
}

// takes ownership of `err`
static void set_error(struct applenw_engine_s *e, CFErrorRef err) {
    pthread_mutex_lock(&e->decode_mutex);
    if (e->error) CFRelease(e->error);
    e->error = err;
    pthread_mutex_unlock(&e->decode_mutex);
}

// e->queue only; takes ownership of `err`
static void handshake_failed(struct applenw_engine_s *e, CFErrorRef err) {
    set_error(e, err);
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

// hand a copy of the current inbound record to NW (via tls_sock)
static void forward_frame(struct applenw_engine_s *e) {
    dispatch_data_t frame = dispatch_data_create(e->inbound_frame.frame, e->inbound_frame.len,
                                                 e->queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    dispatch_async(e->queue, ^{
        if (e->tls_channel) {
            dispatch_io_write(e->tls_channel, 0, frame, e->queue, ^(bool done, dispatch_data_t d, int err){
                if (err != 0) {
                    UM_LOG(WARN, "Write error: %s", strerror(err));
                }
            });
        }
        dispatch_release((dispatch_object_t)frame);
    });
}

static void close_tls_channel(struct applenw_engine_s *e) {
    dispatch_async(e->queue, ^{
        if (e->tls_channel) {
            dispatch_io_close(e->tls_channel, 0);
        }
    });
}

// stop all IO and callbacks into the stream; waits for queued work to drain.
// idempotent, loop thread only.
static void stop_io(struct applenw_engine_s *e) {
    dispatch_sync(e->queue, ^{
        e->async_cb = NULL;
        e->async_ctx = NULL;
        if (e->tls_channel) {
            dispatch_io_close(e->tls_channel, DISPATCH_IO_STOP);
            dispatch_release((dispatch_object_t)e->tls_channel);
            e->tls_channel = NULL;
        }
        if (e->sock != -1) {
            close(e->sock);
            e->sock = -1;
        }
    });
}

static void engine_dealloc(struct applenw_engine_s *e) {
    if (e->error) CFRelease(e->error);
    pthread_mutex_destroy(&e->decode_mutex);
    pthread_cond_destroy(&e->decode_cond);
    tlsuv__free(e);
}

static void tls_to_socket(struct applenw_engine_s *e, int socket) {
    assert(e->tls_channel == NULL);
    UM_LOG(DEBG, "tls_to_socket: staring dispatch tls_sock[%d]", socket);
    e->tls_channel = dispatch_io_create(DISPATCH_IO_STREAM, socket, e->queue, ^(int er){
        if (er != 0) {
            UM_LOG(ERR, "tls_to_socket: error %d", er);
        }
        close(socket);
    });

    dispatch_io_set_low_water(e->tls_channel, 6);
    // dispatch_io_set_high_water(e->tls_channel, 1024);
    dispatch_io_read(e->tls_channel, 0, SIZE_MAX, e->queue,
                     ^(bool done, dispatch_data_t data, int error) {
                         UM_LOG(TRACE, "tls_to_socket: done[%d] error[%d] d[%zd]",
                             done, error, data ? dispatch_data_get_size(data) : -1);
                         if (error == ECANCELED) {
                             // stopped by stop_io(); the engine may already be gone
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
                             size_t avail = dispatch_data_get_size(data);
                             UM_LOG(DEBG, "tls_to_socket: %zu bytes", avail);
                             dispatch_data_apply(data, ^(dispatch_data_t reg, size_t off, const void* b, size_t len){
                                 log_frame(">>> ", b, len);
                                 ssize_t w_rc = e->write_f(e->io, b, len);
                                 return (bool)(len == w_rc);
                             });
                         }
                         if (done && e->io_is_socket) {
                             shutdown(e->sock, SHUT_WR);
                         }
                     });
}

static tls_handshake_state engine_handshake(tlsuv_engine_t self) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
    assert(e->read_f != NULL);
    assert(e->write_f != NULL);

    UM_LOG(INFO, "engine_handshake: %d", e->hs_state);

    if (e->hs_state == TLS_HS_ERROR || e->hs_state == TLS_HS_COMPLETE) {
        return e->hs_state;
    }

    if (e->connection) {
        int rc;
        do {
            rc = read_inbound_frame(e);
            if (rc == TLS_OK) {
                UM_LOG(INFO, "engine_handshake: received frame: %d len: %d", e->inbound_frame.frame[0], e->inbound_frame.len);
                forward_frame(e);

                bool more = discard_inbound_frame(e);
                UM_LOG(INFO, "engine_handshake: more: %d, %zd", more, e->inbound_len);
                if (!more) {
                    break;
                }
            }
            if (rc == TLS_EOF) {
                // shutdown(e->tls_sock, SHUT_WR);
            }
            if (rc == TLS_ERR) {
                close_tls_channel(e);
            }
        } while (rc == TLS_OK);

        if (e->hs_state != TLS_HS_CONTINUE) {
            return e->hs_state;
        }

        if (!e->io_is_socket) {
            struct pollfd pfd = {
                .fd = e->tls_sock,
                .events = POLLIN,
            };

            if (poll(&pfd, 1, 10) == 1) {
                char hs_buf[32 * 1024];
                ssize_t hs_bytes = read(e->tls_sock, hs_buf, sizeof(hs_buf));
                UM_LOG(INFO, "tls_io read: %zd", hs_bytes);
                e->write_f(e->io, hs_buf, hs_bytes);
            }
        }

        return e->hs_state;
    }

    if (e->connection == NULL) {
        int lsoc = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_addr = htonl(INADDR_LOOPBACK),
        };
        if (bind(lsoc, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
            listen(lsoc, 1) < 0) {
            UM_LOG(WARN, "failed to bind or listen: %s", strerror(errno));
            close(lsoc);
            e->hs_state = TLS_HS_ERROR;
            return e->hs_state;
        }

        socklen_t len = sizeof(addr);
        getsockname(lsoc, (struct sockaddr *) &addr, &len);

        char port[10];
        snprintf(port, sizeof(port), "%d", ntohs(addr.sin_port));
        nw_endpoint_t ep = nw_endpoint_create_host("127.0.0.1", port);
        nw_connection_t conn = nw_connection_create(ep, e->protocol_parameters);
        nw_release(ep);

        nw_connection_set_state_changed_handler(conn, ^(nw_connection_state_t state, nw_error_t error) {
            if (error) {
                UM_LOG(WARN, "connection error: %d", nw_error_get_error_code(error));
                // wakes the stream so process_connect/process_inbound sees the failure
                handshake_failed(e, nw_error_copy_cf_error(error));
            }
            switch (state) {
            case nw_connection_state_preparing:
                e->hs_state = TLS_HS_CONTINUE;
                break;
            case nw_connection_state_ready:
                e->hs_state = TLS_HS_COMPLETE;
                UM_LOG(DEBG, "Handshake completed successfully!");
                if (e->async_cb) {
                    e->async_cb(e->async_ctx);
                }
                break;
            case nw_connection_state_failed:
                UM_LOG(INFO, "Connection failed");
                break;
            case nw_connection_state_cancelled:
                engine_dealloc(e);
                UM_LOG(DEBG, "Connection cancelled");
                break;
            default:
                UM_LOG(WARN, "unhandled state: %d", state);
                break;
            }
        });

        nw_connection_set_queue(conn, e->queue);
        nw_connection_start(conn);
        e->connection = conn;

        dispatch_async(e->queue, ^{
            struct pollfd pfd = {
                .fd = lsoc,
                .events = POLLIN,
            };

            if (poll(&pfd, 1, 1000) < 1) {
                UM_LOG(WARN, "nw_connection did not connect in time");
                close(lsoc);
                handshake_failed(e, posix_error(ETIMEDOUT));
                return;
            }
            int s = accept(lsoc, NULL, 0);
            int accept_err = errno;
            close(lsoc);
            if (s < 0) {
                UM_LOG(WARN, "accept failed: %s", strerror(accept_err));
                handshake_failed(e, posix_error(accept_err));
                return;
            }
            e->tls_sock = s;
            int true_val = 1;
            setsockopt(e->tls_sock, SOL_SOCKET, SO_NOSIGPIPE, &true_val, sizeof(true_val));
            setsockopt(e->tls_sock, IPPROTO_TCP, TCP_NODELAY, &true_val, sizeof(true_val));

            if (e->io_is_socket) {
                tls_to_socket(e, e->tls_sock);
            } else {
                // char hs_buf[16 * 1024];
                // ssize_t hs_bytes = recv(e->tls_sock, hs_buf, sizeof(hs_buf), 0);
                // if (hs_bytes < 0) {
                //     e->hs_state = TLS_HS_ERROR;
                //     return e->hs_state;
                // }
                //
                // e->write_f(e->io, hs_buf, hs_bytes);
            }
        });
    }

    return e->hs_state;
}

static const char* engine_get_alpn(tlsuv_engine_t self) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
    if (e->connection == NULL) {
        return NULL;
    }

    nw_protocol_definition_t definition = nw_protocol_copy_tls_definition();
    nw_protocol_metadata_t metadata = nw_connection_copy_protocol_metadata(e->connection, definition);
    sec_protocol_metadata_t sec_metadata = nw_tls_copy_sec_protocol_metadata(metadata);
    const char *negotiated = sec_protocol_metadata_get_negotiated_protocol(sec_metadata);
    sec_release(sec_metadata);
    nw_release(metadata);
    nw_release(definition);
    return negotiated;
}

static int engine_close(tlsuv_engine_t self) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
    stop_io(e);
    return TLS_OK;
}

static int engine_write(tlsuv_engine_t self, const char *data, size_t data_len) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
    if (e->connection == NULL ||
        e->hs_state != TLS_HS_COMPLETE) {
        return TLS_ERR;
    }
    if (data_len > INT32_MAX) {
        data_len = INT32_MAX;
    }
    UM_LOG(DEBG, "engine[%p] write: %zd\n", e, data_len);
    dispatch_data_t dd = dispatch_data_create(data, data_len, e->queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    nw_connection_send(e->connection, dd, NW_CONNECTION_DEFAULT_STREAM_CONTEXT, false, ^(nw_error_t error) {
        if (error) {
            nw_connection_cancel(e->connection);
        }
    });
    dispatch_release((dispatch_object_t)dd);

    if (e->io_is_socket) {
        return (int)data_len;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block dispatch_data_t tls_data = NULL;
    dispatch_read(e->tls_sock, SIZE_MAX, e->queue, ^(dispatch_data_t d, int err) {
        tls_data = d;
        dispatch_retain((dispatch_object_t)tls_data);
        dispatch_semaphore_signal(sem);
    });
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    write_dispatch_data(e, tls_data);

    return (int)data_len;
}

static bool process_decoded(struct applenw_engine_s *e, dispatch_data_t dd, nw_content_context_t ctx, bool done, nw_error_t er){
    UM_LOG(TRACE, "dd[%p] done[%d] er[%d]", dd, done, er ? nw_error_get_error_code(er) : 0);
    if (er != NULL) {
        int code = nw_error_get_error_code(er);
        if (code == ECANCELED)
            return false;

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
    if (dd) {
        dispatch_data_apply(dd, ^bool(dispatch_data_t r, size_t off, const void* bytes, size_t len) {
            UM_LOG(TRACE, "engine[%p] decoded %zd bytes", e, len);
            memcpy(e->decoded + e->decoded_len, bytes, len);
            e->decoded_len += len;
            return true;
        });
    }
    if (done) {
        e->conn_eof = true;
    }
    e->reading_conn = false;

    if (er == NULL && !done && e->decoded_len < sizeof(e->decoded)) {
        e->reading_conn = true;
        nw_connection_receive(
            e->connection, 0, sizeof(e->decoded) - e->decoded_len,
            ^(dispatch_data_t d, nw_content_context_t c, bool done1, nw_error_t er1){
                process_decoded(e, d, c, done1, er1);
            });
    }
    if (e->decoded_len > 0) {
        pthread_cond_signal(&e->decode_cond);
        if (e->async_cb) {
            e->async_cb(e->async_ctx);
        }
    }
    pthread_mutex_unlock(&e->decode_mutex);
    return done;
}

static int engine_read(tlsuv_engine_t self, char *out, size_t *out_bytes, size_t maxout) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
    int rc;
    int frames = 0;
    // forward every complete record we have: a record that decodes to no plaintext
    // (e.g. NewSessionTicket) triggers no async wakeup, so anything left behind
    // it would sit in inbound_buf until the socket becomes readable again
    while ((rc = read_inbound_frame(e)) == TLS_OK) {
        frames++;
        forward_frame(e);
        discard_inbound_frame(e);
    }
    if (rc == TLS_EOF && !e->eof_forwarded) {
        // peer closed: let NW see EOF once all forwarded records are written
        e->eof_forwarded = true;
        close_tls_channel(e);
    }

    *out_bytes = 0;
    pthread_mutex_lock(&e->decode_mutex);
    if (e->decoded_len > 0) {
        size_t to_copy = MIN(e->decoded_len, maxout);
        memcpy(out, e->decoded, to_copy);
        memmove(e->decoded, e->decoded + to_copy, e->decoded_len - to_copy);
        e->decoded_len -= to_copy;

        *out_bytes = to_copy;
        rc = e->decoded_len > 0 ? TLS_MORE_AVAILABLE : TLS_OK;
    }

    // re-arm whenever no receive is pending: process_decoded stops once `decoded` is full,
    // and the remaining plaintext may already be inside NW with no new ciphertext coming
    if (e->error == NULL && !e->reading_conn && !e->conn_eof &&
        e->decoded_len < sizeof(e->decoded)) {
        UM_LOG(DEBG, "engine[%p] starting decode receive", e);
        e->reading_conn = true;
        nw_connection_receive(e->connection, 0, sizeof(e->decoded) - e->decoded_len,
                              ^(dispatch_data_t dd, nw_content_context_t ctx, bool done, nw_error_t er){
                                  process_decoded(e, dd, ctx, done, er);
                              });
    }

    if (e->decoded_len == 0 && *out_bytes == 0) {
        UM_LOG(DEBG, "engine[%p] waiting for decode", e);
        struct timespec wait = {
            .tv_nsec = 10 * NSEC_PER_USEC,
        };
        pthread_cond_timedwait_relative_np(&e->decode_cond, &e->decode_mutex, &wait);

        if (e->decoded_len > 0) {
            size_t to_copy = MIN(e->decoded_len, maxout);
            memcpy(out, e->decoded, to_copy);
            memmove(e->decoded, e->decoded + to_copy, e->decoded_len - to_copy);
            e->decoded_len -= to_copy;

            *out_bytes = to_copy;
            rc = e->decoded_len > 0 ? TLS_MORE_AVAILABLE : TLS_OK;
        }
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
    static char err_buf[256];
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
    if (e->error == NULL) return NULL;

    CFStringRef msg = CFErrorCopyDescription(e->error);
    CFStringGetCString(msg, err_buf, sizeof(err_buf), kCFStringEncodingUTF8);
    CFRelease(msg);
    return err_buf;
}

static int engine_reset(tlsuv_engine_t self) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
    e->hs_state = TLS_HS_BEFORE;
    return 0;
}

static void engine_free(tlsuv_engine_t self) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
    if (e == NULL) return;

    stop_io(e);

    if (e->ca) CFRelease(e->ca);
    if (e->identity) sec_release(e->identity);
    nw_release(e->protocol_parameters);

    // once cancelled, the state handler frees `e` on the queue: don't touch it after that
    dispatch_queue_t queue = e->queue;
    nw_connection_t conn = e->connection;
    if (conn != NULL) {
        nw_connection_cancel(conn);
        nw_release(conn);
    } else {
        engine_dealloc(e);
    }
    nw_release(queue);
}

static void engine_setup_async(tlsuv_engine_t self, int (*cb)(void *async_ctx), void *async_ctx) {
    struct applenw_engine_s *e = (struct applenw_engine_s *) self;
    e->async_cb = cb;
    e->async_ctx = async_ctx;
}

static struct tlsuv_engine_s applenw_engine_api = {
        .set_io = engine_set_io,
        .set_io_fd = engine_set_io_fd,
        .set_protocols = engine_set_protocols,
        .handshake_state = engine_handshake_state,
        .handshake = engine_handshake,
        .get_alpn = engine_get_alpn,
        .close = engine_close,
        .write = engine_write,
        .read = engine_read,
        .strerror = engine_strerror,
        .reset = engine_reset,
        .free = engine_free,
        .setup_async = engine_setup_async,
};

// ctx->ssl_chain is [SecIdentityRef, intermediates...] (built by tls_set_own_cert).
// sec_identity_create_with_certificates() takes the chain to send, leaf first.
static sec_identity_t new_client_identity(struct sectransport_ctx *ctx) {
    if (ctx->ssl_chain == NULL || CFArrayGetCount(ctx->ssl_chain) == 0) {
        return NULL;
    }

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

tlsuv_engine_t applenw_new_engine(tls_context *ctx, const char *host) {
    struct applenw_engine_s *e = tlsuv__calloc(1, sizeof(*e));
    e->api = applenw_engine_api;
    struct sectransport_ctx* sec_ctx = (struct sectransport_ctx *) ctx;
    e->hs_state = TLS_HS_BEFORE;
    e->ca = sec_ctx->ca_bundle ? CFRetain(sec_ctx->ca_bundle) : NULL;
    e->identity = new_client_identity(sec_ctx);
    e->sock = -1;
    e->tls_sock = -1;
    e->cert_verify_f = sec_ctx->cert_verify_f;
    e->verify_ctx = sec_ctx->verify_ctx;

    dispatch_queue_t global = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    e->queue = dispatch_queue_create_with_target(
        "tlsuv.queue", DISPATCH_QUEUE_SERIAL, global);

    e->protocol_parameters = nw_parameters_create_secure_tcp(
        ^(nw_protocol_options_t opts){
            sec_protocol_options_t sec_options = nw_tls_copy_sec_protocol_options(opts);
            sec_protocol_options_set_min_tls_protocol_version(sec_options, tls_protocol_version_TLSv12);
            sec_protocol_options_set_tls_server_name(sec_options, host);
            if (e->identity) {
                sec_protocol_options_set_local_identity(sec_options, e->identity);
            }
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
                        complete(rc == 0);
                    },
                    e->queue);
            } else if (e->ca) {
                sec_protocol_options_set_verify_block(sec_options,
                    ^(sec_protocol_metadata_t metadata, sec_trust_t trust_ref, sec_protocol_verify_complete_t complete){
                        SecTrustRef ref = sec_trust_copy_ref(trust_ref);
                        SecTrustSetAnchorCertificates(ref, e->ca);
                        SecTrustSetAnchorCertificatesOnly(ref, true);
                        CFErrorRef err = NULL;
                        if (SecTrustEvaluateWithError(ref, &err)) {
                            complete(true);
                        } else {
                            char msg[256] = "unknown error";
                            if (err) {
                                CFStringRef desc = CFErrorCopyDescription(err);
                                CFStringGetCString(desc, msg, sizeof(msg), kCFStringEncodingUTF8);
                                CFRelease(desc);
                                CFRelease(err);
                            }
                            UM_LOG(WARN, "server certificate verification failed: %s", msg);
                            complete(false);
                        }
                        CFRelease(ref);
                    },
                    e->queue);
            }
            nw_release(sec_options);
        },
        ^(nw_protocol_options_t opts) {
            nw_tcp_options_set_no_delay(opts, true);
        }
    );

    pthread_mutex_init(&e->decode_mutex, NULL);
    pthread_cond_init(&e->decode_cond, NULL);

    return (tlsuv_engine_t) e;
}


