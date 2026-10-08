// Copyright (c) 2026. NetFoundry Inc.
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

#include <stdbool.h>
#include <string.h>
#include <uv.h>

#include "alloc.h"
#include "tlsuv/listener.h"
#include "um_debug.h"
#include "util.h"

#if _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define closesock closesocket
#else
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define closesock close
#endif

#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif

#define LST_LOG(lvl, fmt, ...) UM_LOG(lvl, "listener: " fmt, ##__VA_ARGS__)

#define ACCEPT_BATCH 32

static int last_socket_error(void) {
    return uv_translate_sys_error(
#if _WIN32
        WSAGetLastError()
#else
        errno
#endif
    );
}

// failed accept(): is it transient (the failed connection is gone, carry on), or is there nothing to
// accept (UV_EAGAIN), or can the listener not continue by itself (anything else)?
static bool accept_error_transient(int err) {
    switch (err) {
        case UV_EINTR:
        case UV_ECONNABORTED:
        case UV_ECONNRESET:
        case UV_EPROTO:
        // accept(2) lists these as pending network errors on the new connection: treat like EAGAIN and retry
        case UV_ENETDOWN:
        case UV_ENETUNREACH:
        case UV_EHOSTUNREACH:
        case UV_ENOTSUP:
        case UV_EPERM:
            return true;
        default:
            return false;
    }
}

static void on_listen_io(uv_poll_t *p, int status, int events);

#if !_WIN32
// The spare is a duplicate of the listening socket: no new kernel object, no filesystem or address
// family dependency (unlike libuv, which opens /dev/null), and closing it leaves the socket open.
static int open_spare_fd(uv_os_sock_t sock) {
    return fcntl(sock, F_DUPFD_CLOEXEC, 0);
}
#endif

// Out of descriptors (EMFILE/ENFILE): accept() cannot take the connection, which stays queued, so a
// level-triggered poll would spin. Same trick as libuv: release the spare descriptor, accept and close
// everything that is waiting, take the spare back. The shed clients see a closed connection.
// Returns false if there was no spare descriptor or the backlog could not be emptied.
static bool shed_backlog(tlsuv_listener_t *l) {
#if _WIN32
    (void) l;
    return false;
#else
    if (l->spare_fd < 0) {
        return false;
    }
    close(l->spare_fd);
    l->spare_fd = -1;

    int err;
    for (;;) {
        int fd = accept(l->sock, NULL, NULL);
        if (fd >= 0) {
            close(fd);
            continue;
        }
        err = errno;
        if (err != EINTR && err != ECONNABORTED) {
            break;
        }
    }
    l->spare_fd = open_spare_fd(l->sock);
    return err == EAGAIN || err == EWOULDBLOCK;
#endif
}

static void free_alpn(tlsuv_listener_t *l) {
    for (int i = 0; i < l->alpn_count; i++) {
        tlsuv__free(l->alpn[i]);
    }
    tlsuv__free(l->alpn);
    l->alpn = NULL;
    l->alpn_count = 0;
}

int tlsuv_listener_init(uv_loop_t *loop, tlsuv_listener_t *l, tls_context *tls) {
    // a server context needs its own certificate, so there is no usable default
    if (tls == NULL) {
        return UV_EINVAL;
    }
    // TLS backends without a server engine (e.g. mbedtls) cannot serve
    if (tls->new_server_engine == NULL) {
        return UV_ENOTSUP;
    }
    void *data = l->data; // callers may set it before init, as libuv allows
    *l = (tlsuv_listener_t){0};
    l->data = data;
    l->loop = loop;
    l->tls = tls;
    l->sock = INVALID_SOCKET;
    l->spare_fd = -1;
    return 0;
}

int tlsuv_listener_set_protocols(tlsuv_listener_t *l, int count, const char *protocols[]) {
    if (l->closing) {
        return UV_EINVAL;
    }
    char **copy = NULL;
    if (count > 0) {
        copy = tlsuv__calloc(count, sizeof(char *));
        if (copy == NULL) {
            return UV_ENOMEM;
        }
        for (int i = 0; i < count; i++) {
            copy[i] = tlsuv__strdup(protocols[i]);
            if (copy[i] == NULL) {
                for (int j = 0; j < i; j++) {
                    tlsuv__free(copy[j]);
                }
                tlsuv__free(copy);
                return UV_ENOMEM;
            }
        }
    }
    free_alpn(l);
    l->alpn = copy;
    l->alpn_count = count > 0 ? count : 0;
    return 0;
}

int tlsuv_listener_bind(tlsuv_listener_t *l, const struct sockaddr *addr, unsigned flags) {
    if (l->closing) {
        return UV_EINVAL;
    }
    if (l->bound) {
        return UV_EALREADY;
    }

    uv_os_sock_t s = socket(addr->sa_family, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        return last_socket_error();
    }
    tlsuv_socket_configure(s);
    tlsuv_socket_set_blocking(s, false);

#if !_WIN32
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *) &on, sizeof(on));
#endif
    if (addr->sa_family == AF_INET6) {
        int v6only = (flags & TLSUV_LISTENER_IPV6ONLY) ? 1 : 0;
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const void *) &v6only, sizeof(v6only));
    }

    socklen_t len = addr->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (bind(s, addr, len) != 0) {
        int rc = last_socket_error(); // before closesock() can change it
        closesock(s);
        return rc;
    }
    l->sock = s;
    l->bound = 1;
    return 0;
}

int tlsuv_listener_start_listen(tlsuv_listener_t *l, int backlog, tlsuv_accept_cb accept_cb,
                                tlsuv_handshake_cb handshake_cb) {
    if (l->closing || !l->bound || accept_cb == NULL || handshake_cb == NULL) {
        return UV_EINVAL;
    }
    if (l->started) {
        return UV_EALREADY;
    }

    if (!l->listening) {
        if (listen(l->sock, backlog > 0 ? backlog : SOMAXCONN) != 0) {
            return last_socket_error();
        }
        int rc = uv_poll_init_socket(l->loop, &l->watcher, l->sock);
        if (rc != 0) {
            return rc;
        }
#if !_WIN32
        l->spare_fd = open_spare_fd(l->sock);
#endif
        l->listening = 1;
    }

    l->accept_cb = accept_cb;
    l->handshake_cb = handshake_cb;
    l->started = 1;
    int rc = uv_poll_start(&l->watcher, UV_READABLE, on_listen_io);
    if (rc != 0) {
        l->started = 0;
    }
    return rc;
}

int tlsuv_listener_stop_listen(tlsuv_listener_t *l) {
    if (l->closing) {
        return UV_EINVAL;
    }
    if (!l->started) {
        return 0;
    }
    l->started = 0;
    return uv_poll_stop(&l->watcher);
}

int tlsuv_listener_getsockname(const tlsuv_listener_t *l, struct sockaddr *name, int *namelen) {
    if (l->closing || !l->bound) {
        return UV_EINVAL;
    }
    socklen_t len = (socklen_t) *namelen;
    if (getsockname(l->sock, name, &len) != 0) {
        return last_socket_error();
    }
    *namelen = (int) len;
    return 0;
}

// Tell the app that accepting failed. If it hands back a stream (e.g. to find its context through the
// stream's `data`), the stream is initialised and gets its handshake_cb with the same error, like any
// other stream that did not make it.
static void report_error(tlsuv_listener_t *l, int err) {
    tlsuv_stream_t *s = l->accept_cb(l, NULL, err);
    if (s != NULL) {
        tlsuv_stream_init(l->loop, s, l->tls);
        l->handshake_cb(s, err);
    }
}

// The listener cannot continue. Stop, so that a persistently failing accept() does not spin the
// loop, and tell the app; it may resume with tlsuv_listener_start_listen().
static void listener_fail(tlsuv_listener_t *l, int err) {
    LST_LOG(WARN, "accept failed, listener stopped: %s", uv_strerror(err));
    l->started = 0;
    uv_poll_stop(&l->watcher);
    report_error(l, err);
}

static void accept_one(tlsuv_listener_t *l, uv_os_sock_t fd, const struct sockaddr *peer) {
    tlsuv_stream_t *s = l->accept_cb(l, peer, 0);
    if (s == NULL) {
        LST_LOG(DEBG, "connection refused by accept_cb");
        closesock(fd);
        return;
    }

    tlsuv_stream_init(l->loop, s, l->tls);
    int rc = tlsuv__stream_accept(s, fd, l->alpn_count, (const char **) l->alpn, l->handshake_cb);
    if (rc != 0) {
        LST_LOG(WARN, "failed to start handshake: %s", uv_strerror(rc));
        closesock(fd);
        // the app handed us a stream, so it gets exactly one handshake_cb for it
        l->handshake_cb(s, rc);
    }
}

static void on_listen_io(uv_poll_t *p, int status, int events) {
    tlsuv_listener_t *l = container_of(p, tlsuv_listener_t, watcher);
    if (status < 0) {
        listener_fail(l, status);
        return;
    }

    // accept_cb may stop the listener, so re-check `started` every round
    for (int i = 0; i < ACCEPT_BATCH && l->started; i++) {
        struct sockaddr_storage ss;
        socklen_t len = sizeof(ss);
        uv_os_sock_t fd = accept(l->sock, (struct sockaddr *) &ss, &len);
        if (fd == INVALID_SOCKET) {
            int err = last_socket_error();
            if (err == UV_EAGAIN) {
                return;
            }
            if (accept_error_transient(err)) {
                continue;
            }
            if ((err == UV_EMFILE || err == UV_ENFILE) && shed_backlog(l)) {
                LST_LOG(WARN, "out of descriptors, shed pending connections");
                // the backlog is empty. Don't accept again in this wake: on Linux accept() fails with
                // EMFILE before it even looks at the queue, so we would shed and report in a loop
                report_error(l, err);
                return;
            }
            listener_fail(l, err);
            return;
        }
        tlsuv_socket_configure(fd);
        tlsuv_socket_set_blocking(fd, false);
        accept_one(l, fd, (struct sockaddr *) &ss);
    }
}

static void on_watcher_closed(uv_handle_t *h) {
    tlsuv_listener_t *l = container_of((uv_poll_t *) h, tlsuv_listener_t, watcher);
    if (l->sock != INVALID_SOCKET) {
        closesock(l->sock);
        l->sock = INVALID_SOCKET;
    }
#if !_WIN32
    if (l->spare_fd >= 0) {
        close(l->spare_fd);
        l->spare_fd = -1;
    }
#endif
    free_alpn(l);
    if (l->close_cb) {
        l->close_cb((uv_handle_t *) l);
    }
}

int tlsuv_listener_close(tlsuv_listener_t *l, uv_close_cb close_cb) {
    if (l->closing) {
        return UV_EINVAL;
    }
    l->closing = 1;
    l->started = 0;
    l->close_cb = close_cb;

    // if the poll handle was never set up (not listening yet), borrow its memory for an idle handle
    // so that close_cb is still deferred to the loop, as tlsuv_stream_close() does
    if (!l->listening) {
        uv_idle_init(l->loop, (uv_idle_t *) &l->watcher);
    }
    uv_close((uv_handle_t *) &l->watcher, on_watcher_closed);
    return 0;
}

size_t tlsuv_listener_size(void) { return sizeof(tlsuv_listener_t); }

tlsuv_listener_t *tlsuv_listener_new(void) { return tlsuv__calloc(1, sizeof(tlsuv_listener_t)); }

void tlsuv_listener_delete(tlsuv_listener_t *l) { tlsuv__free(l); }

void tlsuv_listener_set_data(tlsuv_listener_t *l, void *data) { l->data = data; }

void *tlsuv_listener_get_data(const tlsuv_listener_t *l) { return l->data; }
