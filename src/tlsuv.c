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

#include "tlsuv/tlsuv.h"
#include "um_debug.h"
#include "tlsuv/queue.h"
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <assert.h>

#if _WIN32
#include "win32_compat.h"
#else
#include <sys/ioctl.h>
#endif

#define to_str1(s) #s
#define to_str(s) to_str1(s)

#ifdef TLSUV_VERSION
#define TLSUV_VERS to_str(TLSUV_VERSION)
#else
#define TLSUV_VERS "<unknown>"
#endif

static uv_os_sock_t new_socket(const struct addrinfo *addr);

static void tcp_connect_cb(uv_connect_t* req, int status);
static void on_clt_io(uv_poll_t *, int, int);
static ssize_t try_write(tlsuv_stream_t *, uv_buf_t *);

static tls_context *DEFAULT_TLS = NULL;

static void free_default_tls(void) {
    if (DEFAULT_TLS) {
        DEFAULT_TLS->free_ctx(DEFAULT_TLS);
        DEFAULT_TLS = NULL;
    }
}

struct tlsuv_write_s {
    uv_write_t *wr;
    uv_buf_t buf;
    TAILQ_ENTRY(tlsuv_write_s) _next;
};

tls_context *get_default_tls(void) {
    if (DEFAULT_TLS == NULL) {
        DEFAULT_TLS = default_tls_context(NULL, 0);
        atexit(free_default_tls);
    }
    return DEFAULT_TLS;
}

const char* tlsuv_version(void) {
    return TLSUV_VERS;
}

int tlsuv_stream_init(uv_loop_t *l, tlsuv_stream_t *clt, tls_context *tls) {
    *clt = (tlsuv_stream_t){0};

    clt->loop = l;

    clt->tls = tls != NULL ? tls : get_default_tls();
    clt->read_cb = NULL;
    clt->alloc_cb = NULL;
    clt->queue_len = 0;
    TAILQ_INIT(&clt->queue);

    clt->watcher.data = clt;

    return 0;
}

static int start_io(tlsuv_stream_t *clt) {
    int events = 0;
    if (!TAILQ_EMPTY(&clt->queue)) {
        events |= UV_WRITABLE;
    }

    if (clt->read_cb) {
        events |= UV_READABLE;
    }

    if (events != 0) {
        return uv_poll_start(&clt->watcher, events, on_clt_io);
    } else {
        return uv_poll_stop(&clt->watcher);
    }
}

static void on_internal_close(uv_handle_t *h) {
    tlsuv_stream_t *clt = h->data;
    if (clt->conn_req) {
        clt->conn_req->cb(clt->conn_req, UV_ECANCELED);
        clt->conn_req = NULL;
    }
    while(!TAILQ_EMPTY(&clt->queue)) {
        tlsuv_write_t *req = TAILQ_FIRST(&clt->queue);
        TAILQ_REMOVE(&clt->queue, req, _next);
        req->wr->cb(req->wr, UV_ECANCELED);
        free(req);
    }
    if (clt->close_cb) {
        clt->close_cb((uv_handle_t *) clt);
    }
}

int tlsuv_stream_close(tlsuv_stream_t *clt, uv_close_cb close_cb) {
    if (clt->resolve_req) {
        clt->resolve_req->data = NULL;
        uv_cancel((uv_req_t *) clt->resolve_req);
    }

    clt->close_cb = close_cb;
    if (clt->tls_engine) {
        clt->tls_engine->close(clt->tls_engine);
    }

    if (clt->watcher.type == UV_POLL) {
        uv_close((uv_handle_t *) &clt->watcher, on_internal_close);
    } else {
        on_internal_close((uv_handle_t *) &clt->watcher);
    }

    return 0;
}

int tlsuv_stream_keepalive(tlsuv_stream_t *clt, int keepalive, unsigned int delay) {
    uv_os_fd_t s;
    if (uv_fileno((const uv_handle_t *) &clt->watcher, &s) == 0) {
        int count = 10;
        int intvl = 1;
        setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
#if defined(TCP_KEEPALIVE)
        setsockopt(s, IPPROTO_TCP, TCP_KEEPALIVE, &delay, sizeof(delay));
#endif
        setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
        setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
    }
    return 0;
}

int tlsuv_stream_nodelay(tlsuv_stream_t *clt, int nodelay) {
    uv_os_fd_t s;
    if (uv_fileno((const uv_handle_t *) &clt->watcher, &s) == 0) {
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    }
    return 0;
}

int tlsuv_stream_set_protocols(tlsuv_stream_t *clt, int count, const char *protocols[]) {
    clt->alpn_count = count;
    clt->alpn_protocols = protocols;
    return 0;
}

const char* tlsuv_stream_get_protocol(tlsuv_stream_t *clt) {
    if (clt->tls_engine) {
        return clt->tls_engine->get_alpn(clt->tls_engine);
    }
    return NULL;
}

int tlsuv_stream_set_hostname(tlsuv_stream_t *clt, const char *host) {
    free (clt->host);
    clt->host = strdup(host);
    return 0;
}

static void process_connect(tlsuv_stream_t *clt, int status) {
    assert(clt->conn_req);
    uv_connect_t *req = clt->conn_req;
    int err = 0;
    socklen_t l = sizeof(err);
    getsockopt(clt->sock, SOL_SOCKET, SO_ERROR, &err, &l);

    if (status == 0 && err != 0) {
        status = -(err);
    }

    if (status != 0) {
        UM_LOG(ERR, "failed connect: %d/%s", status, uv_strerror(status));
        clt->conn_req = NULL;
        req->cb(req, status);
        uv_poll_stop(&clt->watcher);
        return;
    }

    if (clt->tls_engine == NULL) {
        clt->tls_engine = clt->tls->new_engine(clt->tls, clt->host);
        if (clt->alpn_protocols) {
            clt->tls_engine->set_protocols(clt->tls_engine, clt->alpn_protocols, clt->alpn_count);
        }
        clt->tls_engine->set_io_fd(clt->tls_engine, clt->sock);
    }

    int rc;
    rc = clt->tls_engine->handshake(clt->tls_engine);

    if (rc == TLS_HS_ERROR) {
        const char *error = clt->tls_engine->strerror(clt->tls_engine);
        UM_LOG(ERR, "TLS handshake failed: %s", error);
        clt->conn_req = NULL;
        req->cb(req, UV_ECONNABORTED);
        uv_poll_stop(&clt->watcher);
        return;
    }

    if (rc == TLS_HS_COMPLETE) {
        UM_LOG(DEBG, "handshake completed");
        clt->conn_req = NULL;
        req->cb(req, 0);
        start_io(clt);
    } else {
        // wait for incoming handshake messages
        uv_poll_start(&clt->watcher, UV_READABLE, on_clt_io);
    }
}

static void process_outbound(tlsuv_stream_t *clt) {
    tlsuv_write_t *req;
    ssize_t ret;

    for (;;) {
        if (TAILQ_EMPTY(&clt->queue)) {
            return;
        }

        req = TAILQ_FIRST(&clt->queue);
        ret = tlsuv_stream_try_write(clt, &req->buf);
        if (ret > 0) {
            req->buf.base += ret;
            req->buf.len -= ret;
        }

        // complete
        if (req->buf.len == 0) {
            clt->queue_len -= 1;
            TAILQ_REMOVE(&clt->queue, req, _next);
            req->wr->cb(req->wr, 0);
            free(req);
            continue;
        }

        if (ret == UV_EAGAIN) {
            return;
        }

        UM_LOG(WARN, "failed to write: %d/%s", (int)ret, uv_strerror(ret));
        break;
    }

    // error handling
    // fail all pending requests
    do {
        clt->queue_len -= 1;
        TAILQ_REMOVE(&clt->queue, req, _next);
        req->wr->cb(req->wr, (int)ret);
        free(req);
        req = TAILQ_FIRST(&clt->queue);
    } while (!TAILQ_EMPTY(&clt->queue));
}

static void on_clt_io(uv_poll_t *p, int status, int events) {
    tlsuv_stream_t *clt = p->data;
    if (clt->conn_req) {
        UM_LOG(VERB, "processing connect: events=%d status=%d", events, status);
        process_connect(clt, status);
        return;
    }

    if (status != 0) {
        if (clt->read_cb) {
            uv_buf_t buf;
            clt->alloc_cb((uv_handle_t *) clt, 32 * 1024, &buf);
            clt->read_cb((uv_stream_t *) clt, status, &buf);
        }
        return;
    }

    if (events & UV_WRITABLE) {
        // flush queued requests
        process_outbound(clt);
    }

    if (events & UV_READABLE) {
        size_t count;
        size_t total;
        uv_buf_t buf;
        int rc = TLS_MORE_AVAILABLE;
        for (int i = 0; rc == TLS_MORE_AVAILABLE &&  i < 16; i++) {
            clt->alloc_cb((uv_handle_t *) clt, 64 * 1024, &buf);
            if (buf.base == NULL || buf.len == 0) {
                clt->read_cb((uv_stream_t *) clt, UV_ENOBUFS, &buf);
                break;
            }

            total = 0;

            do {
                rc = clt->tls_engine->read(clt->tls_engine, buf.base + total, &count, buf.len - total);
                total += count;
                count = 0;
            } while (rc == TLS_MORE_AVAILABLE && total < buf.len);

            if (rc == TLS_ERR) {
                clt->read_cb((uv_stream_t *)clt, UV_ECONNABORTED, &buf);
                return;
            }

            if (rc == TLS_EOF) {
                clt->read_cb((uv_stream_t *) clt, UV_EOF, &buf);
                return;
            }

            clt->read_cb((uv_stream_t *) clt, (ssize_t) total, &buf);
        }
    }

    start_io(clt);
}

int tlsuv_stream_open(uv_connect_t *req, tlsuv_stream_t *clt, uv_os_fd_t fd, uv_connect_cb cb) {
    if (!req) {
        return UV_EINVAL;
    }
    if (clt->conn_req != NULL && clt->conn_req != req) {
        return UV_EALREADY;
    }

    req->type = UV_CONNECT;
    req->cb = cb;
    req->handle = (uv_stream_t *) clt;

    clt->sock = fd;
    uv_poll_init_socket(clt->loop, &clt->watcher, clt->sock);
    clt->watcher.data = clt;
    return uv_poll_start(&clt->watcher, UV_READABLE | UV_WRITABLE | UV_DISCONNECT, on_clt_io);
}

int tlsuv_stream_connect_addr(uv_connect_t *req, tlsuv_stream_t *clt, const struct addrinfo *addr, uv_connect_cb cb) {
    if (!req) {
        return UV_EINVAL;
    }
    if (clt->conn_req != NULL && clt->conn_req != req) {
        return UV_EALREADY;
    }

    uv_os_sock_t s = new_socket(addr);
    if (s < 0) {
        return -errno;
    }

    tlsuv_stream_open(req, clt, s, cb);

    int ret = connect(clt->sock, addr->ai_addr, addr->ai_addrlen);
    if (ret == -1) {
        switch (errno) {
            case EINPROGRESS:
            case EWOULDBLOCK:
                break;
            default:
                cb(req, -errno);
                clt->conn_req = NULL;
                return 0;
        }
    }
    return 0;
}

static void on_resolve(uv_getaddrinfo_t *req, int status, struct addrinfo *addr) {
    tlsuv_stream_t *clt = req->data;
    if (clt) {
        clt->resolve_req = NULL;
        if (status == 0) {
            tlsuv_stream_connect_addr(clt->conn_req, clt, addr, clt->conn_req->cb);
        } else if (status != UV_ECANCELED) {
            clt->conn_req->cb(clt->conn_req, status);
            clt->conn_req = NULL;
        }
    }
    uv_freeaddrinfo(addr);
    free(req);
}

int tlsuv_stream_connect(uv_connect_t *req, tlsuv_stream_t *clt, const char *host, int port, uv_connect_cb cb) {
    if (!req) {
        return UV_EINVAL;
    }
    if (port <= 0 || port > UINT16_MAX) {
        return UV_EINVAL;
    }
    if (clt->conn_req != NULL) {
        return UV_EALREADY;
    }

    char portstr[6];
    snprintf(portstr, sizeof(portstr), "%d", port);

    req->handle = (uv_stream_t *) clt;
    req->cb = cb;

    tlsuv_stream_set_hostname(clt, host);
    clt->conn_req = req;

    clt->resolve_req = calloc(1, sizeof(uv_getaddrinfo_t));
    clt->resolve_req->data = clt;
    struct addrinfo hints = {
            .ai_socktype = SOCK_STREAM,
    };
    return uv_getaddrinfo(clt->loop, clt->resolve_req, on_resolve, host, portstr, &hints);
}

int tlsuv_stream_read_start(tlsuv_stream_t *clt, uv_alloc_cb alloc_cb, uv_read_cb read_cb) {
    if (clt == NULL || alloc_cb == NULL || read_cb == NULL) {
        return UV_EINVAL;
    }

    if (clt->read_cb) {
        return UV_EALREADY;
    }

    int rc = uv_poll_start(&clt->watcher, UV_READABLE, on_clt_io);
    if (rc == 0) {
        clt->alloc_cb = alloc_cb;
        clt->read_cb = read_cb;
    }
    return rc;
}

int tlsuv_stream_read_stop(tlsuv_stream_t *clt) {
    if (clt == NULL) {
        return UV_EINVAL;
    }

    if (clt->read_cb == NULL) {
        return 0;
    }
    clt->read_cb = NULL;
    clt->alloc_cb = NULL;

    return start_io(clt);
}

int tlsuv_stream_try_write(tlsuv_stream_t *clt, uv_buf_t *buf) {
    int rc = clt->tls_engine->write(clt->tls_engine, buf->base, buf->len);
    if (rc > 0) {
        return rc;
    }

    if (rc == TLS_ERR) {
        UM_LOG(WARN, "tls connection error: %s", clt->tls_engine->strerror(clt->tls_engine));
        return UV_ECONNABORTED;
    }

    if (rc == TLS_AGAIN) {
        return UV_EAGAIN;
    }

    return UV_EINVAL;
}

int tlsuv_stream_write(uv_write_t *req, tlsuv_stream_t *clt, uv_buf_t *buf, uv_write_cb cb) {
    if (req == NULL || clt == NULL) {
        return UV_EINVAL;
    }

    req->handle = (uv_stream_t *) clt;
    req->cb = cb;

    ssize_t count = 0;
    // nothing is pending
    // try writing directly
    if (TAILQ_EMPTY(&clt->queue)) {
        count = tlsuv_stream_try_write(clt, buf);
    }

    if (count == UV_EAGAIN) {
        count = 0;
    }

    if (count < 0) {
        return (int)count;
    }

    if (count == buf->len) {
        // successfully wrote the whole request
        cb(req, 0);
    } else {
        // queue request
        tlsuv_write_t *wr = malloc(sizeof(*wr));
        wr->wr = req;
        wr->buf = uv_buf_init(buf->base + count, buf->len - count);

        clt->queue_len += 1;
        TAILQ_INSERT_TAIL(&clt->queue, wr, _next);
        UM_LOG(INFO, "qlen = %zd", clt->queue_len);
    }

    return 0;
}

int tlsuv_stream_free(tlsuv_stream_t *clt) {
    if (clt->host) {
        free(clt->host);
        clt->host = NULL;
    }
    if (clt->tls_engine) {
        clt->tls_engine->free(clt->tls_engine);
        clt->tls_engine = NULL;
    }

    return 0;
}

uv_os_sock_t new_socket(const struct addrinfo *addr) {
    uv_os_sock_t sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

    int on = 1;
    int flags;

#if defined(SO_NOSIGPIPE)
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#elif defined(F_SETNOSIGPIPE)
    fcntl(sock, F_SETNOSIGPIPE, on);
#endif

#if defined(FD_CLOEXEC)
    flags = fcntl(sock, F_GETFD);
    fcntl(sock, F_SETFD, flags | FD_CLOEXEC);
#endif
#if defined(O_NONBLOCK)
    flags = fcntl(sock, F_GETFL);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#elif defined(FIONBIO)
    ioctl(sock, FIONBIO, &on);
#endif

    return sock;
}

