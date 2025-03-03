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

#include "tlsuv/tlsuv.h"
#include "um_debug.h"
#include "util.h"
#include "tlsuv/queue.h"
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <assert.h>

#if _WIN32
#include "win32_compat.h"
#include <winsock2.h>
#define ioctl ioctlsocket
#define get_error() WSAGetLastError()
#else
#define closesocket(s) close(s)
#define get_error() errno
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#define to_str1(s) #s
#define to_str(s) to_str1(s)

#ifdef TLSUV_VERSION
#define TLSUV_VERS to_str(TLSUV_VERSION)
#else
#define TLSUV_VERS "<unknown>"
#endif

static void on_clt_io(uv_poll_t *, int, int);
static void fail_pending_reqs(tlsuv_stream_t *clt, int err);
static void check_read(uv_idle_t *idle);

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

    clt->connector = tlsuv_global_connector();
    clt->tls = tls != NULL ? tls : get_default_tls();
    clt->read_cb = NULL;
    clt->alloc_cb = NULL;
    clt->queue_len = 0;
    TAILQ_INIT(&clt->queue);

    return 0;
}

void tlsuv_stream_set_connector(tlsuv_stream_t *clt, const tlsuv_connector_t *c) {
    assert(clt != NULL);
    clt->connector = c != NULL ? c : tlsuv_global_connector();
}

static int start_io(tlsuv_stream_t *clt) {
    int events = 0;

    // was closed already
    if (uv_is_closing((const uv_handle_t *) &clt->watcher)) {
        return UV_EINVAL;
    }

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
    tlsuv_stream_t *clt = container_of(h, tlsuv_stream_t, watcher);
    if (clt->conn_req) {
        uv_connect_t *req = clt->conn_req;
        clt->conn_req = NULL;
        if (req->cb) {
            req->cb(req, UV_ECANCELED);
        }
    }

    if (h->type == UV_POLL && h->data) {
        uv_idle_t *idle = h->data;
        assert(idle->type == UV_IDLE);
        uv_close((uv_handle_t *) idle, (uv_close_cb) tlsuv__free);
    }

    // error handling
    // fail all pending requests
    fail_pending_reqs(clt, UV_ECANCELED);

    if (clt->tls_engine) {
        clt->tls_engine->free(clt->tls_engine);
        clt->tls_engine = NULL;
    }

    if (clt->close_cb) {
        clt->close_cb((uv_handle_t *) clt);
    }
}

int tlsuv_stream_close(tlsuv_stream_t *clt, uv_close_cb close_cb) {
    clt->read_cb = NULL;
    clt->alloc_cb = NULL;
    clt->close_cb = close_cb;

    if (clt->connect_req) {
        UM_LOG(VERB, "cancel before connector cb");
        const void *cr = clt->connect_req;
        clt->connector->cancel(cr);
        clt->connect_req = NULL;
    }

    if (clt->tls_engine) {
        clt->tls_engine->close(clt->tls_engine);
    }

    if (clt->watcher.type == UV_POLL) {
        uv_poll_stop(&clt->watcher);
        closesocket(clt->sock);
    } else {
        // if uv_poll has not been set up create a throwaway handle to defer close_cb
        uv_idle_init(clt->loop, (uv_idle_t*)&clt->watcher);
    }
    uv_close((uv_handle_t *) &clt->watcher, on_internal_close);

    return 0;
}

int tlsuv_stream_keepalive(tlsuv_stream_t *clt, int keepalive, unsigned int delay) {
    uv_os_sock_t s;
    if (uv_fileno((const uv_handle_t *) &clt->watcher, (uv_os_fd_t *) &s) == 0) {
        int count = 10;
        int intvl = 1;
        setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
#if defined(TCP_KEEPALIVE)
        setsockopt(s, IPPROTO_TCP, TCP_KEEPALIVE, &delay, sizeof(delay));
#endif
#if defined(TCP_KEEPINTVL)
        setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
#endif
#if defined(TCP_KEEPCNT)
        setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
#endif
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
    tlsuv__free (clt->host);
    clt->host = tlsuv__strdup(host);
    return 0;
}

static void process_connect(tlsuv_stream_t *clt, int status) {
    assert(clt->conn_req);
    uv_connect_t *req = clt->conn_req;
    int err = 0;
    socklen_t l = sizeof(err);
    getsockopt(clt->sock, SOL_SOCKET, SO_ERROR, &err, &l);

    if (status == 0 && err != 0) {
#if _WIN32
        switch(err) {
            case WSAECONNREFUSED: status = UV_ECONNREFUSED; break;
            case WSAECANCELLED: status = UV_ECANCELED; break;
            case WSAECONNRESET: status = UV_ECONNRESET; break;
            case WSAECONNABORTED: status = UV_ECONNABORTED; break;
            default:
                status = -err;
        }
#else
        status = -(err);
#endif
    }

    if (status != 0) {
        UM_LOG(ERR, "failed connect: %d/%s", status, uv_strerror(status));
        clt->conn_req = NULL;
        uv_poll_stop(&clt->watcher);
        req->cb(req, status);
        return;
    }

    if (clt->tls_engine == NULL) {
        clt->tls_engine = clt->tls->new_engine(clt->tls, clt->host);
        if (clt->alpn_protocols) {
            clt->tls_engine->set_protocols(clt->tls_engine, clt->alpn_protocols, clt->alpn_count);
        }
        clt->tls_engine->set_io_fd(clt->tls_engine, (uv_os_fd_t) clt->sock);
    }

    int rc;
    rc = clt->tls_engine->handshake(clt->tls_engine);

    if (rc == TLS_HS_ERROR) {
        const char *error = clt->tls_engine->strerror(clt->tls_engine);
        UM_LOG(ERR, "TLS handshake failed: %s", error);
        clt->conn_req = NULL;
        uv_poll_stop(&clt->watcher);
        req->cb(req, UV_ECONNABORTED);
        return;
    }

    if (rc == TLS_HS_COMPLETE) {
        UM_LOG(DEBG, "handshake completed");
        clt->conn_req = NULL;
        start_io(clt);
        req->cb(req, 0);
    } else {
        // wait for incoming handshake messages
        uv_poll_start(&clt->watcher, UV_READABLE, on_clt_io);
    }
}

static ssize_t write_req(tlsuv_stream_t *clt, uv_buf_t *buf) {
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

static void fail_pending_reqs(tlsuv_stream_t *clt, int err) {
    while(!TAILQ_EMPTY(&clt->queue)) {
        tlsuv_write_t *req = TAILQ_FIRST(&clt->queue);
        TAILQ_REMOVE(&clt->queue, req, _next);
        clt->queue_len -= 1;

        if (req->wr->cb) {
            req->wr->cb(req->wr, (int) err);
        }
        tlsuv__free(req);
    }
}

static void process_outbound(tlsuv_stream_t *clt) {
    tlsuv_write_t *req;
    ssize_t ret = 0;

    while (!TAILQ_EMPTY(&clt->queue)) {
        req = TAILQ_FIRST(&clt->queue);
        ret = write_req(clt, &req->buf);
        if (ret > 0) {
            req->buf.base += ret;
            req->buf.len -= ret;

            // complete
            if (req->buf.len == 0) {
                clt->queue_len -= 1;
                TAILQ_REMOVE(&clt->queue, req, _next);
                if (req->wr->cb) {
                    req->wr->cb(req->wr, 0);
                }
                tlsuv__free(req);
                req = NULL;
            }
            continue;
        }

        if (ret == UV_EAGAIN) {
            return;
        }

        break;
    }

    // write failed so fail all queued requests
    if (ret < 0) {
        UM_LOG(WARN, "failed to write: %d/%s", (int)ret, uv_strerror(ret));
        while (!TAILQ_EMPTY(&clt->queue)) {
            req = TAILQ_FIRST(&clt->queue);
            TAILQ_REMOVE(&clt->queue, req, _next);
            clt->queue_len -= 1;
            if (req->wr->cb) {
                req->wr->cb(req->wr, (int) ret);
            }
            tlsuv__free(req);
        }
    }
}

static void process_inbound(tlsuv_stream_t *clt) {
    size_t total;
    uv_buf_t buf;
    int rc;

    int attempts = 16;

    // got IO or idle check, can clear the handle
    if (clt->watcher.data) {
        uv_idle_t *idler = clt->watcher.data;
        assert(idler->type == UV_IDLE);

        clt->watcher.data = NULL;
        uv_close((uv_handle_t *) idler, (uv_close_cb) tlsuv__free);
    }

    while(clt->read_cb && (attempts-- > 0)) {
        assert(clt->alloc_cb != NULL);

        buf = uv_buf_init(NULL, 0);
        clt->alloc_cb((uv_handle_t *) clt, 64 * 1024, &buf);
        if (buf.base == NULL || buf.len == 0) {
            clt->read_cb((uv_stream_t *) clt, UV_ENOBUFS, &buf);
            break;
        }

        total = 0;

        do {
            size_t count = 0;
            rc = clt->tls_engine->read(clt->tls_engine, buf.base + total, &count, buf.len - total);
            total += count;
        } while ( (rc == TLS_MORE_AVAILABLE || rc == TLS_OK) && total < buf.len);

        if (total > 0) {
            clt->read_cb((uv_stream_t *) clt, (ssize_t) total, &buf);
            continue;
        }

        if (rc == TLS_ERR) {
            clt->read_cb((uv_stream_t *)clt, UV_ECONNABORTED, &buf);
            fail_pending_reqs(clt, UV_ECONNABORTED);
            break;
        }

        if (rc == TLS_EOF) {
            clt->read_cb((uv_stream_t *) clt, UV_EOF, &buf);
            break;
        }

        clt->read_cb((uv_stream_t *) clt, (ssize_t) total, &buf);

        if (rc == TLS_AGAIN) {
            break;
        }
    }
    UM_LOG(TRACE, "finished reading after %d iterations", 16 - attempts);
}

static void on_clt_io(uv_poll_t *p, int status, int events) {
    tlsuv_stream_t *clt = container_of(p, tlsuv_stream_t, watcher);
    if (clt->conn_req) {
        UM_LOG(VERB, "processing connect: events=%d status=%d", events, status);
        process_connect(clt, status);
        return;
    }

    if (status != 0) {
        UM_LOG(WARN, "IO failed: %d/%s", status, uv_strerror(status));
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
        process_inbound(clt);
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

    clt->conn_req = req;
    req->type = UV_CONNECT;
    req->cb = cb;
    req->handle = (uv_stream_t *) clt;

    clt->sock = fd;
    uv_poll_init_socket(clt->loop, &clt->watcher, clt->sock);
    process_connect(clt, 0);
    return 0;
}

int tlsuv_stream_connect_addr(uv_connect_t *req, tlsuv_stream_t *clt, const struct addrinfo *addr, uv_connect_cb cb) {
    if (!req) {
        return UV_EINVAL;
    }
    if (clt->conn_req != NULL && clt->conn_req != req) {
        return UV_EALREADY;
    }

    uv_os_sock_t s = tlsuv_socket(addr, 0);
    if (s < 0) {
        return -get_error();
    }

    int ret = connect(s, addr->ai_addr, addr->ai_addrlen);
    if (ret == -1) {
        int error = get_error();
        switch (error) {
            case EINPROGRESS:
            case EWOULDBLOCK:
#if _WIN32
            case WSAEWOULDBLOCK:
            case WSAEINPROGRESS:
#endif
                break;
            default:
                cb(req, -error);
                clt->conn_req = NULL;
                return 0;
        }
    }

    return tlsuv_stream_open(req, clt, s, cb);
}

static void on_connect(uv_os_sock_t sock, int status, void *ctx) {
    uv_connect_t *r = ctx;
    tlsuv_stream_t *clt = (tlsuv_stream_t *)r->handle;
    clt->connect_req = NULL;

    // app closed stream before it connected
    if (clt->close_cb) {
        UM_LOG(VERB, "closed before connect: %d/%s", status, uv_strerror(status));
        on_internal_close((uv_handle_t *) &clt->watcher);
        return;
    }

    if (status == 0) {
        tlsuv_stream_open(clt->conn_req, clt, sock, clt->conn_req->cb);
        return;
    }

    clt->conn_req = NULL;
    r->cb(r, status);
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

    clt->connect_req = clt->connector->connect(clt->loop, clt->connector, host, portstr, on_connect, clt->conn_req);
    return 0;
}

int tlsuv_stream_read_start(tlsuv_stream_t *clt, uv_alloc_cb alloc_cb, uv_read_cb read_cb) {
    if (clt == NULL || alloc_cb == NULL || read_cb == NULL) {
        return UV_EINVAL;
    }

    if (clt->read_cb) {
        return UV_EALREADY;
    }

    clt->alloc_cb = alloc_cb;
    clt->read_cb = read_cb;

    int rc = start_io(clt);
    if (rc != 0) {
        clt->alloc_cb = NULL;
        clt->read_cb = NULL;
    } else {
        // schedule idle read (if nothing on the wire)
        // in case reading was stopped with data buffered in TLS engine
        uv_idle_t *idle = tlsuv__calloc(1, sizeof(*idle));
        clt->watcher.data = idle;
        uv_idle_init(clt->loop, idle);
        idle->data = clt;
        uv_idle_start(idle, check_read);
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
    // do not allow to cut the line
    if (!TAILQ_EMPTY(&clt->queue)) {
        return UV_EAGAIN;
    }

    return (int) write_req(clt, buf);
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

    // successfully wrote the whole request
    if (count == buf->len) {
        cb(req, 0);
        return 0;
    }

    // queue request or whatever left
    tlsuv_write_t *wr = tlsuv__malloc(sizeof(*wr));
    wr->wr = req;
    wr->buf = uv_buf_init(buf->base + count, buf->len - count);
    clt->queue_len += 1;
    TAILQ_INSERT_TAIL(&clt->queue, wr, _next);

    // make sure to re-arm IO after queuing request
    return start_io(clt);
}

int tlsuv_stream_free(tlsuv_stream_t *clt) {
    if (clt->host) {
        tlsuv__free(clt->host);
        clt->host = NULL;
    }
    if (clt->tls_engine) {
        clt->tls_engine->free(clt->tls_engine);
        clt->tls_engine = NULL;
    }

    return 0;
}

int tlsuv_socket_set_blocking(uv_os_sock_t s, bool blocking) {

#if defined(O_NONBLOCK)
    int flags = fcntl(s, F_GETFL);
    if (blocking) {
        fcntl(s, F_SETFL, flags & ~O_NONBLOCK);
    } else {
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
    }
#elif defined(FIONBIO)
    if (blocking) {
        int off = 0;
        ioctl(s, FIONBIO, &off);
    } else {
        int on = 1;
        ioctl(s, FIONBIO, &on);
    }
#endif
    return 0;
}

void check_read(uv_idle_t *idler) {
    tlsuv_stream_t *clt = idler->data;
    // this will clean up idle handle
    process_inbound(clt);
}

int tlsuv_stream_peername(const tlsuv_stream_t *clt, struct sockaddr *addr, int *namelen) {
    uv_os_fd_t fd;
    int r = uv_fileno((const uv_handle_t *) &clt->watcher, &fd);
    if (r != 0) {
        return r;
    }

    socklen_t socklen = (socklen_t)*namelen;
    r = getpeername(fd, addr, &socklen);
    if (r != 0) {
        return r;
    }

    *namelen = (int)socklen;
    return 0;
}
