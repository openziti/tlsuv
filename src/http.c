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

#include "tlsuv/http.h"
#include "tlsuv/tcp_src.h"

#include <stdlib.h>
#include <string.h>

#include "um_debug.h"
#include "win32_compat.h"
#include "http_req.h"
#include "compression.h"
#include "util.h"

#define DEFAULT_IDLE_TIMEOUT 0

extern tls_context *get_default_tls(void);

static void http_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf);

static void fail_active_request(tlsuv_http_t *c, int code, const char *msg);

static void close_connection(tlsuv_http_t *c);

static void free_http(tlsuv_http_t *clt);

static inline void safe_continue(tlsuv_http_t *c) {
    if (c && !uv_is_closing((const uv_handle_t *) &c->proc)) {
        uv_async_send(&c->proc);
    }
}

enum status {
    Disconnected,
    Connecting,
    Handshaking,
    Connected
};

static const uv_link_methods_t http_methods = {
        .close = uv_link_default_close,
        .read_start = uv_link_default_read_start,
        .write = uv_link_default_write,
        .alloc_cb_override = uv_link_default_alloc_cb_override,
        .read_cb_override = http_read_cb
};

static const char *supported_alpn[] = {
    "http/1.1"
};

static const int supported_apln_num = sizeof(supported_alpn)/ sizeof(*supported_alpn);

static void http_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf) {
    tlsuv_http_t *c = link->data;

    if (nread < 0) {
        if (c->active) {
            const char *err = uv_strerror((int)nread);
            UM_LOG(ERR, "connection error before active request could complete %zd (%s)", nread, err);
            fail_active_request(c, (int)nread, err);
        }

        close_connection(c);
    } else if (nread > 0) {
        if (c->active != NULL) {
            tlsuv_http_req_t *ar = c->active;
            if (http_req_process(ar, buf->base, nread) < 0) {
                UM_LOG(WARN, "failed to parse HTTP response");
                fail_active_request(c, UV_EINVAL, "failed to parse HTTP response");
                close_connection(c);
            }

            if (ar->state == completed) {
                bool keepalive = c->keepalive;
                const char *keep_alive_hdr = tlsuv_http_resp_header(&ar->resp, "Connection");
                if (keep_alive_hdr) {
                    keepalive = strcasecmp(keep_alive_hdr, "close") != 0;
                }

                c->active = NULL;
                http_req_free(ar);
                tlsuv__free(ar);

                if (keepalive) {
                    safe_continue(c);
                } else {
                    close_connection(c);
                }
            }
         } else {
            UM_LOG(ERR, "received %zd bytes without active request", nread);
        }
    }

    if (buf && buf->base) {
        tlsuv__free(buf->base);
    }
}

static void clear_req_body(tlsuv_http_req_t *req, int code) {
    struct body_chunk_s *chunk = req->req_body, *next;
    while(chunk) {
        next = chunk->next;
        if (chunk->cb) {
            chunk->cb(req, chunk->chunk, code);
        }
        tlsuv__free(chunk);

        chunk = next;
    }
    req->req_body = NULL;
}

static void fail_active_request(tlsuv_http_t *c, int code, const char *msg) {
    tlsuv_http_req_t *req = c->active;

    if (req == NULL || req->state == completed) return;
    c->active = NULL;

    if (req->resp_cb != NULL) {
        req->resp.code = code;
        req->resp.status = tlsuv__strdup(msg);
        req->resp_cb(&req->resp, req->data);
        req->resp_cb = NULL;
    } else if (req->resp.body_cb != NULL) {
        req->resp.body_cb(c->active, NULL, code);
    }

    clear_req_body(req, code);
    http_req_free(req);
    tlsuv__free(req);
}

static void fail_all_requests(tlsuv_http_t *c, int code, const char *msg) {
    // move the queue to avoid failing requests added
    // during error handing
    struct req_q queue = c->requests;
    STAILQ_INIT(&c->requests);

    fail_active_request(c, code, msg);

    tlsuv_http_req_t *r;
    while (!STAILQ_EMPTY(&queue)) {
        r = STAILQ_FIRST(&queue);
        STAILQ_REMOVE_HEAD(&queue, _next);
        if (r->resp_cb != NULL) {
            r->resp.code = code;
            r->resp.status = tlsuv__strdup(msg);
            r->resp_cb(&r->resp, r->data);
            uv_unref((uv_handle_t *) &c->proc);
        }
        clear_req_body(r, code);
        http_req_free(r);
        tlsuv__free(r);
    }

    // app added new requests during error handling
    if (!STAILQ_EMPTY(&c->requests)) {
        safe_continue(c);
    }
}

static void on_tls_handshake(tls_link_t *tls, int status) {
    tlsuv_http_t *clt = tls->data;

    switch (status) {
        case TLS_HS_COMPLETE:
            clt->connected = Connected;
            UM_LOG(TRACE, "handshake completed with alpn[%s]", clt->engine->get_alpn(clt->engine));
            safe_continue(clt);
            break;

        case TLS_HS_ERROR: {
            const char *err = tls->engine->strerror(tls->engine);
            UM_LOG(ERR, "handshake failed status[%d]: %s", status, tls->engine->strerror(tls->engine));
            close_connection(clt);
            fail_all_requests(clt, UV_ECONNABORTED, err);
            break;
        }

        default:
            UM_LOG(ERR, "unexpected handshake status[%d]", status);
            close_connection(clt);
    }
}

static void make_links(tlsuv_http_t *clt, uv_link_t *conn_src) {
    uv_link_init(&clt->http_link, &http_methods);
    clt->http_link.data = clt;

    if (clt->ssl) {
        if (clt->tls == NULL) {
            clt->tls = get_default_tls();
            UM_LOG(VERB, "using TLS[%s]", clt->tls->version());
        }

        if (clt->host_change) {
            if (clt->engine) {
                clt->engine->free(clt->engine);
            }
            clt->engine = NULL;
            clt->host_change = false;
        }

        if (!clt->engine) {
            clt->engine = clt->tls->new_engine(clt->tls, clt->host);
            clt->engine->set_protocols(clt->engine, supported_alpn, supported_apln_num);
        }

        tlsuv_tls_link_free(&clt->tls_link);
        tlsuv_tls_link_init(&clt->tls_link, clt->engine, on_tls_handshake);
        clt->tls_link.data = clt;

        uv_link_chain(conn_src, (uv_link_t *) &clt->tls_link);
        uv_link_chain((uv_link_t *) &clt->tls_link, &clt->http_link);
        clt->connected = Handshaking;
    }
    else {
        uv_link_chain(conn_src, &clt->http_link);
    }

    uv_link_read_start(&clt->http_link);

    if (!clt->ssl) {
        clt->connected = Connected;
        safe_continue(clt);
    }
}

static void link_close_cb(uv_link_t *l) {
    tlsuv_http_t *clt = l->data;
    if (clt) {
        if (clt->engine) {
            clt->engine->free(clt->engine);
            clt->engine = NULL;
        }
        clt->src->release(clt->src);
        safe_continue(clt);
    }
}

static void src_connect_cb(tlsuv_src_t *src, int status, void *ctx) {
    UM_LOG(VERB, "src connected status = %d", status);
    tlsuv_http_t *clt = ctx;
    uv_timer_stop(clt->conn_timer);
    if (status == 0) {
        switch (clt->connected) {
            case Connecting:
                make_links(clt, (uv_link_t *) src->link);
                break;

            case Disconnected:
                UM_LOG(WARN, "src connected after timeout: state = %d", clt->connected);
                clt->src->cancel(clt->src);
                break;

            default:
                UM_LOG(ERR, "src connected for client in state[%d]", clt->connected);
        }
    } 
    else {
        UM_LOG(DEBG, "failed to connect: %d(%s)", status, uv_strerror(status));
        clt->connected = Disconnected;
        fail_all_requests(clt, status, uv_strerror(status));
        safe_continue(clt);
    }
}

static void src_connect_timeout(uv_timer_t *t) {
    tlsuv_http_t *clt = t->data;

    src_connect_cb(clt->src, UV_ETIMEDOUT, clt);
    clt->src->cancel(clt->src);
}

static void req_write_cb(uv_link_t *source, int status, void *arg) {
    UM_LOG(VERB, "request write completed: %d", status);
    tlsuv__free(arg);
}

static void req_write_body_cb(uv_link_t *source, int status, void *arg) {
    UM_LOG(VERB, "request body write completed: %d", status);
    struct body_chunk_s *chunk = arg;
    if (chunk->cb) {
        chunk->cb(chunk->req, chunk->chunk, status);
    }
    tlsuv__free(chunk);
}

static void chunk_hdr_wcb(uv_link_t *l, int status, void *arg) {
    if (arg != NULL) {
        tlsuv__free(arg);
    }
}

static void send_body(tlsuv_http_req_t *req) {
    tlsuv_http_t *clt = req->client;
    if (clt->active != req) {
        UM_LOG(ERR, "attempt to send body for inactive request");
    }

    uv_buf_t buf;
    while (req->req_body != NULL) {
        struct body_chunk_s *b = req->req_body;
        req->req_body = b->next;
        UM_LOG(VERB, "sending body chunk %ld bytes", b->len);
        req->body_sent_size += b->len;

        if (req->req_chunked) {
            if (b->len > 0) {
                buf.base = tlsuv__malloc(10);
                buf.len = snprintf(buf.base, 10, "%zx\r\n", b->len);
                uv_link_write((uv_link_t *) &clt->http_link, &buf, 1, NULL, chunk_hdr_wcb, buf.base);

                buf.base = (char*)b->chunk;
                buf.len = b->len;
                uv_link_write((uv_link_t *) &clt->http_link, &buf, 1, NULL, req_write_body_cb, b);

                buf.base = "\r\n";
                buf.len = 2;
                uv_link_write((uv_link_t *) &clt->http_link, &buf, 1, NULL, chunk_hdr_wcb, NULL);
            } else { // last chunk
                buf.base = "0\r\n\r\n";
                buf.len = 5;
                uv_link_write((uv_link_t *) &clt->http_link, &buf, 1, NULL, chunk_hdr_wcb, NULL);
                tlsuv__free(b);
                req->state = body_sent;
            }
        }
        else {
            buf = uv_buf_init((char*)b->chunk, (unsigned int)b->len);
            uv_link_write((uv_link_t *) &clt->http_link, &buf, 1, NULL, req_write_body_cb, b);
            if (req->body_sent_size > req->req_body_size) {
                UM_LOG(WARN, "Supplied data[%ld] is larger than provided Content-Length[%ld]",
                        req->body_sent_size, req->req_body_size);
            }

            if (req->body_sent_size >= req->req_body_size) {
                req->state = body_sent;
            }
        }
    }
}

static void close_connection(tlsuv_http_t *c) {
    if (c->conn_timer) {
        uv_timer_stop(c->conn_timer);
    }

    switch (c->connected) {
        case Handshaking:
        case Connected:
            UM_LOG(VERB, "closing connection");
            uv_link_close((uv_link_t *) &c->http_link, link_close_cb);
        case Connecting:
            c->connected = Disconnected;
            break;
    }
}

static void idle_timeout(uv_timer_t *t) {
    UM_LOG(VERB, "idle timeout triggered");
    tlsuv_http_t *clt = t->data;
    close_connection(clt);
}

static void process_requests(uv_async_t *ar) {
    tlsuv_http_t *c = ar->data;

    if (c->active == NULL && !STAILQ_EMPTY(&c->requests)) {
        c->active = STAILQ_FIRST(&c->requests);
        STAILQ_REMOVE_HEAD(&c->requests, _next);

        // if not keepalive close connection before next request
        if (!c->keepalive) {
            close_connection(c);
        }
    }

    if (c->active == NULL) {
        if (c->connected == Connected && c->idle_time >= 0) {
            UM_LOG(VERB, "no more requests, scheduling idle(%ld) close", c->idle_time);
            uv_timer_start(c->conn_timer, idle_timeout, c->idle_time, 0);
        }
        uv_unref((uv_handle_t *) &c->proc);
        return;
    }

    if (c->connected == Disconnected) {
        c->connected = Connecting;
        UM_LOG(VERB, "client not connected, starting connect sequence");
        if (c->connect_timeout > 0) {
            uv_timer_start(c->conn_timer, src_connect_timeout, c->connect_timeout, 0);
        }
        int rc = c->src->connect(c->src, c->host, c->port, src_connect_cb, c);
        if (rc != 0) {
            src_connect_cb(c->src, rc, c);
        }
    } else if (c->connected == Connected) {
        UM_LOG(VERB, "client connected, processing request[%s] state[%d]", c->active->path, c->active->state);
        if (c->active->state < headers_sent) {
            UM_LOG(VERB, "sending request[%s] headers", c->active->path);
            uv_buf_t req;
            req.base = tlsuv__malloc(8196);
            ssize_t header_len = http_req_write(c->active, req.base, 8196);
            if (header_len == UV_ENOMEM) {
                tlsuv__free(req.base);
                fail_active_request(c, (int)header_len, "request header too big");
                safe_continue(c);
                return;
            } else {
                req.len = header_len;
                UM_LOG(TRACE, "writing request >>> %.*s", (int) req.len, req.base);
                uv_link_write((uv_link_t *) &c->http_link, &req, 1, NULL, req_write_cb, req.base);
                c->active->state = headers_sent;
            }
        }

        // send body
        if (c->active->state < body_sent) {
            UM_LOG(VERB, "sending request[%s] body", c->active->path);
            send_body(c->active);
        }
    }
}

static void on_clt_close(uv_handle_t *h) {
    tlsuv_http_t *clt = h->data;
    free_http(clt);
    if (clt->close_cb) {
        clt->close_cb(clt);
    }
}

int tlsuv_http_close(tlsuv_http_t *clt, tlsuv_http_close_cb close_cb) {
    if (clt->conn_timer) {
        uv_close((uv_handle_t *) clt->conn_timer, (uv_close_cb) tlsuv__free);
        clt->conn_timer = NULL;
    }

    if (clt->proc.type == UV_ASYNC) {
        clt->close_cb = close_cb;
        uv_close((uv_handle_t *) &clt->proc, on_clt_close);
    } else {
        return UV_EINVAL;
    }
    fail_all_requests(clt, UV_ECANCELED, uv_strerror(UV_ECANCELED));
    close_connection(clt);

    if (clt->engine != NULL) {
        clt->engine->free(clt->engine);
        clt->engine = NULL;
    }
    clt->tls = NULL;
    return 0;
}

static void http_set_prefix(tlsuv_http_t *clt, const char *pfx, size_t pfx_len) {
    if (clt->prefix) {
        tlsuv__free(clt->prefix);
        clt->prefix = NULL;
    }
    if (pfx == NULL)
        return;

    // drop extra leading slashes
    while(pfx_len > 0 && pfx[0] == '/') {
        pfx_len--;
        pfx++;
    }

    if (pfx && pfx_len > 0) {
        clt->prefix = tlsuv__calloc(1, pfx_len + 2);
        snprintf(clt->prefix, pfx_len + 2, "/%.*s",
                 (int)pfx_len, pfx
                 );
    }
}

int tlsuv_http_set_url(tlsuv_http_t *clt, const char *url) {
    struct tlsuv_url_s u;

    if (tlsuv_parse_url(&u, url) != 0) {
        UM_LOG(ERR, "invalid URL[%s]", url);
        return UV_EINVAL;
    }

    if (u.scheme == NULL) {
        UM_LOG(ERR, "invalid URL: no scheme");
        return UV_EINVAL;
    }

    if (u.hostname == NULL) {
        UM_LOG(ERR, "invalid URL: no host");
        return UV_EINVAL;
    }

    uint16_t port;
    if (strncasecmp("http", u.scheme, u.scheme_len) == 0) {
        port = 80;
    } else if (strncasecmp("https", u.scheme, u.scheme_len) == 0) {
        port = 443;
        clt->ssl = true;
    } else {
        UM_LOG(ERR, "scheme(%.*s) is not supported", (int)u.scheme_len, u.scheme);
        return UV_EINVAL;
    }

    if (clt->host) {
        clt->host_change = true;
        tlsuv__free(clt->host);
    }
    set_http_header(&clt->headers, "Host", NULL);

    clt->host = tlsuv__strndup(u.hostname, u.hostname_len);
    if (u.port != 0) {
        char host_hdr[128];
        port = u.port;
        snprintf(host_hdr, sizeof(host_hdr), "%s:%d", clt->host, port);
        tlsuv_http_header(clt, "Host", host_hdr);
    } else {
        tlsuv_http_header(clt, "Host", clt->host);
    }


    snprintf(clt->port, sizeof(clt->port), "%d", port);

    if (u.path != NULL) {
        http_set_prefix(clt, u.path, u.path_len);
    }
    return 0;
}

int tlsuv_http_init_with_src(uv_loop_t *l, tlsuv_http_t *clt, const char *url, tlsuv_src_t *src) {
    STAILQ_INIT(&clt->requests);
    LIST_INIT(&clt->headers);

    clt->own_src = false;
    clt->ssl = false;
    clt->tls = NULL;
    clt->engine = NULL;
    clt->active = NULL;
    clt->connected = Disconnected;
    clt->src = src;
    clt->host_change = false;
    clt->host = NULL;
    clt->prefix = NULL;
    clt->conn_timer = NULL;
    clt->proc = (uv_async_t){0};

    int rc = tlsuv_http_set_url(clt, url);
    if (rc != 0) {
        return rc;
    }

    clt->connect_timeout = 0;
    clt->idle_time = DEFAULT_IDLE_TIMEOUT;
    clt->conn_timer = tlsuv__calloc(1, sizeof(uv_timer_t));
    uv_timer_init(l, clt->conn_timer);
    uv_unref((uv_handle_t *) clt->conn_timer);
    clt->conn_timer->data = clt;

    tlsuv_http_header(clt, "Connection", "keep-alive");
    if (um_available_encoding() != NULL) {
        tlsuv_http_header(clt, "Accept-Encoding", um_available_encoding());
    }

    uv_async_init(l, &clt->proc, process_requests);
    uv_unref((uv_handle_t *) &clt->proc);
    clt->proc.data = clt;

    return 0;
}

void tlsuv_http_set_path_prefix(tlsuv_http_t *clt, const char *prefix) {
    http_set_prefix(clt, prefix, prefix ? strlen(prefix) : 0);
}

int tlsuv_http_init(uv_loop_t *l, tlsuv_http_t *clt, const char *url) {
    tcp_src_t *src = tlsuv__calloc(1, sizeof(tcp_src_t));
    if (src == NULL) {
        return UV_ENOMEM;
    }

    tcp_src_init(l, src);
    tcp_src_nodelay(src, 1);
    tcp_src_keepalive(src, 1, 3);
    int rc = tlsuv_http_init_with_src(l, clt, url, (tlsuv_src_t *) src);
    if (rc == 0) {
        clt->own_src = true;
        clt->tls_link = (tls_link_t) {0};
    } else {
        tcp_src_free(src);
        tlsuv__free(src);
    }
    return rc;
}

int tlsuv_http_connect_timeout(tlsuv_http_t *clt, long millis) {
    clt->connect_timeout = millis;
    return 0;
}

int tlsuv_http_idle_keepalive(tlsuv_http_t *clt, long millis) {
    clt->idle_time = millis;
    return 0;
}

void tlsuv_http_set_ssl(tlsuv_http_t *clt, tls_context *tls) {
    clt->tls = tls;
}

tlsuv_http_req_t *tlsuv_http_req(tlsuv_http_t *clt, const char *method, const char *path, tlsuv_http_resp_cb resp_cb, void *ctx) {
    tlsuv_http_req_t *r = tlsuv__calloc(1, sizeof(tlsuv_http_req_t));
    http_req_init(r, method, path);

    r->client = clt;
    r->resp_cb = resp_cb;
    r->data = ctx;

    // copy client headers
    tlsuv_http_hdr *h;
    LIST_FOREACH(h, &clt->headers, _next) {
        set_http_header(&r->req_headers, h->name, h->value);
    }

    STAILQ_INSERT_TAIL(&clt->requests, r, _next);
    uv_timer_stop(clt->conn_timer);
    uv_ref((uv_handle_t *) &clt->proc);
    safe_continue(clt);

    return r;
}

int tlsuv_http_cancel_all(tlsuv_http_t *clt) {
    fail_all_requests(clt, UV_ECANCELED, uv_strerror(UV_ECANCELED));
    close_connection(clt);
    return 0;
}

int tlsuv_http_req_cancel(tlsuv_http_t *clt, tlsuv_http_req_t *req) {
    return http_req_cancel_err(clt, req, UV_ECANCELED, NULL);
}

int http_req_cancel_err(tlsuv_http_t *clt, tlsuv_http_req_t *req, int error, const char *msg) {

    tlsuv_http_req_t *r = NULL;
    STAILQ_FOREACH(r, &clt->requests, _next) {
        if (r == req) break;
    }

    if (r == req || req == clt->active) { // req is in the queue
        if (req == clt->active) {
            clt->active = NULL;
            // since active request is being cancelled we don't want to consume what's left on the wire for it
            // and need to close connection
            close_connection(clt);
        } else {
            STAILQ_REMOVE(&clt->requests, req, tlsuv_http_req_s, _next);
        }

        req->resp.code = error;
        req->resp.status = tlsuv__strdup(msg ? msg : uv_strerror(error));
        clear_req_body(req, req->resp.code);

        if (req->state < headers_received && req->resp_cb) { // resp_cb has not been called yet
            req->resp_cb(&req->resp, req->data);
            req->resp_cb = NULL;
        } else if (req->resp.body_cb) {
            req->resp.body_cb(req, NULL, req->resp.code);
        }

        http_req_free(req);
        tlsuv__free(req);
        return 0;
    } else {
        return UV_EINVAL;
    }
}


void tlsuv_http_header(tlsuv_http_t *clt, const char *name, const char *value) {
    set_http_header(&clt->headers, name, value);
}

int tlsuv_http_req_header(tlsuv_http_req_t *req, const char *name, const char *value) {
    if (strcasecmp(name, "transfer-encoding") == 0 &&
        strcmp(value, "chunked") == 0) {

        // Content-Length was set already
        if (req->req_body_size != -1) {
            return UV_EINVAL;
        }

        req->req_chunked = true;
    }

    if (strcasecmp(name, "Content-Length") == 0) {
        // Transfer-Encoding: chunked was set already
        if (req->req_chunked) {
            return UV_EINVAL;
        }
        req->req_body_size = strtol(value, NULL, 10);
        req->req_chunked = false;
    }

    set_http_header(&req->req_headers, name, value);
    return 0;
}

void tlsuv_http_req_end(tlsuv_http_req_t *req) {
    if (req->req_chunked) {
        struct body_chunk_s *chunk = tlsuv__calloc(1, sizeof(struct body_chunk_s));

        chunk->len = 0;
        chunk->next = NULL;
        chunk->req = req;

        if (req->req_body == NULL) {
            req->req_body = chunk;
        }
        else {
            struct body_chunk_s *prev = req->req_body;
            while (prev->next != NULL) {
                prev = prev->next;
            }

            prev->next = chunk;
        }

        safe_continue(req->client);
    }
}

int tlsuv_http_req_data(tlsuv_http_req_t *req, const char *body, size_t bodylen, tlsuv_http_body_cb cb) {
    if (strcmp(req->method, "POST") != 0 && strcmp(req->method, "PUT") != 0) {
        return UV_EINVAL;
    }

    if (req->state > headers_sent) {
        return UV_EINVAL;
    }

    struct body_chunk_s *chunk = tlsuv__calloc(1, sizeof(struct body_chunk_s));
    chunk->chunk = (char*)body;
    chunk->len = bodylen;
    chunk->cb = cb;
    chunk->next = NULL;
    chunk->req = req;

    if (req->req_body == NULL) {
        req->req_body = chunk;
    }
    else {
        struct body_chunk_s *prev = req->req_body;
        while (prev->next != NULL) {
            prev = prev->next;
        }

        prev->next = chunk;
    }

    safe_continue(req->client);
    return 0;
}

static void free_http(tlsuv_http_t *clt) {
    free_hdr_list(&clt->headers);
    tlsuv__free(clt->host);
    if (clt->prefix) tlsuv__free(clt->prefix);

    if (clt->active) {
        http_req_free(clt->active);
        tlsuv__free(clt->active);
        clt->active = NULL;
    }

    while (!STAILQ_EMPTY(&clt->requests)) {
        tlsuv_http_req_t *req = STAILQ_FIRST(&clt->requests);
        STAILQ_REMOVE_HEAD(&clt->requests, _next);
        http_req_free(req);
        tlsuv__free(req);
    }

    if (clt->own_src && clt->src) {
        clt->src->release(clt->src);
        tcp_src_free((tcp_src_t *) clt->src);
        tlsuv__free(clt->src);
        clt->src = NULL;
    }
    tlsuv_tls_link_free(&clt->tls_link);
}


int tlsuv_parse_url(struct tlsuv_url_s *url, const char *urlstr) {
    memset(url, 0, sizeof(struct tlsuv_url_s));

    const char *p = urlstr;

    int file_prefix_len = strlen("file:/");
    // special handling for file:/, file://, file://host/, file:///
    if (strncmp(urlstr, "file:/", file_prefix_len) == 0) {
        url->scheme = p;
        url->scheme_len = 4; // strlen("file")
        p += file_prefix_len;

        if (p[0] == '/') {
            p++;
            if (p[0] == '/') {
                // file:/// means empty hostname
                p++;
            } else {
                // file://path means there must be a hostname. find the next slash
                char *pos = strchr(p, '/');
                if (pos != NULL) {
                    size_t index = pos - p;
                    url->hostname = p;
                    url->hostname_len = index;
                    p += index + 1;
                } else {
                    // poorly formatted entry. this would be just `file://` or `file://hostnameonly`
                    url->hostname = p;
                    url->hostname_len = strlen(p);
                    return -1;
                }
            }
        } else {
            //one slash - else empty on purpose to indicate this is expected to be no-op
        }

#ifdef _WIN32
        if (strlen(p) > 0 && p[1] == ':') {
            // expect a windows path to have a drive letter c:, d:, etc.
        } else {
            // if no ':' in position 2, back up to pickup the leading slash
            p--;
        }
#else
        p--; //on non-windows, always backup to pickup the leading slash
#endif
        url->path = p;
        url->path_len = strlen(p);
        return 0;
    }


    int count = 0;
    int rc = sscanf(p, "%*[^:]%n://", &count);
    if (rc == 0 &&
        (p + count)[0] == ':' && (p + count)[1] == '/' && (p + count)[2] == '/'
            ) {
        url->scheme = p;
        url->scheme_len = count;
        p += (count + 3);
    }

    if (strchr(p, '@') != NULL) {
        url->username = p;
        sscanf(p, "%*[^:@]%n", &count);
        url->username_len = count;
        p += count;
        if (*p == ':') {
            p++;
            url->password = p;
            sscanf(p, "%*[^@]%n", &count);
            url->password_len = count;
            p += count;
        }
        p++;
    }

    count = 0;
    if (sscanf(p, "%*[^:/]%n", &count) == 0 && count > 0) {
        url->hostname = p;
        url->hostname_len = count;
        p += count;
    }

    if (*p == ':') {
        if (url->hostname == NULL)
            return -1;
        p += 1;
        char *pend;
        long lport = strtol(p, &pend, 10);

        if (pend == p)
            return -1;

        if (lport > 0 && lport <= UINT16_MAX) {
            url->port = (uint16_t) lport;
            p = pend;
        } else {
            return -1;
        }
    }

    if (*p == '\0')
        return 0;

    if (*p != '/') {
        return -1;
    }

    if (sscanf(p, "%*[^?]%n", &count) == 0) {
        url->path = p;
        url->path_len = count;
        p += count;
    }

    if (*p == '?') {
        url->query = p + 1;
        url->query_len = strlen(url->query);
    }

    return 0;
}
