/*
Copyright 2019-2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "uv_mbed/um_http.h"
#include "uv_mbed/tcp_src.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "um_debug.h"
#include "win32_compat.h"
#include "http_req.h"
#include "compression.h"

#define DEFAULT_IDLE_TIMEOUT 0

extern tls_context *get_default_tls();

static const unsigned int U1 = 1;

static void http_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf);

static int http_status_cb(http_parser *parser, const char *status, size_t len);

static int http_message_cb(http_parser *parser);

static int http_body_cb(http_parser *parser, const char *body, size_t len);

static int http_header_field_cb(http_parser *parser, const char *f, size_t len);

static int http_header_value_cb(http_parser *parser, const char *v, size_t len);

static int http_headers_complete_cb(http_parser *p);

static void fail_active_request(um_http_t *c, int code, const char *msg);

static void close_connection(um_http_t *c);

static void free_http(um_http_t *clt);

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

static void http_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf) {
    um_http_t *c = link->data;

    if (nread < 0) {
        if (c->active) {
            const char *err = uv_strerror(nread);
            UM_LOG(ERR, "connection error before active request could complete %zd (%s)", nread, err);
            fail_active_request(c, nread, err);
        }

        close_connection(c);
        uv_async_send(&c->proc);
        if (buf && buf->base) {
            free(buf->base);
        }
        return;
    }

    if (c->active != NULL) {

        if (nread > 0) {
            http_req_process(c->active, buf->base, nread);
        }

		if (c->active->state == completed) {
            um_http_req_t *hr = c->active;
            c->active = NULL;

            bool keep_alive = true;
            const char *keep_alive_hdr = um_http_resp_header(&hr->resp, "Connection");
            if (strcmp(hr->resp.http_version, "1.1") == 0) {
                if (keep_alive_hdr && strcasecmp("close", keep_alive_hdr) == 0)
                    keep_alive = false;
            } else if (strcmp(hr->resp.http_version, "1.0") == 0) {
                keep_alive = keep_alive_hdr && strcasecmp("keep-alive", keep_alive_hdr) == 0;
            } else {
                UM_LOG(WARN, "unexpected HTTP version(%s)", hr->resp.http_version);
                keep_alive = false;
            }

            http_req_free(hr);
            free(hr);

            if (!keep_alive) {
                close_connection(c);
            }
            else {
                uv_async_send(&c->proc);
            }
        }
    } else if (nread > 0) {
        UM_LOG(ERR, "received %zd bytes without active request", nread);
    }

    if (buf && buf->base) {
        free(buf->base);
    }
}

static void fail_active_request(um_http_t *c, int code, const char *msg) {
    if (c->active != NULL && c->active->resp_cb != NULL) {
        c->active->resp.code = code;
        c->active->resp.status = strdup(msg);
        c->active->resp_cb(&c->active->resp, c->active->data);
        http_req_free(c->active);
        free(c->active);
        c->active = NULL;
    }

    um_http_req_t *r;
    while (!STAILQ_EMPTY(&c->requests)) {
        r = STAILQ_FIRST(&c->requests);
        STAILQ_REMOVE_HEAD(&c->requests, _next);
        if (r->resp_cb != NULL) {
            r->resp.code = code;
            r->resp.status = strdup(msg);
            r->resp_cb(&r->resp, r->data);
            uv_unref((uv_handle_t *) &c->proc);
        }
        http_req_free(r);
        free(r);
    }
}

static void on_tls_handshake(tls_link_t *tls, int status) {
    um_http_t *clt = tls->data;

    switch (status) {
        case TLS_HS_COMPLETE:
            clt->connected = Connected;
            uv_async_send(&clt->proc);
            break;

        case TLS_HS_ERROR:
            UM_LOG(ERR, "handshake failed status[%d]", status);
            close_connection(clt);
            fail_active_request(clt, UV_ECONNABORTED, uv_strerror(UV_ECONNABORTED));
            break;

        default:
            UM_LOG(ERR, "unexpected handshake status[%d]", status);
            close_connection(clt);
    }
}

static void make_links(um_http_t *clt, uv_link_t *conn_src) {
    uv_link_init(&clt->http_link, &http_methods);
    clt->http_link.data = clt;

    if (clt->ssl) {
        if (clt->tls == NULL) {
            clt->tls = get_default_tls();
        }

        if (clt->host_change) {
            clt->tls->api->free_engine(clt->engine);
            clt->engine = NULL;
            clt->host_change = false;
        }

        if (!clt->engine) {
            clt->engine = clt->tls->api->new_engine(clt->tls->ctx, clt->host);
        }

        um_tls_init(&clt->tls_link, clt->engine, on_tls_handshake);
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
        uv_async_send(&clt->proc);
    }
}

static void link_close_cb(uv_link_t *l) {
    um_http_t *clt = l->data;
    if (clt) {
        uv_async_send(&clt->proc);
    }
}

static void src_connect_cb(um_src_t *src, int status, void *ctx) {
    UM_LOG(VERB, "src connected status = %d", status);
    um_http_t *clt = ctx;
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
        fail_active_request(clt, status, uv_strerror(status));
        uv_async_send(&clt->proc);
    }
}

static void src_connect_timeout(uv_timer_t *t) {
    um_http_t *clt = t->data;

    src_connect_cb(clt->src, UV_ETIMEDOUT, clt);
    clt->src->cancel(clt->src);
}

static void req_write_cb(uv_link_t *source, int status, void *arg) {
    UM_LOG(VERB, "request write completed: %d", status);
    free(arg);
}

static void req_write_body_cb(uv_link_t *source, int status, void *arg) {
    UM_LOG(VERB, "request body write completed: %d", status);
    struct body_chunk_s *chunk = arg;
    if (chunk->cb) {
        chunk->cb(chunk->req, chunk->chunk, status);
    }
    free(chunk);
}

static void chunk_hdr_wcb(uv_link_t *l, int status, void *arg) {
    if (arg != NULL) {
        free(arg);
    }
}

static void send_body(um_http_req_t *req) {
    um_http_t *clt = req->client;
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
                buf.base = malloc(10);
                buf.len = snprintf(buf.base, 10, "%zx\r\n", b->len);
                uv_link_write((uv_link_t *) &clt->http_link, &buf, 1, NULL, chunk_hdr_wcb, buf.base);

                buf.base = b->chunk;
                buf.len = b->len;
                uv_link_write((uv_link_t *) &clt->http_link, &buf, 1, NULL, req_write_body_cb, b);

                buf.base = "\r\n";
                buf.len = 2;
                uv_link_write((uv_link_t *) &clt->http_link, &buf, 1, NULL, chunk_hdr_wcb, NULL);
            } else { // last chunk
                buf.base = "0\r\n\r\n";
                buf.len = 5;
                uv_link_write((uv_link_t *) &clt->http_link, &buf, 1, NULL, chunk_hdr_wcb, NULL);
                free(b);
                req->state = body_sent;
            }
        }
        else {
            buf = uv_buf_init(b->chunk, b->len);
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

static void close_connection(um_http_t *c) {
    uv_timer_stop(c->conn_timer);
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
    um_http_t *clt = t->data;
    close_connection(clt);
}

static void process_requests(uv_async_t *ar) {
    um_http_t *c = ar->data;

    if (c->active == NULL && !STAILQ_EMPTY(&c->requests)) {
        c->active = STAILQ_FIRST(&c->requests);
        STAILQ_REMOVE_HEAD(&c->requests, _next);
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
    }
    else if (c->connected == Connected) {
        UM_LOG(VERB, "client connected, processing request[%s] state[%d]", c->active->path, c->active->state);
        if (c->active->state < headers_sent) {
            UM_LOG(VERB, "sending request[%s] headers", c->active->path);
            uv_buf_t req;
            req.base = malloc(8196);
            req.len = http_req_write(c->active, req.base, 8196);
            UM_LOG(TRACE, "writing request >>> %*.*s", req.len, req.len, req.base);
            uv_link_write((uv_link_t *) &c->http_link, &req, 1, NULL, req_write_cb, req.base);
            c->active->state = headers_sent;
        }

        // send body
        if (c->active->state < body_sent) {
            UM_LOG(VERB, "sending request[%s] body", c->active->path);
            send_body(c->active);
        }
    }
}

static void on_clt_close(uv_handle_t *h) {
    um_http_t *clt = h->data;
    free_http(clt);
    if (clt->close_cb) {
        clt->close_cb(clt);
    }
}

int um_http_close(um_http_t *clt, um_http_close_cb close_cb) {
    uv_close((uv_handle_t *) &clt->proc, on_clt_close);

    fail_active_request(clt, UV_ECANCELED, uv_strerror(UV_ECANCELED));
    close_connection(clt);

    if (clt->src != NULL) { 
        clt->src->release(clt->src);
    }

    if (clt->engine != NULL) {
        clt->tls->api->free_engine(clt->engine);
        clt->engine = NULL;
    }
    clt->tls = NULL;

    clt->close_cb = close_cb;
    uv_close((uv_handle_t *) clt->conn_timer, free);
    return 0;
}

static void http_set_prefix(um_http_t *clt, const char *pfx, size_t pfx_len) {
    if (clt->prefix) {
        free(clt->prefix);
        clt->prefix = NULL;
    }

    if (pfx) {
        clt->prefix = calloc(1, pfx_len + 1);
        strncpy(clt->prefix, pfx, pfx_len);
    }
}

int um_http_set_url(um_http_t *clt, const char *url) {
    struct http_parser_url url_parse = {0};
    if (http_parser_parse_url(url, strlen(url), false, &url_parse)) {
        UM_LOG(ERR, "invalid URL[%s]", url);
        return UV_EINVAL;
    }

    if (clt->host) {
        clt->host_change = true;
        free(clt->host);
    }
    set_http_header(&clt->headers, "Host", NULL);

    if (url_parse.field_set & (U1 << (unsigned int) UF_HOST)) {
        clt->host = strndup(url +
                            url_parse.field_data[UF_HOST].off,
                            url_parse.field_data[UF_HOST].len);
    }
    else {
        UM_LOG(ERR, "invalid URL: no host");
        return UV_EINVAL;
    }

    um_http_header(clt, "Host", clt->host);

    uint16_t port = -1;
    if (url_parse.field_set & (U1 << (unsigned int) UF_SCHEMA)) {
        if (strncasecmp("http", url + url_parse.field_data[UF_SCHEMA].off, url_parse.field_data[UF_SCHEMA].len) == 0) {
            port = 80;
        } else if (strncasecmp("https", url + url_parse.field_data[UF_SCHEMA].off, url_parse.field_data[UF_SCHEMA].len) == 0) {
            port = 443;
            clt->ssl = true;
        } else {
            UM_LOG(ERR, "scheme(%*.*s) is not supported",
                    url_parse.field_data[UF_SCHEMA].len, url_parse.field_data[UF_SCHEMA].len,
                    url + url_parse.field_data[UF_SCHEMA].off);
            return UV_EINVAL;
        }
    }
    else {
        UM_LOG(ERR, "invalid URL: no scheme");
        return UV_EINVAL;
    }

    if (url_parse.field_set & (U1 << (unsigned int) UF_PORT)) {
        port = url_parse.port;
    }

    sprintf(clt->port, "%d", port);

    if (url_parse.field_set & (U1 << (unsigned int) UF_PATH)) {
        http_set_prefix(clt, url + url_parse.field_data[UF_PATH].off, url_parse.field_data[UF_PATH].len);
    }
    return 0;
}

int um_http_init_with_src(uv_loop_t *l, um_http_t *clt, const char *url, um_src_t *src) {
    STAILQ_INIT(&clt->requests);
    LIST_INIT(&clt->headers);

    clt->ssl = false;
    clt->tls = NULL;
    clt->engine = NULL;
    clt->active = NULL;
    clt->connected = Disconnected;
    clt->src = src;
    clt->host_change = false;
    clt->host = NULL;
    clt->prefix = NULL;

    int rc = um_http_set_url(clt, url);
    if (rc != 0) {
        return rc;
    }

    clt->connect_timeout = 0;
    clt->idle_time = DEFAULT_IDLE_TIMEOUT;
    clt->conn_timer = calloc(1, sizeof(uv_timer_t));
    uv_timer_init(l, clt->conn_timer);
    uv_unref((uv_handle_t *) clt->conn_timer);
    clt->conn_timer->data = clt;

    um_http_header(clt, "Connection", "keep-alive");
    if (um_available_encoding() != NULL) {
        um_http_header(clt, "Accept-Encoding", um_available_encoding());
    }

    uv_async_init(l, &clt->proc, process_requests);
    uv_unref((uv_handle_t *) &clt->proc);
    clt->proc.data = clt;

    return 0;
}

void um_http_set_path_prefix(um_http_t *clt, const char *prefix) {
    http_set_prefix(clt, prefix, strlen(prefix));
}

int um_http_init(uv_loop_t *l, um_http_t *clt, const char *url) {
    tcp_src_t *src = calloc(1, sizeof(tcp_src_t));
    tcp_src_init(l, src);
    clt->own_src = true;
    return um_http_init_with_src(l, clt, url, (um_src_t *)src);
}

int um_http_connect_timeout(um_http_t *clt, long millis) {
    clt->connect_timeout = millis;
    return 0;
}

int um_http_idle_keepalive(um_http_t *clt, long millis) {
    clt->idle_time = millis;
    return 0;
}

void um_http_set_ssl(um_http_t *clt, tls_context *tls) {
    clt->tls = tls;
}

um_http_req_t *um_http_req(um_http_t *c, const char *method, const char *path, um_http_resp_cb resp_cb, void *ctx) {
    um_http_req_t *r = calloc(1, sizeof(um_http_req_t));
    http_req_init(r, method, path);

    r->client = c;
    r->resp_cb = resp_cb;
    r->data = ctx;

    // copy client headers
    um_http_hdr *h;
    LIST_FOREACH(h, &c->headers, _next) {
        set_http_header(&r->req_headers, h->name, h->value);
    }

    STAILQ_INSERT_TAIL(&c->requests, r, _next);
    uv_timer_stop(c->conn_timer);
    uv_ref((uv_handle_t *) &c->proc);
    uv_async_send(&c->proc);

    return r;
}



void um_http_header(um_http_t *clt, const char *name, const char *value) {
    set_http_header(&clt->headers, name, value);
}

int um_http_req_header(um_http_req_t *req, const char *name, const char *value) {
    if (strcasecmp(name, "transfer-encoding") == 0 &&
        strcmp(value, "chunked") == 0) {

        // Content-Length was set already
        if (req->req_body_size != -1) {
            return UV_EINVAL;
        }

        req->req_chunked = true;
    }

    if (strcasecmp(name, "Content-Length") == 0) {
        // Transfet-Encoding: chunked was set already
        if (req->req_chunked) {
            return UV_EINVAL;
        }
        req->req_body_size = strtol(value, NULL, 10);
        req->req_chunked = false;
    }

    set_http_header(&req->req_headers, name, value);
    return 0;
}

void um_http_req_end(um_http_req_t *req) {
    if (req->req_chunked) {
        struct body_chunk_s *chunk = calloc(1, sizeof(struct body_chunk_s));

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

        uv_async_send(&req->client->proc);
    }
}

int um_http_req_data(um_http_req_t *req, const char *body, ssize_t body_len, um_http_body_cb cb) {
    if (strcmp(req->method, "POST") != 0 && strcmp(req->method, "PUT") != 0) {
        return UV_EINVAL;
    }

    if (req->state > headers_sent) {
        return UV_EINVAL;
    }

    struct body_chunk_s *chunk = calloc(1, sizeof(struct body_chunk_s));
    chunk->chunk = body;
    chunk->len = body_len;
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

    uv_async_send(&req->client->proc);
    return 0;
}

static void free_http(um_http_t *clt) {
    free_hdr_list(&clt->headers);
    free(clt->host);
    if (clt->prefix) free(clt->prefix);

    if (clt->active) {
        http_req_free(clt->active);
        free(clt->active);
        clt->active = NULL;
    }

    while (!STAILQ_EMPTY(&clt->requests)) {
        um_http_req_t *req = STAILQ_FIRST(&clt->requests);
        STAILQ_REMOVE_HEAD(&clt->requests, _next);
        http_req_free(req);
        free(req);
    }
}