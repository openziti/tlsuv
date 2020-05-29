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

#define DEFAULT_IDLE_TIMEOUT 0

extern tls_context *get_default_tls();

static const unsigned int U1 = 1;

static void http_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf);

static int tls_read_start(uv_link_t *l);

static void tls_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf);

static int tls_write(uv_link_t *link, uv_link_t *source, const uv_buf_t bufs[],
                     unsigned int nbufs, uv_stream_t *send_handle, uv_link_write_cb cb, void *arg);

static void tls_close(uv_link_t *link, uv_link_t *source, uv_link_close_cb cb);

static int http_status_cb(http_parser *parser, const char *status, size_t len);

static int http_message_cb(http_parser *parser);

static int http_body_cb(http_parser *parser, const char *body, size_t len);

static int http_header_field_cb(http_parser *parser, const char *f, size_t len);

static int http_header_value_cb(http_parser *parser, const char *v, size_t len);

static int http_headers_complete_cb(http_parser *p);

static void requests_fail(um_http_t *c, int code, const char *msg);

static void close_connection(um_http_t *c);
static void free_req(um_http_req_t *req);

static void free_http(um_http_t *clt);

enum status {
    Disconnected,
    Connecting,
    Connected
};

struct body_chunk_s {
    char *chunk;
    size_t len;
    um_http_body_cb cb;

    um_http_req_t *req;

    struct body_chunk_s *next;
};

static const uv_link_methods_t http_methods = {
        .close = uv_link_default_close,
        .read_start = uv_link_default_read_start,
        .write = uv_link_default_write,
        .alloc_cb_override = uv_link_default_alloc_cb_override,
        .read_cb_override = http_read_cb
};

static const uv_link_methods_t tls_methods = {
        .close = tls_close,
        .read_start = tls_read_start,
        .write = tls_write,
        .alloc_cb_override = uv_link_default_alloc_cb_override,
        .read_cb_override = tls_read_cb
};

static http_parser_settings HTTP_PROC = {
        .on_header_field = http_header_field_cb,
        .on_header_value = http_header_value_cb,
        .on_headers_complete = http_headers_complete_cb,
        .on_status = http_status_cb,
        .on_message_complete = http_message_cb,
        .on_body = http_body_cb
};

static int http_headers_complete_cb(http_parser *p) {
    um_http_req_t *req = p->data;
    req->state = headers_received;
    if (req->resp_cb != NULL) {
        req->resp_cb(&req->resp, req->data);
    }
    return 0;
}

static int http_header_field_cb(http_parser *parser, const char *f, size_t len) {
    um_http_req_t *req = parser->data;
    if (req->resp.headers == NULL) {
        req->resp.headers = calloc(20, sizeof(um_http_hdr));
    }
    req->resp.headers[req->resp.nh].name = strndup(f, len);
    return 0;
}

static int http_header_value_cb(http_parser *parser, const char *v, size_t len) {
    um_http_req_t *req = parser->data;
    req->resp.headers[req->resp.nh++].value = strndup(v, len);

    return 0;
}

static int http_status_cb(http_parser *parser, const char *status, size_t len) {
    UM_LOG(VERB, "status = %d %.*s", parser->status_code, (int) len, status);
    um_http_req_t *r = parser->data;
    r->resp.code = (int) parser->status_code;
    snprintf(r->resp.http_version, sizeof(r->resp.http_version), "%d.%d", parser->http_major, parser->http_minor);
    r->resp.status = calloc(1, len);
    strncpy(r->resp.status, status, len);
    return 0;
}

static int http_message_cb(http_parser *parser) {
    UM_LOG(VERB, "message complete");
    um_http_req_t *r = parser->data;
    r->state = completed;
    if (r->resp.body_cb != NULL) {
        r->resp.body_cb(r, NULL, UV_EOF);
    }
    return 0;
}

static int http_body_cb(http_parser *parser, const char *body, size_t len) {
    um_http_req_t *r = parser->data;
    if (r->resp.body_cb != NULL) {
        r->resp.body_cb(r, body, len);
    }
    return 0;
}

static void http_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf) {
    um_http_t *c = link->data;

    if (nread < 0) {
        const char *err = uv_strerror(nread);
        UM_LOG(WARN, "received %zd (%s)", nread, err);
        requests_fail(c, nread, err);

        close_connection(c);
        return;
    }

    if (c->active != NULL) {

        if (nread > 0) {
            UM_LOG(TRACE, "processing \n%*.*s", nread, nread, buf->base);
            size_t processed = http_parser_execute(&c->active->parser, &HTTP_PROC, buf->base, nread);
            UM_LOG(VERB, "processed %zd out of %zd", processed, nread);
        }

		if (c->active->state == completed) {
            um_http_req_t *hr = c->active;
            c->active = NULL;
            free_req(hr);
            free(hr);

            uv_async_send(&c->proc);
        }
    } else if (nread > 0) {
        UM_LOG(ERR, "received %zd bytes without active request", nread);
    }

    if (buf && buf->base) {
        free(buf->base);
    }
}

static void requests_fail(um_http_t *c, int code, const char *msg) {
    if (c->active != NULL && c->active->resp_cb != NULL) {
        c->active->resp.code = code;
        c->active->resp.status = strdup(msg);
        c->active->resp_cb(&c->active->resp, c->active->data);
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
        free_req(r);
        free(r);
    }
}

static void make_links(um_http_t *clt, uv_link_t *conn_src) {
    uv_link_init(&clt->http_link, &http_methods);
    clt->http_link.data = clt;

    if (clt->ssl) {
        uv_link_init(&clt->tls_link, &tls_methods);
        clt->tls_link.data = clt;

        uv_link_chain((uv_link_t *) conn_src, &clt->tls_link);
        uv_link_chain(&clt->tls_link, &clt->http_link);
    }
    else {
        uv_link_chain((uv_link_t *) conn_src, &clt->http_link);
    }

    uv_link_read_start(&clt->http_link);

    if (!clt->ssl) {
        clt->connected = Connected;
        uv_async_send(&clt->proc);
    }
}

static void src_connect_cb(um_http_src_t *src, int status) {
    UM_LOG(VERB, "src connected status = %d", status);
    if (status == 0) {
        make_links(src->clt, src->link);
    } 
    else {
        requests_fail(src->clt, status, uv_strerror(status));
    }
}

static void link_close_cb(uv_link_t *l) {}

static void tls_write_cb(uv_link_t *source, int status, void *arg) {
    if (arg != NULL) {
        free(arg);
    }
}

static int tls_read_start(uv_link_t *l) {
    uv_link_default_read_start(l);

    um_http_t *clt = l->data;
    if (clt->tls == NULL) {
        clt->tls = get_default_tls();
    }
    clt->engine = clt->tls->api->new_engine(clt->tls->ctx, clt->host);

    uv_buf_t buf;
    buf.base = malloc(32 * 1024);
    tls_handshake_state st = clt->engine->api->handshake(clt->engine->engine, NULL, 0, buf.base, &buf.len, 32 * 1024);
    UM_LOG(VERB, "starting TLS handshake(sending %zd bytes, st = %d)", buf.len, st);

    return uv_link_propagate_write(l->parent, l, &buf, 1, NULL, tls_write_cb, buf.base);
}

static void tls_read_cb(uv_link_t *l, ssize_t nread, const uv_buf_t *b) {
    um_http_t *clt = l->data;

    if (nread < 0) {
        if (b && b->base)
            free(b->base);
        uv_link_propagate_read_cb(l, nread, NULL);
        return;
    }

    tls_handshake_state hs_state = clt->engine->api->handshake_state(clt->engine->engine);
    if (hs_state == TLS_HS_CONTINUE) {
        assert(clt->connected == Connecting);
        UM_LOG(VERB, "continuing TLS handshake(%zd bytes received)", nread);
        uv_buf_t buf;
        buf.base = malloc(32 * 1024);
        tls_handshake_state st =
                clt->engine->api->handshake(clt->engine->engine, b->base, nread, buf.base, &buf.len, 32 * 1024);

        UM_LOG(VERB, "continuing TLS handshake(sending %zd bytes, st = %d)", buf.len, st);
        if (buf.len > 0) {
            uv_link_propagate_write(l->parent, l, &buf, 1, NULL, tls_write_cb, buf.base);
        }
        else {
            free(buf.base);
        }

        if (st == TLS_HS_COMPLETE) {
            UM_LOG(VERB, "handshake completed");
            clt->connected = Connected;
            uv_async_send(&clt->proc);
        }
        else if (st == TLS_HS_ERROR) {
            char err[1024];
            int errlen = 0;
            if (clt->engine->api->strerror) {
                errlen = clt->engine->api->strerror(clt->engine->engine, err, sizeof(err));
            }
            UM_LOG(ERR, "TLS handshake error %*.*s", errlen, errlen, err);
            uv_link_propagate_read_cb(l, UV_ECONNABORTED, NULL);
        }
    }
    else if (hs_state == TLS_HS_COMPLETE) {
        uv_buf_t read_buf;
        uv_link_propagate_alloc_cb(l, 32 * 1024, &read_buf);

        size_t readbuflen = read_buf.len;
        read_buf.len = 0;

        size_t out_bytes;
        char *inptr = b->base;
        size_t inlen = nread;
        int rc;
        do {
            rc = clt->engine->api->read(clt->engine->engine, inptr, inlen,
                    read_buf.base + read_buf.len, &out_bytes, readbuflen - read_buf.len);

            UM_LOG(VERB, "produced %zd application byte (rc=%d)", out_bytes, rc);
            read_buf.len += out_bytes;
            inptr = NULL;
            inlen = 0;
        } while (rc == TLS_MORE_AVAILABLE && out_bytes > 0);

        uv_link_propagate_read_cb(l, read_buf.len, &read_buf);
    }
    else {
        UM_LOG(VERB, "hs_state = %d", hs_state);
    }

    if (b != NULL && b->base != NULL) {
        free(b->base);
    }
}

static int tls_write(uv_link_t *l, uv_link_t *source, const uv_buf_t bufs[],
                     unsigned int nbufs, uv_stream_t *send_handle, uv_link_write_cb cb, void *arg) {
    um_http_t *clt = l->data;
    uv_buf_t buf;
    buf.base = malloc(32 * 1024);
    clt->engine->api->write(clt->engine->engine, bufs[0].base, bufs[0].len, buf.base, &buf.len, 32 * 1024);
    int rc = uv_link_propagate_write(l->parent, l, &buf, 1, NULL, tls_write_cb, buf.base);

    cb(source, 0, arg);

    return rc;
}

static void tls_close(uv_link_t *l, uv_link_t *source, uv_link_close_cb close_cb) {
    UM_LOG(VERB, "closing TLS link");
    um_http_t *clt = l->data;

    clt->tls->api->free_engine(clt->engine);
    clt->engine = NULL;

    close_cb(source);
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
    uv_timer_stop(&c->idle_timer);
    if (c->connected == Connected ) {
        UM_LOG(VERB, "closing connection");
        c->connected = Disconnected;
        uv_link_close((uv_link_t *) &c->http_link, link_close_cb);
    }
}

static void idle_timeout(uv_timer_t *t) {
    UM_LOG(VERB, "idle timeout triggered");
    um_http_t *clt = t->data;
    close_connection(clt);
}

static void process_requests(uv_async_t *ar) {
    um_http_t *c = ar->data;

    if (c->connected == Disconnected) {
        c->connected = Connecting;
        UM_LOG(VERB, "client not connected, starting connect sequence");
        c->src->connect(c->src, src_connect_cb);
    }
    else if (c->connected == Connected) {
        UM_LOG(VERB, "client connected, processing request");

        if (c->active != NULL) {
            return;
        }

        if (STAILQ_EMPTY(&c->requests)) {
            if (c->idle_time >= 0) {
                UM_LOG(VERB, "no more requests, scheduling idle(%ld) close", c->idle_time);
                uv_timer_start(&c->idle_timer, idle_timeout, c->idle_time, 0);
                uv_unref((uv_handle_t *) &c->proc);
            }
        }
        else {

            c->active = STAILQ_FIRST(&c->requests);
            STAILQ_REMOVE_HEAD(&c->requests, _next);

            uv_buf_t req;
            req.base = malloc(8196);
            req.len = snprintf(req.base, 8196,
                               "%s %s HTTP/1.1\r\n",
                               c->active->method, c->active->path);

            if (strcmp(c->active->method, "POST") == 0 ||
                strcmp(c->active->method, "PUT") == 0 ||
                strcmp(c->active->method, "PATCH") == 0) {
                if (!c->active->req_chunked && c->active->req_body_size == -1) {
                    size_t req_len = 0;
                    struct body_chunk_s *chunk = c->active->req_body;
                    while (chunk != NULL) {
                        req_len += chunk->len;
                        chunk = chunk->next;
                    }
                    um_http_hdr *content_length = malloc(sizeof(um_http_hdr));
                    content_length->name = strdup("Content-Length");
                    content_length->value = malloc(16);
                    sprintf(content_length->value, "%ld", req_len);
                    LIST_INSERT_HEAD(&c->active->req_headers, content_length, _next);
                }
            }

            um_http_hdr *h;
            bool need_host = true; 
            LIST_FOREACH(h, &c->headers, _next) {
                if (strcasecmp(h->name, "Host") == 0) {
                    need_host = false;
                }

                req.len += snprintf(req.base + req.len, 8196 - req.len,
                                    "%s: %s\r\n", h->name, h->value);
            }
            LIST_FOREACH(h, &c->active->req_headers, _next) {
                if (strcasecmp(h->name, "Host") == 0) {
                    need_host = false;
                }

                req.len += snprintf(req.base + req.len, 8196 - req.len,
                                    "%s: %s\r\n", h->name, h->value);
            }

            if (need_host) {
                req.len += snprintf(req.base + req.len, 8196 - req.len,
                                    "Host: %s\r\n", c->host);
            }
            req.len += snprintf(req.base + req.len, 8196 - req.len,
                                "\r\n");
            UM_LOG(TRACE, "writing request >>> %*.*s", req.len, req.len, req.base);
            uv_link_write((uv_link_t *) &c->http_link, &req, 1, NULL, req_write_cb, req.base);
            c->active->state = headers_sent;

            // send body
            send_body(c->active);
        }
    }
}

int um_http_close(um_http_t *clt) {
    close_connection(clt);
    uv_close((uv_handle_t *) &clt->idle_timer, NULL);
    uv_close((uv_handle_t *) &clt->proc, NULL);

    if (clt->src != NULL) { 
        clt->src->release(clt->src);
    }

    free_http(clt);
    return 0;
}

int um_http_init_with_src(uv_loop_t *l, um_http_t *clt, const char *url, um_http_src_t *src) {
    STAILQ_INIT(&clt->requests);
    LIST_INIT(&clt->headers);

    clt->ssl = false;
    clt->tls = NULL;
    clt->engine = NULL;
    clt->active = NULL;
    clt->connected = Disconnected;
    clt->src = src;
    src->clt = clt;

    clt->idle_time = DEFAULT_IDLE_TIMEOUT;
    uv_timer_init(l, &clt->idle_timer);
    uv_unref((uv_handle_t *) &clt->idle_timer);
    clt->idle_timer.data = clt;

    um_http_header(clt, "Connection", "keep-alive");

    struct http_parser_url url_parse = {0};
    int rc = http_parser_parse_url(url, strlen(url), false, &url_parse);

    if (url_parse.field_set & (U1 << (unsigned int) UF_HOST)) {
        clt->host = strndup(url +
                            url_parse.field_data[UF_HOST].off,
                            url_parse.field_data[UF_HOST].len);
    }
    else {
        UM_LOG(ERR, "invalid URL: no host");
        return UV_EINVAL;
    }

    uint16_t port = -1;
    if (url_parse.field_set & (U1 << (unsigned int) UF_SCHEMA)) {
        if (strncasecmp("http", url + url_parse.field_data[UF_SCHEMA].off, url_parse.field_data[UF_SCHEMA].len) == 0) {
            port = 80;
        }
        else if (strncasecmp("https", url + url_parse.field_data[UF_SCHEMA].off, url_parse.field_data[UF_SCHEMA].len) ==
                 0) {
            port = 443;
            clt->ssl = true;
        }
        else {
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

    uv_async_init(l, &clt->proc, process_requests);
    uv_unref((uv_handle_t *) &clt->proc);
    clt->proc.data = clt;

    return 0;
}

int um_http_init(uv_loop_t *l, um_http_t *clt, const char *url) {
    tcp_src_init(l, &clt->default_src);
    return um_http_init_with_src(l, clt, url, (um_http_src_t *)&clt->default_src);    
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
    r->client = c;
    r->parser.data = r;
    r->method = strdup(method);
    r->path = strdup(path);
    r->req_body = NULL;
    r->req_chunked = false;
    r->req_body_size = -1;
    r->body_sent_size = 0;
    r->state = created;

    r->resp.req = r;
    r->resp_cb = resp_cb;
    r->data = ctx;

    http_parser_init(&r->parser, HTTP_RESPONSE);

    STAILQ_INSERT_TAIL(&c->requests, r, _next);

    uv_timer_stop(&c->idle_timer);
    uv_ref((uv_handle_t *) &c->proc);
    uv_async_send(&c->proc);

    return r;
}

void um_http_header(um_http_t *clt, const char *name, const char *value) {
    um_http_hdr *h;
    LIST_FOREACH(h, &clt->headers, _next) {
        if (strcmp(h->name, name) == 0) {
            break;
        }
    }

    if (value == NULL) {
        if (h != NULL) {
            LIST_REMOVE(h, _next);
            free(h->value);
            free(h->name);
        }
        return;
    }

    if (h == NULL) {
        h = malloc(sizeof(um_http_hdr));
        h->name = strdup(name);
        LIST_INSERT_HEAD(&clt->headers, h, _next);
    } else {
        free(h->value);
    }

    h->value = strdup(value);
}

int um_http_req_header(um_http_req_t *req, const char *name, const char *value) {
    um_http_hdr *h = malloc(sizeof(um_http_hdr));
    h->name = strdup(name);
    h->value = strdup(value);

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

    LIST_INSERT_HEAD(&req->req_headers, h, _next);
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

        if (req->client->active == req) {
            send_body(req);
        }
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

    if (req->client->active == req) {
        send_body(req);
    }
    return 0;
}

static void free_hdr(um_http_hdr *hdr) {
    free(hdr->name);
    free(hdr->value);
}

static void free_hdr_list(um_header_list *l) {
    um_http_hdr *h;
    while (!LIST_EMPTY(l)) {
        h = LIST_FIRST(l);
        LIST_REMOVE(h, _next);

        free_hdr(h);
        free(h);
    }
}

static void free_req(um_http_req_t *req) {
    free_hdr_list(&req->req_headers);
    if (req->resp.headers) {
        for (um_http_hdr *h = req->resp.headers; h->name != NULL; h++) {
            free(h->name);
            free(h->value);
        }
        free(req->resp.headers);
    }
    if (req->resp.status) {
        free(req->resp.status);
    }
    free(req->path);
    free(req->method);
}

static void free_http(um_http_t *clt) {
    free_hdr_list(&clt->headers);
    free(clt->host);
    if (clt->engine != NULL) {
        clt->tls->api->free_engine(clt->engine);
        clt->engine = NULL;
    }
    clt->tls = NULL;

    if (clt->active) {
        free_req(clt->active);
        free(clt->active);
        clt->active = NULL;
    }

    while (!STAILQ_EMPTY(&clt->requests)) {
        um_http_req_t *req = STAILQ_FIRST(&clt->requests);
        STAILQ_REMOVE_HEAD(&clt->requests, _next);
        free_req(req);
        free(req);
    }
}