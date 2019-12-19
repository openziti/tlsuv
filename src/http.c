/*
Copyright 2019 NetFoundry, Inc.

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

#include <stdlib.h>
#include <string.h>

#define DEBUG

#ifdef DEBUG
#define LOG(fmt, ...) \
printf(__FILE__ ":%d " fmt "\n", __LINE__, ##__VA_ARGS__ )
#else
#define LOG(...)
#endif

#include "win32_compat.h"

static const unsigned int U1 = 1;

static void http_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf);

static int tls_read_start(uv_link_t *l);

static void tls_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf);

static int tls_write(uv_link_t *link, uv_link_t *source, const uv_buf_t bufs[],
                     unsigned int nbufs, uv_stream_t *send_handle, uv_link_write_cb cb, void *arg);

static int http_status_cb(http_parser *parser, const char *status, size_t len);

static int http_message_cb(http_parser *parser);

static int http_body_cb(http_parser *parser, const char *body, size_t len);

static int http_header_field_cb(http_parser *parser, const char *f, size_t len);

static int http_header_value_cb(http_parser *parser, const char *v, size_t len);

static int http_headers_complete_cb(http_parser *p);

static void requests_fail(um_http_t *c, int code);

static void free_req(um_http_req_t *req);

static void free_http(um_http_t *clt);

struct body_chunk_s {
    const char *chunk;
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
        .close = uv_link_default_close,
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
        req->resp_cb(req, p->status_code, &req->resp_headers);
    }
    return 0;
}

static int http_header_field_cb(http_parser *parser, const char *f, size_t len) {
    um_http_req_t *req = parser->data;
    um_http_hdr *h = malloc(sizeof(um_http_hdr));
    h->name = strndup(f, len);
    LIST_INSERT_HEAD(&req->resp_headers, h, _next);
    return 0;
}

static int http_header_value_cb(http_parser *parser, const char *v, size_t len) {
    um_http_req_t *req = parser->data;
    um_http_hdr *h = LIST_FIRST(&req->resp_headers);
    h->value = strndup(v, len);
    return 0;
}

static int http_status_cb(http_parser *parser, const char *status, size_t len) {
    LOG("status = %d %*.*s", parser->status_code, (int) len, (int) len, status);
    return 0;
}

static int http_message_cb(http_parser *parser) {
    LOG("message complete");
    um_http_req_t *r = parser->data;
    r->state = completed;
    if (r->body_cb != NULL) {
        r->body_cb(r, NULL, UV_EOF);
    }
    return 0;
}

static int http_body_cb(http_parser *parser, const char *body, size_t len) {
    um_http_req_t *r = parser->data;
    if (r->body_cb != NULL) {
        r->body_cb(r, body, len);
    }
    return 0;
}

static void http_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf) {
    um_http_t *c = link->data;

    if (nread < 0) {
        requests_fail(c, nread);
    }
    if (c->active != NULL) {

        size_t processed = http_parser_execute(&c->active->response, &HTTP_PROC, buf->base, nread);

        LOG("processed %zd out of %zd", processed, nread);
        if (c->active->state == completed) {
            um_http_req_t *hr = c->active;
            c->active = NULL;
            free_req(hr);
            free(hr);

            uv_async_send(&c->proc);
        }
    }

    if (buf && buf->base) {
        free(buf->base);
    }
}

static void requests_fail(um_http_t *c, int code) {
    if (c->active != NULL && c->active->resp_cb != NULL) {
        c->active->resp_cb(c->active, code, NULL);
    }

    um_http_req_t *r;
    while (!STAILQ_EMPTY(&c->requests)) {
        r = STAILQ_FIRST(&c->requests);
        STAILQ_REMOVE_HEAD(&c->requests, _next);
        if (r->resp_cb != NULL) {
            r->resp_cb(r, code, NULL);
            uv_unref((uv_handle_t *) &c->proc);
        }
        free_req(r);
        free(r);
    }
}

static void connect_cb(uv_connect_t *req, int status) {
    um_http_t *c = req->data;

    if (status == 0) {
        uv_link_read_start(&c->http_link);

        if (!c->ssl) {
            c->connected = true;
            uv_async_send(&c->proc);
        }
    }
    else {
        requests_fail(c, status);
    }

    free(req);
}

static void resolve_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addr) {
    um_http_t *c = req->data;

    if (status == 0) {
        uv_connect_t *conn_req = malloc(sizeof(uv_connect_t));
        conn_req->data = c;
        uv_tcp_connect(conn_req, &c->conn, addr->ai_addr, connect_cb);
        uv_freeaddrinfo(addr);
    }
    else {
        requests_fail(c, status);
    }
    free(req);
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
    clt->engine = clt->tls->api->new_engine(clt->tls->ctx, clt->host);


    uv_buf_t buf;
    buf.base = malloc(32 * 1024);
    tls_handshake_state st = clt->engine->api->handshake(clt->engine->engine, NULL, 0, buf.base, &buf.len, 32 * 1024);
    LOG("starting TLS handshake(sending %zd bytes, st = %d)", buf.len, st);

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
        LOG("continuing TLS handshake(%zd bytes received)", nread);
        uv_buf_t buf;
        buf.base = malloc(32 * 1024);
        tls_handshake_state st =
                clt->engine->api->handshake(clt->engine->engine, b->base, nread, buf.base, &buf.len, 32 * 1024);

        LOG("continuing TLS handshake(sending %zd bytes, st = %d)", buf.len, st);
        if (buf.len > 0) {
            uv_link_propagate_write(l->parent, l, &buf, 1, NULL, tls_write_cb, buf.base);
        }
        else {
            free(buf.base);
        }

        if (st == TLS_HS_COMPLETE) {
            LOG("handshake completed");
            clt->connected = true;
            uv_async_send(&clt->proc);
        }
        else if (st == TLS_HS_ERROR) {
            char err[1024];
            int errlen = 0;
            if (clt->engine->api->strerror) {
                errlen = clt->engine->api->strerror(clt->engine->engine, err, sizeof(err));
            }
            LOG("TLS handshake error %*.*s", errlen, errlen, err);
            uv_link_propagate_read_cb(l, UV_ECONNABORTED, NULL);
        }
    }
    else if (hs_state == TLS_HS_COMPLETE) {
        uv_buf_t read_buf;
        uv_link_propagate_alloc_cb(l, 32 * 1024, &read_buf);
        clt->engine->api->read(clt->engine->engine, b->base, nread, read_buf.base, &read_buf.len, 32 * 1024);
        uv_link_propagate_read_cb(l, read_buf.len, &read_buf);
    }
    else {
        LOG("hs_state = %d", hs_state);
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

static void req_write_cb(uv_link_t *source, int status, void *arg) {
    LOG("request write completed: %d", status);
    free(arg);
}

static void req_write_body_cb(uv_link_t *source, int status, void *arg) {
    LOG("request body write completed: %d", status);
    struct body_chunk_s *chunk = arg;
    if (chunk->cb) {
        chunk->cb(chunk->req, chunk->chunk, status);
    }
    free(chunk);
}

static void process_requests(uv_async_t *ar) {
    um_http_t *c = ar->data;

    if (!c->connected) {
        LOG("client not connected, starting connect sequence");
        uv_getaddrinfo_t *resolv_req = malloc(sizeof(uv_getaddrinfo_t));
        resolv_req->data = c;
        uv_getaddrinfo(ar->loop, resolv_req, resolve_cb, c->host, c->port, NULL);
    }
    else {
        LOG("client connected, processing request");

        if (c->active != NULL) {
            return;
        }

        if (STAILQ_EMPTY(&c->requests)) {
            LOG("no more requests, closing");
            uv_close((uv_handle_t *) &c->proc, NULL);
            uv_link_close((uv_link_t *) &c->http_link, link_close_cb);

        }
        else {

            c->active = STAILQ_FIRST(&c->requests);
            STAILQ_REMOVE_HEAD(&c->requests, _next);

            uv_buf_t req;
            req.base = malloc(8196);
            req.len = snprintf(req.base, 8196,
                               "%s %s HTTP/1.1\r\n"
                               "Host: %s\r\n",
                               c->active->method, c->active->path, c->host);

            if (strcmp(c->active->method, "POST") == 0 || strcmp(c->active->method, "PUT") == 0) {
                if (!c->active->req_chunked && c->active->req_size == -1) {
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
            LIST_FOREACH(h, &c->headers, _next) {
                req.len += snprintf(req.base + req.len, 8196 - req.len,
                                    "%s: %s\r\n", h->name, h->value);
            }
            LIST_FOREACH(h, &c->active->req_headers, _next) {
                req.len += snprintf(req.base + req.len, 8196 - req.len,
                                    "%s: %s\r\n", h->name, h->value);
            }
            req.len += snprintf(req.base + req.len, 8196 - req.len,
                                "\r\n");

            uv_link_write((uv_link_t *) &c->http_link, &req, 1, NULL, req_write_cb, req.base);

            // send body
            while (c->active->req_body != NULL) {
                struct body_chunk_s *b = c->active->req_body;
                c->active->req_body = b->next;

                req.base = b->chunk;
                req.len = b->len;
                uv_link_write((uv_link_t *) &c->http_link, &req, 1, NULL, req_write_body_cb, b);
            }
        }
    }
}

int um_http_close(um_http_t *clt) {
    free_http(clt);
    return 0;
}

int um_http_init(uv_loop_t *l, um_http_t *clt, const char *url) {
    STAILQ_INIT(&clt->requests);
    LIST_INIT(&clt->headers);

    clt->ssl = false;
    clt->tls = NULL;
    clt->engine = NULL;
    clt->tls_link = NULL;
    clt->active = NULL;
    clt->connected = false;
    struct http_parser_url url_parse = {0};
    int rc = http_parser_parse_url(url, strlen(url), false, &url_parse);

    if (url_parse.field_set & (U1 << (unsigned int) UF_HOST)) {
        clt->host = strndup(url +
                            url_parse.field_data[UF_HOST].off,
                            url_parse.field_data[UF_HOST].len);
    }
    else {
        fprintf(stderr, "invalid URL: no host");
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
            fprintf(stderr, "scheme(%*.*s) is not supported",
                    url_parse.field_data[UF_SCHEMA].len, url_parse.field_data[UF_SCHEMA].len,
                    url + url_parse.field_data[UF_SCHEMA].off);
            return UV_EINVAL;
        }
    }
    else {
        fprintf(stderr, "invalid URL: no scheme");
        return UV_EINVAL;
    }

    if (url_parse.field_set & (U1 << (unsigned int) UF_PORT)) {
        port = url_parse.port;
    }

    sprintf(clt->port, "%d", port);

    uv_async_init(l, &clt->proc, process_requests);
    uv_unref((uv_handle_t *) &clt->proc);
    clt->proc.data = clt;
    uv_tcp_init(l, &clt->conn);
    uv_link_source_init(&clt->conn_src, (uv_stream_t *) &clt->conn);

    uv_link_init(&clt->http_link, &http_methods);
    clt->http_link.data = clt;

    if (clt->ssl) {
        clt->tls_link = malloc(sizeof(uv_link_t));
        uv_link_init(clt->tls_link, &tls_methods);
        clt->tls_link->data = clt;

        clt->tls = default_tls_context(NULL, 0);

        uv_link_chain((uv_link_t *) &clt->conn_src, clt->tls_link);
        uv_link_chain(clt->tls_link, &clt->http_link);
    }
    else {
        uv_link_chain((uv_link_t *) &clt->conn_src, &clt->http_link);
    }

    return 0;
}

um_http_req_t *um_http_req(um_http_t *c, const char *method, const char *path) {
    um_http_req_t *r = calloc(1, sizeof(um_http_req_t));
    r->client = c;
    r->response.data = r;
    r->method = strdup(method);
    r->path = strdup(path);
    r->req_body = NULL;
    r->req_chunked = false;
    r->req_size = -1;
    r->state = created;

    http_parser_init(&r->response, HTTP_RESPONSE);

    STAILQ_INSERT_TAIL(&c->requests, r, _next);

    uv_ref((uv_handle_t *) &c->proc);
    uv_async_send(&c->proc);

    return r;
}

void um_http_header(um_http_t *clt, const char *name, const char *value) {
    um_http_hdr *h = malloc(sizeof(um_http_hdr));
    h->name = strdup(name);
    h->value = strdup(value);

    LIST_INSERT_HEAD(&clt->headers, h, _next);
}

int um_http_req_header(um_http_req_t *req, const char *name, const char *value) {
    um_http_hdr *h = malloc(sizeof(um_http_hdr));
    h->name = strdup(name);
    h->value = strdup(value);

    if (strcasecmp(name, "transfer-encoding") == 0 &&
        strcmp(value, "chunked") == 0) {

        // Content-Length was set already
        if (req->req_size != -1) {
            return UV_EINVAL;
        }

        req->req_chunked = true;
    }

    if (strcasecmp(name, "Content-Length") == 0) {
        // Transfet-Encoding: chunked was set already
        if (req->req_chunked) {
            return UV_EINVAL;
        }

        req->req_chunked = true;
    }

    LIST_INSERT_HEAD(&req->req_headers, h, _next);
    return 0;
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
    free_hdr_list(&req->resp_headers);
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
    if (clt->tls != NULL) {
        clt->tls->api->free_ctx(clt->tls);
        clt->tls = NULL;
    }
    if (clt->tls_link != NULL) {
        free(clt->tls_link);
        clt->tls_link = NULL;
    }

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