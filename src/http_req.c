/*
Copyright 2020 NetFoundry, Inc.

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

#include "http_req.h"
#include "um_debug.h"
#include "win32_compat.h"
#include <string.h>

static void free_hdr(um_http_hdr *hdr);

static int http_headers_complete_cb(http_parser *p);
static int http_header_field_cb(http_parser *parser, const char *f, size_t len);
static int http_header_value_cb(http_parser *parser, const char *v, size_t len);
static int http_status_cb(http_parser *parser, const char *status, size_t len);
static int http_message_cb(http_parser *parser);
static int http_body_cb(http_parser *parser, const char *body, size_t len);

static http_parser_settings HTTP_PROC = {
        .on_header_field = http_header_field_cb,
        .on_header_value = http_header_value_cb,
        .on_headers_complete = http_headers_complete_cb,
        .on_status = http_status_cb,
        .on_message_complete = http_message_cb,
        .on_body = http_body_cb
};

void http_req_init(um_http_req_t *r, const char *method, const char *path) {
    r->parser.data = r;
    r->method = strdup(method);
    r->path = strdup(path);
    r->req_body = NULL;
    r->req_chunked = false;
    r->req_body_size = -1;
    r->body_sent_size = 0;
    r->state = created;
    r->resp.req = r;

    http_parser_init(&r->parser, HTTP_RESPONSE);
}

void http_req_free(um_http_req_t *req) {
    if (req == NULL) return;

    free_hdr_list(&req->req_headers);
    free_hdr_list(&req->resp.headers);
    if (req->resp.status) {
        free(req->resp.status);
    }
    free(req->path);
    free(req->method);
}

size_t http_req_process(um_http_req_t *req, const char* buf, ssize_t len) {
    UM_LOG(TRACE, "processing \n%.*s", len, buf);
    size_t processed = http_parser_execute(&req->parser, &HTTP_PROC, buf, len);
    UM_LOG(VERB, "processed %zd out of %zd", processed, len);
    return processed;
}

static void free_hdr(um_http_hdr *hdr) {
    free(hdr->name);
    free(hdr->value);
}

void free_hdr_list(um_header_list *l) {
    um_http_hdr *h;
    while (!LIST_EMPTY(l)) {
        h = LIST_FIRST(l);
        LIST_REMOVE(h, _next);

        free_hdr(h);
        free(h);
    }
}

size_t http_req_write(um_http_req_t *req, char *buf, size_t maxlen) {
    size_t len = snprintf(buf, maxlen,
                          "%s %s HTTP/1.1\r\n",
                          req->method, req->path);

    if (strcmp(req->method, "POST") == 0 ||
        strcmp(req->method, "PUT") == 0 ||
        strcmp(req->method, "PATCH") == 0) {
        if (!req->req_chunked && req->req_body_size == -1) {
            size_t req_len = 0;
            struct body_chunk_s *chunk = req->req_body;
            while (chunk != NULL) {
                req_len += chunk->len;
                chunk = chunk->next;
            }
            req->req_body_size = req_len;
            char length_str[16];
            sprintf(length_str, "%ld", req_len);
            set_http_header(&req->req_headers, "Content-Length", length_str);
        }
    }

    um_http_hdr *h;
    LIST_FOREACH(h, &req->req_headers, _next) {
        len += snprintf(buf + len, maxlen - len, "%s: %s\r\n", h->name, h->value);
    }

    len += snprintf(buf + len, maxlen - len, "\r\n");
    return len;
}

void set_http_headern(um_header_list *hl, const char* name, const char *value, size_t vallen) {
    um_http_hdr *h;
    LIST_FOREACH(h, hl, _next) {
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

    h = malloc(sizeof(um_http_hdr));
    h->name = strdup(name);
    LIST_INSERT_HEAD(hl, h, _next);

    h->value = strndup(value, vallen);
}

void set_http_header(um_header_list *hl, const char* name, const char *value) {
    um_http_hdr *h;
    LIST_FOREACH(h, hl, _next) {
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
        LIST_INSERT_HEAD(hl, h, _next);
    } else {
        free(h->value);
    }

    h->value = strdup(value);
}

const char* um_http_resp_header(um_http_resp_t *resp, const char *name) {
    um_http_hdr *h;
    LIST_FOREACH(h, &resp->headers, _next) {
        if (strcasecmp(h->name, name) == 0) {
            return h->value;
        }
    }
    return NULL;
}

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
    req->resp.curr_header = strndup(f, len);
    return 0;
}

static int http_header_value_cb(http_parser *parser, const char *v, size_t len) {
    um_http_req_t *req = parser->data;
    set_http_headern(&req->resp.headers, req->resp.curr_header, v, len);
    free(req->resp.curr_header);
    req->resp.curr_header = NULL;
    return 0;
}

static int http_status_cb(http_parser *parser, const char *status, size_t len) {
    UM_LOG(VERB, "status = %d %.*s", parser->status_code, (int) len, status);
    um_http_req_t *r = parser->data;
    r->resp.code = (int) parser->status_code;
    snprintf(r->resp.http_version, sizeof(r->resp.http_version), "%d.%d", parser->http_major, parser->http_minor);
    r->resp.status = calloc(1, len+1);
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