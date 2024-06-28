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

#include "alloc.h"
#include "http_req.h"
#include "um_debug.h"
#include "win32_compat.h"
#include <string.h>
#include <ctype.h>
#include "compression.h"

static void free_hdr(tlsuv_http_hdr *hdr);

static int http_headers_complete_cb(llhttp_t *p);
static int http_header_field_cb(llhttp_t *parser, const char *f, size_t len);
static int http_header_value_cb(llhttp_t *parser, const char *v, size_t len);
static int http_status_cb(llhttp_t *parser, const char *status, size_t len);
static int http_message_cb(llhttp_t *parser);
static int http_body_cb(llhttp_t *parser, const char *body, size_t len);

static llhttp_settings_t HTTP_PROC = {
        .on_header_field = http_header_field_cb,
        .on_header_value = http_header_value_cb,
        .on_headers_complete = http_headers_complete_cb,
        .on_status = http_status_cb,
        .on_message_complete = http_message_cb,
        .on_body = http_body_cb
};

void http_req_init(tlsuv_http_req_t *r, const char *method, const char *path) {
    r->method = tlsuv__strdup(method);
    r->path = tlsuv__strdup(path);
    r->req_body = NULL;
    r->req_chunked = false;
    r->req_body_size = -1;
    r->body_sent_size = 0;
    r->state = created;
    r->resp.req = r;

    llhttp_init(&r->parser, HTTP_RESPONSE, &HTTP_PROC);
    r->parser.data = r;
}

void http_req_free(tlsuv_http_req_t *req) {
    if (req == NULL) return;

    free_hdr_list(&req->req_headers);
    free_hdr_list(&req->resp.headers);
    if (req->resp.status) {
        tlsuv__free(req->resp.status);
    }
    if (req->inflater) {
        um_free_inflater(req->inflater);
    }
    tlsuv__free(req->query);
    tlsuv__free(req->path);
    tlsuv__free(req->method);
}

static int printable_len(const unsigned char* buf, size_t len) {
    const unsigned char *p = buf;
    while (p - buf < len && (isprint(*p) || isspace(*p))) p++;
    return (int)(p - buf);
}

ssize_t http_req_process(tlsuv_http_req_t *req, const char* buf, ssize_t len) {
    UM_LOG(TRACE, "processing %zd bytes\n%.*s", len, printable_len((const unsigned char*)buf, len), buf);
    llhttp_errno_t err = llhttp_execute(&req->parser, buf, len);
    ssize_t processed = -1;
    if (err == HPE_OK) {
        processed = len;
        UM_LOG(VERB, "processed %zd of %zd", processed, len);
    } else if (err == HPE_PAUSED_UPGRADE) {
        processed = llhttp_get_error_pos(&req->parser) - buf;
        UM_LOG(VERB, "websocket upgrade: processed %zd out of %zd", processed, len);
        llhttp_resume_after_upgrade(&req->parser);
    } else {
        UM_LOG(WARN, "failed to process: %d/%s", err, llhttp_errno_name(err));
    }
    return processed;
}

static void free_hdr(tlsuv_http_hdr *hdr) {
    tlsuv__free(hdr->name);
    tlsuv__free(hdr->value);
}

void free_hdr_list(um_header_list *l) {
    tlsuv_http_hdr *h;
    while (!LIST_EMPTY(l)) {
        h = LIST_FIRST(l);
        LIST_REMOVE(h, _next);

        free_hdr(h);
        tlsuv__free(h);
    }
}

#define HEXIFY(c) (((c) < 10) ? '0' + (c) : 'A' + (c) - 10)

static ssize_t write_url_encoded(char *buf, size_t maxlen, const char *url) {
    static char unsafe[] = "/:\"<>%{}|\\^`";
    char *p = buf;

#define CHECK_APPEND(ptr, c)  if (ptr - buf < maxlen)  *ptr++ = (c); else return UV_ENOMEM

    for(; *url != 0; url++) {
        if (*url <= ' ' || strchr(unsafe, *url) != NULL) {
            CHECK_APPEND(p, '%');
            CHECK_APPEND(p, HEXIFY((*url >> 4) & 0xf));
            CHECK_APPEND(p, HEXIFY(*url & 0xf));
        } else {
            CHECK_APPEND(p, *url);
        }
    }
#undef CHECK_APPEND
    return p - buf;
}

static void free_body_cb(tlsuv_http_req_t *r, char *body, ssize_t i) {
    tlsuv__free(body);
}

static char *encode_query (size_t count, const tlsuv_http_pair *pairs, size_t *outlen) {
#define MAX_FORM (16 * 1024)
    char *body = tlsuv__malloc(MAX_FORM);
    if (body == NULL) {
        return NULL;
    }

    size_t len = 0;
    for (int i = 0; i < count; i++) {
        if (len >= MAX_FORM) { goto error; }

        if (i > 0) {
            body[len++] = '&';
        }
        ssize_t l = write_url_encoded(body + len, MAX_FORM - len,  pairs[i].name);
        if (l < 0) { goto error; }
        len += l;

        if (len >= MAX_FORM) { goto error; }
        body[len++] = '=';

        l = write_url_encoded(body + len, MAX_FORM - len, pairs[i].value);
        if (l < 0) { goto error; }
        len += l;
    }
    body[len] = '\0';
    if (outlen)
        *outlen = len;
    return body;
    error:
    tlsuv__free(body);
    return NULL;
}

int tlsuv_http_req_query(tlsuv_http_req_t *req, size_t count, const tlsuv_http_pair params[]) {
    if (req->state > headers_sent) {
        return UV_EINVAL;
    }

    char *query = NULL;

    if (count > 0 && params != NULL) {
        query = encode_query(count, params, NULL);
        if (query == NULL) {
            return UV_EINVAL;
        }
    }

    tlsuv__free(req->query);
    req->query = query;
    return 0;
}

int tlsuv_http_req_form(tlsuv_http_req_t *req, size_t count, const tlsuv_http_pair pairs[]) {
    if (strcmp(req->method, "POST") != 0) {
        return UV_EINVAL;
    }

    if (count == 0 || pairs == NULL) {
        return UV_EINVAL;
    }

    if (req->state > headers_sent) {
        return UV_EINVAL;
    }


    size_t len = 0;
    char *body = encode_query(count, pairs, &len);
    if (body == NULL) {
        http_req_cancel_err(req->client, req, UV_ENOMEM, "form data too big");
        return UV_ENOMEM;
    }

    tlsuv_http_req_header(req, "Content-Type", "application/x-www-form-urlencoded");

    char content_len[16];
    snprintf(content_len, sizeof(content_len), "%zd", len);
    tlsuv_http_req_header(req, "Content-Length", content_len);

    UM_LOG(VERB, "form: %.*s", (int)len, body);
    int rc = tlsuv_http_req_data(req, body, len, free_body_cb);
    tlsuv_http_req_end(req);
    return rc;
}


ssize_t http_req_write(tlsuv_http_req_t *req, char *buf, size_t maxlen) {
    const char *pfx = "";
    if (req->client && req->client->prefix) {
        pfx = req->client->prefix;
    }

    size_t len = 0;

#define CHECK_APPEND(l, op) do { \
ssize_t a_size = op;             \
if (a_size < 0 || a_size >= maxlen - l) return UV_ENOMEM; \
l += a_size;\
} while(0)

    CHECK_APPEND(len, snprintf(buf, maxlen - len, "%s %s%s",
                               req->method, pfx, req->path));
    if (req->query) {
        CHECK_APPEND(len, snprintf(buf + len, maxlen - len, "?%s", req->query));
    }
    CHECK_APPEND(len, snprintf(buf + len, maxlen - len, " HTTP/1.1\r\n"));

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
            req->req_body_size = (ssize_t)req_len;
            char length_str[16];
            snprintf(length_str, sizeof(length_str), "%ld", req_len);
            set_http_header(&req->req_headers, "Content-Length", length_str);
        }
    }

    tlsuv_http_hdr *h;
    LIST_FOREACH(h, &req->req_headers, _next) {
        CHECK_APPEND(len, snprintf(buf + len, maxlen - len, "%s: %s\r\n", h->name, h->value));
    }

    CHECK_APPEND(len, snprintf(buf + len, maxlen - len, "\r\n"));
    return (ssize_t)len;
}

void add_http_header(um_header_list *hl, const char* name, const char *value, size_t vallen) {
    tlsuv_http_hdr *h;

    h = tlsuv__malloc(sizeof(tlsuv_http_hdr));
    h->name = tlsuv__strdup(name);
    LIST_INSERT_HEAD(hl, h, _next);

    h->value = tlsuv__strndup(value, vallen);
}

void set_http_header(um_header_list *hl, const char* name, const char *value) {
    tlsuv_http_hdr *h;
    LIST_FOREACH(h, hl, _next) {
        if (strcasecmp(h->name, name) == 0) {
            break;
        }
    }

    if (value == NULL) {
        if (h != NULL) {
            LIST_REMOVE(h, _next);
            tlsuv__free(h->value);
            tlsuv__free(h->name);
            tlsuv__free(h);
        }
        return;
    }

    if (h == NULL) {
        h = tlsuv__malloc(sizeof(tlsuv_http_hdr));
        h->name = tlsuv__strdup(name);
        LIST_INSERT_HEAD(hl, h, _next);
    } else {
        tlsuv__free(h->value);
    }

    h->value = tlsuv__strdup(value);
}

const char*tlsuv_http_resp_header(tlsuv_http_resp_t *resp, const char *name) {
    tlsuv_http_hdr *h;
    LIST_FOREACH(h, &resp->headers, _next) {
        if (strcasecmp(h->name, name) == 0) {
            return h->value;
        }
    }
    return NULL;
}

static int http_headers_complete_cb(llhttp_t *p) {
    UM_LOG(VERB, "headers complete");

    tlsuv_http_req_t *req = p->data;
    req->state = headers_received;

    const char *compression = tlsuv_http_resp_header(&req->resp, "content-encoding");
    if (compression) {
        set_http_header(&req->resp.headers, "content-length", NULL);
        set_http_header(&req->resp.headers, "transfer-encoding", "chunked");
    }
    if (req->resp_cb != NULL) {
        req->resp_cb(&req->resp, req->data);
    }
    if (compression && req->resp.body_cb) {
        req->inflater = um_get_inflater(compression, (data_cb) req->resp.body_cb, req);
    }
    return 0;
}

static int http_header_field_cb(llhttp_t *parser, const char *f, size_t len) {
    tlsuv_http_req_t *req = parser->data;
    req->resp.curr_header = tlsuv__strndup(f, len);
    return 0;
}

static int http_header_value_cb(llhttp_t *parser, const char *v, size_t len) {
    tlsuv_http_req_t *req = parser->data;

    if (len > 0) {
        if (req->resp.curr_header) {
            add_http_header(&req->resp.headers, req->resp.curr_header, v, len);
        } else {
            UM_LOG(WARN, "Invalid HTTP parsing state, received header value[%.*s] without header name", (int)len, v);
        }
    }
    if (req->resp.curr_header) tlsuv__free(req->resp.curr_header);
    req->resp.curr_header = NULL;
    return 0;
}

static int http_status_cb(llhttp_t *parser, const char *status, size_t len) {
    UM_LOG(VERB, "status = %d %.*s", parser->status_code, (int) len, status);
    tlsuv_http_req_t *r = parser->data;
    r->resp.code = (int) parser->status_code;
    snprintf(r->resp.http_version, sizeof(r->resp.http_version), "%1d.%1d", parser->http_major, parser->http_minor);
    r->resp.status = tlsuv__calloc(1, len+1);
    strncpy(r->resp.status, status, len);
    return 0;
}

static int http_message_cb(llhttp_t *parser) {
    UM_LOG(VERB, "message complete");
    tlsuv_http_req_t *r = parser->data;
    r->state = completed;
    if (r->resp.body_cb) {
        if (r->inflater == NULL || um_inflate_state(r->inflater) == 1) {
            r->resp.body_cb(r, NULL, UV_EOF);
        } else {
            UM_LOG(ERR, "incomplete decompression at the end of HTTP message");
            r->resp.body_cb(r, NULL, UV_EINVAL);
        }
    }

    return 0;
}

static int http_body_cb(llhttp_t *parser, const char *body, size_t len) {
    tlsuv_http_req_t *r = parser->data;
    if (r->inflater) {
        um_inflate(r->inflater, body, len);
    } else {
        if (r->resp.body_cb != NULL) {
            r->resp.body_cb(r, (char*)body, (ssize_t)len);
        }
    }
    return 0;
}
