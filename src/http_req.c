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
    r->method = strdup(method);
    r->path = strdup(path);
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
        free(req->resp.status);
    }
    if (req->inflater) {
        um_free_inflater(req->inflater);
    }
    free(req->path);
    free(req->method);
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
    free(hdr->name);
    free(hdr->value);
}

void free_hdr_list(um_header_list *l) {
    tlsuv_http_hdr *h;
    while (!LIST_EMPTY(l)) {
        h = LIST_FIRST(l);
        LIST_REMOVE(h, _next);

        free_hdr(h);
        free(h);
    }
}

#define HEXIFY(c) (((c) < 10) ? '0' + (c) : 'A' + (c) - 10)

static size_t write_url_encoded(char *buf, const char *url) {
    static char unsafe[] = "\"<>%{}|\\^`";
    char *p = buf;
    for(; *url != 0; url++) {
        if (*url <= ' ' || strchr(unsafe, *url) != NULL) {
            *p++ = '%';
            *p++ = HEXIFY((*url >> 4) & 0xf);
            *p++ = HEXIFY(*url & 0xf);
        } else {
            *p++ = *url;
        }
    }
    return p - buf;
}

size_t http_req_write(tlsuv_http_req_t *req, char *buf, size_t maxlen) {
    const char *pfx = "";
    if (req->client && req->client->prefix) {
        pfx = req->client->prefix;
    }

    size_t len = 0;
    len += snprintf(buf, maxlen, "%s ", req->method);
    len += write_url_encoded(buf + len, pfx);
    len += write_url_encoded(buf + len, req->path);
    len += snprintf(buf + len, maxlen - len, " HTTP/1.1\r\n");


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
            snprintf(length_str, sizeof(length_str), "%ld", req_len);
            set_http_header(&req->req_headers, "Content-Length", length_str);
        }
    }

    tlsuv_http_hdr *h;
    LIST_FOREACH(h, &req->req_headers, _next) {
        len += snprintf(buf + len, maxlen - len, "%s: %s\r\n", h->name, h->value);
    }

    len += snprintf(buf + len, maxlen - len, "\r\n");
    return len;
}

void add_http_header(um_header_list *hl, const char* name, const char *value, size_t vallen) {
    tlsuv_http_hdr *h;

    h = malloc(sizeof(tlsuv_http_hdr));
    h->name = strdup(name);
    LIST_INSERT_HEAD(hl, h, _next);

    h->value = strndup(value, vallen);
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
            free(h->value);
            free(h->name);
            free(h);
        }
        return;
    }

    if (h == NULL) {
        h = malloc(sizeof(tlsuv_http_hdr));
        h->name = strdup(name);
        LIST_INSERT_HEAD(hl, h, _next);
    } else {
        free(h->value);
    }

    h->value = strdup(value);
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
    req->resp.curr_header = strndup(f, len);
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
    if (req->resp.curr_header) free(req->resp.curr_header);
    req->resp.curr_header = NULL;
    return 0;
}

static int http_status_cb(llhttp_t *parser, const char *status, size_t len) {
    UM_LOG(VERB, "status = %d %.*s", parser->status_code, (int) len, status);
    tlsuv_http_req_t *r = parser->data;
    r->resp.code = (int) parser->status_code;
    snprintf(r->resp.http_version, sizeof(r->resp.http_version), "%1d.%1d", parser->http_major, parser->http_minor);
    r->resp.status = calloc(1, len+1);
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
            r->resp.body_cb(r, body, len);
        }
    }
    return 0;
}
