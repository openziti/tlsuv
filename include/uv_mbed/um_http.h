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


#ifndef UV_MBED_UM_HTTP_H
#define UV_MBED_UM_HTTP_H

#include <http_parser.h>
#include <uv_link_t.h>

#include <stdbool.h>
#include "queue.h"
#include "tls_engine.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct um_http_hdr_s {
    char *name;
    char *value;

    LIST_ENTRY(um_http_hdr_s) _next;
} um_http_hdr;

typedef LIST_HEAD(hdr_list, um_http_hdr_s) um_header_list;

typedef struct um_http_req_s um_http_req_t;

typedef void (*um_http_resp_cb)(um_http_req_t *req, int http_code, um_header_list *headers);

typedef void (*um_http_body_cb)(um_http_req_t *req, const char *body, ssize_t len);

enum http_request_state {
    created,
    headers_sent,
    body_sent,
    headers_received,
    completed
};
typedef struct um_http_req_s {

    struct um_http_s *client;
    char *method;
    char *path;
    http_parser response;
    enum http_request_state state;

    bool req_chunked;
    ssize_t req_size;
    void *req_body;
    um_header_list req_headers;
    um_header_list resp_headers;

    um_http_resp_cb resp_cb;
    um_http_body_cb body_cb;

    void *data;

    STAILQ_ENTRY(um_http_req_s) _next;
} um_http_req_t;

typedef struct um_http_s {
    char *host;
    char port[6];

    bool ssl;
    tls_context *tls;
    tls_engine *engine;

    um_header_list headers;

    bool connected;
    uv_tcp_t conn;
    uv_link_source_t conn_src;
    uv_link_t http_link;
    uv_link_t *tls_link;

    uv_async_t proc;
    um_http_req_t *active;
    STAILQ_HEAD(req_q, um_http_req_s) requests;
} um_http_t;


int um_http_init(uv_loop_t *l, um_http_t *clt, const char *url);

void um_http_header(um_http_t *clt, const char *name, const char *value);

int um_http_close(um_http_t *l);


um_http_req_t *um_http_req(um_http_t *clt, const char *method, const char *path);

int um_http_req_header(um_http_req_t *req, const char *name, const char *value);

int um_http_req_data(um_http_req_t *req, const char *body, ssize_t bodylen, um_http_body_cb cb);
void um_http_req_end(um_http_req_t *req);

#ifdef __cplusplus
}
#endif

#endif //UV_MBED_UM_HTTP_H
