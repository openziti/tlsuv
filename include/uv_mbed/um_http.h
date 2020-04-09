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

/**
 * @file um_http.h
 * @brief HTTP client header file
 *
 * @see sample/um-curl.c
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

/**
 * HTTP Header struct.
 */
typedef struct um_http_hdr_s {
    char *name;
    char *value;

    LIST_ENTRY(um_http_hdr_s) _next;
} um_http_hdr;

/**
 * List of HTTP headers
 */
typedef LIST_HEAD(hdr_list, um_http_hdr_s) um_header_list;

typedef struct um_http_resp_s um_http_resp_t;
typedef struct um_http_req_s um_http_req_t;

/**
 * HTTP response callback type.
 */
typedef void (*um_http_resp_cb)(um_http_resp_t *resp, void *ctx);

/**
 * HTTP body callback type.
 */
typedef void (*um_http_body_cb)(um_http_req_t *req, const char *body, ssize_t len);

/**
 * @brief State of HTTP request.
 */
typedef enum http_request_state {
    created,
    headers_sent,
    body_sent,
    headers_received,
    completed
} http_request_state;

/**
 * @brief HTTP responce object passed into #um_http_resp_cb.
 */
typedef struct um_http_resp_s {
    um_http_req_t *req;

    char http_version[4];
    int code;
    char *status;

    int nh;
    um_http_hdr *headers;

    /** @brief callback called with response body data. May be called multiple times, last one with `len` of `UV_EOF` */
    um_http_body_cb body_cb;
} um_http_resp_t;

/**
 * HTTP request object.
 *
 */
typedef struct um_http_req_s {

    struct um_http_s *client;
    char *method;
    char *path;
    http_parser parser;
    enum http_request_state state;

    bool req_chunked;
    ssize_t req_size;
    void *req_body;
    um_header_list req_headers;

    /** @brief callback called after server has sent response headers. Called before #body_cb */
    um_http_resp_cb resp_cb;

    /*! request context */
    void *data;

    um_http_resp_t resp;

    STAILQ_ENTRY(um_http_req_s) _next;
} um_http_req_t;

/**
 * @brief HTTP client struct
 */
typedef struct um_http_s {
    char *host;
    char port[6];

    bool ssl;
    tls_context *tls;
    tls_engine *engine;

    um_header_list headers;

    int connected;
    uv_tcp_t conn;
    uv_link_source_t conn_src;
    uv_link_t http_link;
    uv_link_t tls_link;

    long idle_time;
    uv_timer_t idle_timer;

    uv_async_t proc;
    um_http_req_t *active;
    STAILQ_HEAD(req_q, um_http_req_s) requests;
} um_http_t;

/**
 * Initialize HTTP client
 * @param l libuv loop to execute
 * @param clt client struct
 * @param url url to initialize client with. Only scheme, host, port(optional) are used.
 * @return 0 or error code
 */
int um_http_init(uv_loop_t *l, um_http_t *clt, const char *url);

/**
 * \brief Set idle timeout.
 *
 * Sets the length of time client will keep connection open after the last request was processed.
 * Timeout of 0 will cause connection to be closed as soon as the last request in the queue is completed,
 * client will re-establish connection for any consequent requests.
 * Note: this only controls client side of the connection, server side may close it at any time before timeout expires.
 * @param clt
 * @param millis timeout in milliseconds, use -1 to defer to server side closing connection, default is 0
 * @return 0 or error code
 */
int um_http_idle_keepalive(um_http_t *clt, long millis);

/**
 * @brief Set #tls_context on the client.
 *
 * Useful if you have custom TLS context (different implementation)
 * or default TLS context configured with custom CA or client certificate.
 * This operation only makes sense if client was initialized with `https` URL.
 * @see um_http_init()
 * @see tls_context
 */
void um_http_set_ssl(um_http_t *clt, tls_context *tls);

/**
 * \brief Set header on the client.
 *
 * All requests execute by the client will get that request header. Pass `value==NULL` to unset the header.
 * @param clt
 * @param name name of the header
 * @param value value
 */
void um_http_header(um_http_t *clt, const char *name, const char *value);

/**
 * close client and release all resources associate with it
 * @param l
 * @return 0 or error code
 */
int um_http_close(um_http_t *l);

/**
 * Create HTTP request with givan client and queue it for execution.
 * Request lifecycle is managed by the client.
 * @param clt HTTP client
 * @param method HTTP method
 * @param path request URI (including query)
 * @param resp_cb callback called after server has sent response headers.
 * @param ctx arbitrary data passed back in #resp_cb
 * @return request that should be modified by setting callbacks, headers, etc
 */
um_http_req_t *um_http_req(um_http_t *clt, const char *method, const char *path, um_http_resp_cb resp_cb, void *ctx);

/**
 * Set request header
 * @param req
 * @param name
 * @param value
 * @return o or error code
 */
int um_http_req_header(um_http_req_t *req, const char *name, const char *value);

/**
 * Write request body. Could be called multiple times. @see um_http_req_end
 * @param req
 * @param body
 * @param bodylen
 * @param cb
 * @return
 */
int um_http_req_data(um_http_req_t *req, const char *body, ssize_t bodylen, um_http_body_cb cb);

/**
 * Indicate the end of the request body. Only needed if `Transfer-Encoding` header was set to `chunked`
 * @param req
 */
void um_http_req_end(um_http_req_t *req);

#ifdef __cplusplus
}
#endif

#endif //UV_MBED_UM_HTTP_H
