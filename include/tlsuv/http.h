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

/**
 * @file um_http.h
 * @brief HTTP client header file
 *
 * @see sample/um-curl.c
 */

#ifndef TLSUV_HTTP_H
#define TLSUV_HTTP_H

#include <stdbool.h>
#include "queue.h"
#include "tls_engine.h"
#include "tcp_src.h"
#include "tls_link.h"

#include <llhttp.h>
#include <uv_link_t.h>


#ifdef __cplusplus
extern "C" {
#endif

/**
 * HTTP Header struct.
 */
typedef struct tlsuv_http_hdr_s {
    char *name;
    char *value;

    LIST_ENTRY(tlsuv_http_hdr_s) _next;
} tlsuv_http_hdr;

/**
 * List of HTTP headers
 */
typedef LIST_HEAD(hdr_list, tlsuv_http_hdr_s) um_header_list;

typedef struct tlsuv_http_resp_s tlsuv_http_resp_t;
typedef struct tlsuv_http_req_s tlsuv_http_req_t;
typedef struct tlsuv_http_s tlsuv_http_t;
typedef struct tlsuv_http_inflater_s tlsuv_http_inflater_t;
/**
 * HTTP response callback type.
 */
typedef void (*tlsuv_http_resp_cb)(tlsuv_http_resp_t *resp, void *ctx);

/**
 * HTTP body callback type.
 */
typedef void (*tlsuv_http_body_cb)(tlsuv_http_req_t *req, char *body, ssize_t len);

typedef void (*tlsuv_http_close_cb)(tlsuv_http_t *);
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
struct tlsuv_http_resp_s {
    tlsuv_http_req_t *req;

    char http_version[8];
    int code;
    char *status;

    char *curr_header;
    um_header_list headers;

    /** @brief callback called with response body data. May be called multiple times, last one with `len` of `UV_EOF` */
    tlsuv_http_body_cb body_cb;
};

/**
 * HTTP request object.
 *
 */
struct tlsuv_http_req_s {

    struct tlsuv_http_s *client;
    char *method;
    char *path;
    char *query;
    llhttp_t parser;
    enum http_request_state state;

    bool req_chunked;
    ssize_t req_body_size;
    size_t body_sent_size;
    void *req_body;
    um_header_list req_headers;

    /** @brief callback called after server has sent response headers. Called before #body_cb */
    tlsuv_http_resp_cb resp_cb;
    tlsuv_http_inflater_t *inflater;

    /*! request context */
    void *data;

    tlsuv_http_resp_t resp;

    STAILQ_ENTRY(tlsuv_http_req_s) _next;
};

/**
 * @brief HTTP client struct
 */
struct tlsuv_http_s {
    char *host;
    char port[6];
    char *prefix;
    bool host_change;

    bool ssl;
    tls_context *tls;
    tlsuv_engine_t engine;

    um_header_list headers;

    int connected;
    bool keepalive;
    tlsuv_src_t *src;
    bool own_src;

    uv_link_t http_link;
    tls_link_t tls_link;

    long connect_timeout;
    long idle_time;
    uv_timer_t *conn_timer;

    uv_async_t proc;
    tlsuv_http_req_t *active;
    STAILQ_HEAD(req_q, tlsuv_http_req_s) requests;

    void *data;
    tlsuv_http_close_cb close_cb;
};

typedef struct tlsuv_http_pair {
    const char *name;
    const char *value;
} tlsuv_http_pair;

/**
 * Initialize HTTP client
 * @param l libuv loop to execute
 * @param clt client struct
 * @param url url to initialize client with. Only scheme, host, port(optional), path(@see tlsuv_http_set_path_prefix) are used.
 * @return 0 or error code
 */
int tlsuv_http_init(uv_loop_t *l, tlsuv_http_t *clt, const char *url);

/**
 * @brief Initialize HTTP client with source link
 * 
 * Initialize HTTP client with a source link that will be used in place of TCP link source
 * 
 * @param l libuv loop to execute
 * @param clt client struct
 * @param url url to initialize client with. Only scheme, host, port(optional), path(@see tlsuv_http_set_path_prefix) are used.
 * @param src source link to be used in place of TCP
 * 
 * @return 0 or error code
 */
int tlsuv_http_init_with_src(uv_loop_t *l, tlsuv_http_t *clt, const char *url, tlsuv_src_t *src);


/**
 * change the base URL for the given client.
 *
 * Note: this call leaves current connection intact if it is established.
 * The new host/port will be used the next time connection has to be established.
 *
 * @param clt client struct
 * @param url new base URL
 */
 int tlsuv_http_set_url(tlsuv_http_t *clt, const char *url);

/**
 * @brief Set path prefix on the client.
 *
 * Any request going out after this will be re-written to prepend prefix to request path.
 * @param clt
 * @param prefix path prefix, NULL to clear it
 */

void tlsuv_http_set_path_prefix(tlsuv_http_t *clt, const char *prefix);

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
int tlsuv_http_idle_keepalive(tlsuv_http_t *clt, long millis);

/**
 * \brief Set connect timeout.
 *
 * Sets the length of time client wait for connection to be established.
 * Timeout of 0 will rely on system level timeout.
 * Note: if timeout is larger than system default it has no practical effect.
 * @param clt
 * @param millis timeout in milliseconds, use 0 to use system level TCP timeout, default is 0
 * @return 0 or error code
 */
int tlsuv_http_connect_timeout(tlsuv_http_t *clt, long millis);

/**
 * @brief Set #tls_context on the client.
 *
 * Useful if you have custom TLS context (different implementation)
 * or default TLS context configured with custom CA or client certificate.
 * This operation only makes sense if client was initialized with `https` URL.
 * @see tlsuv_http_init()
 * @see tls_context
 */
void tlsuv_http_set_ssl(tlsuv_http_t *clt, tls_context *tls);

/**
 * @brief Set a custom connector on the client.
 *
 * The connector will be used to establish connections for HTTP requests.
 * This is useful for scenarios where custom transport is needed (e.g. proxy, Ziti).
 * If a custom connector is set, the client will use the globally set connector.
 * This function must be called before any requests are made.
 *
 * @param clt the client
 * @param connector the connector to use
 */
void tlsuv_http_set_connector(tlsuv_http_t *clt, const tlsuv_connector_t *connector);

/**
 * @brief Set a header on the client.
 *
 * All requests executed by the client will get that request header.
 * Calling it multiple times with the same name will add another header with the same name.
 * Pass `value==NULL` to unset all values for the given name.
 * @param clt
 * @param name name of the header
 * @param value value
 */
void tlsuv_http_header(tlsuv_http_t *clt, const char *name, const char *value);

/**
 * close client and release all resources associate with it
 * @param clt
 * @return 0 or error code
 */
int tlsuv_http_close(tlsuv_http_t *clt, tlsuv_http_close_cb close_cb);

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
tlsuv_http_req_t *tlsuv_http_req(tlsuv_http_t *clt, const char *method, const char *path, tlsuv_http_resp_cb resp_cb, void *ctx);

/**
 * Set request header
 * @param req
 * @param name
 * @param value
 * @return o or error code
 */
int tlsuv_http_req_header(tlsuv_http_req_t *req, const char *name, const char *value);

/**
 * Write request body. Could be called multiple times. @see tlsuv_http_req_end
 * @param req
 * @param body
 * @param bodylen
 * @param cb
 * @return
 */
int tlsuv_http_req_data(tlsuv_http_req_t *req, const char *body, size_t bodylen, tlsuv_http_body_cb cb);

/**
 * Convenience method to send a form request. Can only be done once.
 * set request's `Content-Type` to `application/x-www-form-urlencoded`
 * and encodes the form values into the body of the request.
 *
 * Form size is limited to 16K encoded bytes. If that size is exceeded UV_ENOMEM is returned
 * and request is cancelled (request callback is called with appropriate error code/message)
 *
 * @param req
 * @param count number of name/value pairs
 * @param pairs name/value pairs
 * @return 0 for success, or error code
 */
int tlsuv_http_req_form(tlsuv_http_req_t *req, size_t count, const tlsuv_http_pair pairs[]);

/**
 * Convenience method to set query parameters on the given request.
 *
 * Repeated calls will override the query, i.e. only parameters from the last call will be preserved.
 * Call with `count=0` or `params=NULL` to clear previously set parameters
 *
 * @param req
 * @param count number of name/value pairs
 * @param params name/value pairs
 * @return 0 for success, or error code
 */
int tlsuv_http_req_query(tlsuv_http_req_t *req, size_t count, const tlsuv_http_pair params[]);

/**
 * Indicate the end of the request body. Only needed if `Transfer-Encoding` header was set to `chunked`
 * @param req
 */
void tlsuv_http_req_end(tlsuv_http_req_t *req);

/**
 * Cancels provided request
 * @param clt client
 * @param req request to be cancelled
 * @return 0, or error code
 */
int tlsuv_http_req_cancel(tlsuv_http_t *clt, tlsuv_http_req_t *req);

/**
 * Cancels all (active and queued) requests for the given client.
 * All pending requests would have their callbacks called with cancellation code.
 * If there is an active request, either resp_cb or body_cb (depending on the state) will be called with cancellation code.
 *
 * @param clt client
 * @return
 */
int tlsuv_http_cancel_all(tlsuv_http_t *clt);

/**
 * @brief return response header
 * @param resp HTTP response
 * @param name header name
 * @return value of the header or NULL
 */
const char *tlsuv_http_resp_header(tlsuv_http_resp_t *resp, const char *name);

/**
 * parsed URL
 */
struct tlsuv_url_s {
    const char *scheme;
    size_t scheme_len;
    const char *username;
    size_t username_len;
    const char *password;
    size_t password_len;
    const char *hostname;
    size_t hostname_len;
    uint16_t port;
    const char *path;
    size_t path_len;
    const char *query;
    size_t query_len;
};

/**
 * Zero-copy URL parser. [url] fields point to the parsed [urlstr].
 * @param url parsed URL structure
 * @param urlstr URL in string form
 * @return 0 on success, -1 on failure
 */
int tlsuv_parse_url(struct tlsuv_url_s *url, const char *urlstr);

#ifdef __cplusplus
}
#endif

#endif//TLSUV_HTTP_H
