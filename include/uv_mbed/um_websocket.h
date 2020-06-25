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

#ifndef UV_MBED_UM_WEBSOCKET_H
#define UV_MBED_UM_WEBSOCKET_H

#include <uv.h>
#include <uv/unix.h>
#include "um_http.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct um_websocket_s um_websocket_t;

/**
 * @brief Websocket object.
 */
struct um_websocket_s {
    UV_HANDLE_FIELDS

    uv_read_cb read_cb;

    um_http_req_t *req;

    char *host;

    uv_connect_t *conn_req;

    um_http_src_t *src;
    tcp_src_t default_src;

    uv_link_t ws_link;
    tls_link_t tls_link;
    tls_context *tls;
};

/**
 * @brief Initialize websocket
 * @param loop loop for execution
 * @param ws websocket object
 * @return error code
 */
int um_websocket_init(uv_loop_t *loop, um_websocket_t *ws);

/**
 * @brief set #tls_context on the client.
 * @param ws websocket
 * @param ctx TLS context to use for `wss://` connection
 */
void um_websocket_set_tls(um_websocket_t *ws, tls_context *ctx);

/**
 * @brief set additional headers for initial websocket request
 * @param ws websocket
 * @param name header name
 * @param value header value
 */
void um_websocket_set_header(um_websocket_t *ws, const char *name, const char *value);

/**
 * @brief Connect websocket to a service with given URL
 * @param req connect request
 * @param ws websocket
 * @param url address of the websocket server
 * @param conn_cb callback called after websocket is connected, or failed to connect
 * @param data_cb callback called when data is received from the server
 * @return error code
 */
int um_websocket_connect(uv_connect_t *req, um_websocket_t *ws, const char *url, uv_connect_cb conn_cb, uv_read_cb data_cb);

/**
 * @brief write data to websocket
 * @param req write request
 * @param ws websocket
 * @param buf data
 * @param cb callback called after write operation is completed or failed
 * @return error code
 */
int um_websocket_write(uv_write_t *req, um_websocket_t *ws, uv_buf_t *buf, uv_write_cb cb);

/**
 * @brief close websocket
 * @param ws websocket
 * @param cb callback called after close operation completes
 * @return error code
 */
int um_websocket_close(um_websocket_t *ws, uv_close_cb cb);

#ifdef __cplusplus
}
#endif

#endif //UV_MBED_UM_WEBSOCKET_H
