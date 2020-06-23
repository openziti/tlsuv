/*
Copyright 2019 Netfoundry, Inc.

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

//
// Created by eugene on 6/12/20.
//

#ifndef UV_MBED_UM_WEBSOCKET_H
#define UV_MBED_UM_WEBSOCKET_H

#include <uv.h>
#include <uv/unix.h>
#include "um_http.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct um_websocket_s um_websocket_t;


struct um_websocket_s {
    UV_HANDLE_FIELDS

    uv_read_cb read_cb;

    um_http_req_t *req;

    char *host;

    int connected;
    uv_connect_t *conn_req;

    um_http_src_t *src;
    tcp_src_t default_src;

    uv_link_t ws_link;
    tls_link_t tls_link;
    tls_context *tls;
};


int um_websocket_init(uv_loop_t *loop, um_websocket_t *ws);
void um_websocket_set_tls(um_websocket_t *ws, tls_context *ctx);
void um_websocket_set_header(um_websocket_t *ws, const char *name, const char *value);
int um_websocket_connect(uv_connect_t *req, um_websocket_t *ws, const char *url, uv_connect_cb, uv_read_cb);
int um_websocket_write(uv_write_t *req, um_websocket_t *ws, uv_buf_t *buf, uv_write_cb);
int um_websocket_close(um_websocket_t *ws, uv_close_cb);

#ifdef __cplusplus
}


#endif

#endif //UV_MBED_UM_WEBSOCKET_H
