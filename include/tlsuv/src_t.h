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
 * @file src_t.h
 * @brief header file for tlsuv_src_t type
 *
 */

#ifndef TLSUV_SRC_T_H
#define TLSUV_SRC_T_H

#include <uv_link_t.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Source link types
 */
typedef struct tlsuv_src_s tlsuv_src_t;

typedef void (*tlsuv_src_connect_cb)(tlsuv_src_t *sl, int status, void *connect_ctx);
typedef void (*tlsuv_src_cancel_t)(tlsuv_src_t *sl);
typedef  int (*tlsuv_src_connect_t)(tlsuv_src_t *sl, const char *host, const char *port, tlsuv_src_connect_cb cb, void *connect_ctx);
typedef void (*tlsuv_src_release_t)(tlsuv_src_t *sl);

#define tlsuv_SRC_FIELDS             \
    uv_link_t *link;                 \
    uv_loop_t *loop;                 \
    void *connect_ctx;               \
    tlsuv_src_connect_t connect;     \
    tlsuv_src_connect_cb connect_cb; \
    tlsuv_src_cancel_t cancel;       \
    tlsuv_src_release_t release;


/**
 * A source provides the connected byte stream a client (tlsuv_http_t, tlsuv_websocket_t) runs on, instead of
 * the client connecting by itself. The client chains its TLS link (if the URL needs one) and its protocol link
 * onto `link`.
 *
 * The source sets `link`, `connect`, `cancel` and `release`; tlsuv calls the three functions without a NULL check.
 * `loop`, `connect_cb` and `connect_ctx` are the source's own: tlsuv does not read them (connect() typically
 * saves its `cb` and `ctx` arguments in the last two).
 *
 * connect(src, host, port, cb, ctx)
 *   Start connecting to host:port, as given in the URL. The HTTP client calls it every time it has to (re)connect,
 *   always on the same source; the websocket client calls it once.
 *   Report the outcome with cb(src, status, ctx): 0 when `link` is ready (initialized, with nothing chained to it),
 *   negative on failure. cb may run before connect() returns.
 *   Alternatively connect() may fail by returning non-zero, without calling cb: the HTTP client then fails its
 *   requests with that code, the websocket client returns it from tlsuv_websocket_connect() and does not call
 *   its connect callback.
 *   tlsuv does not call cancel or release for a failed connect; the source cleans up after itself.
 *
 * link
 *   The client closes its connection with uv_link_close() on the last link of its chain, which closes `link` too
 *   (its close method runs; tlsuv does not use `link` afterwards). That can happen inside the source's own read
 *   callback. For the next connection the source provides a usable `link` again.
 *
 * cancel(src)
 *   The HTTP client calls it when its connect timeout expired (the requests have been failed already), and again
 *   when the connect completes after that, so it may run twice for one connect.
 *   The websocket client calls it when the websocket is closed, once per close, after its links were closed.
 *   That includes a websocket whose connect failed.
 *   The source should drop the connection and not report an abandoned connect through cb afterwards.
 *
 * release(src)
 *   HTTP client only: one connection of the client was closed (for whatever reason, tlsuv_http_close() included)
 *   and its links, `link` among them, are closed. The client carries on with the same source and may call
 *   connect() again, so release does not mean the source is no longer needed. It is not called for a connection
 *   that was never made. The websocket client never calls it.
 *
 * tlsuv_http_close() and tlsuv_websocket_close() do not free the source: it belongs to the application.
 */
struct tlsuv_src_s {
    tlsuv_SRC_FIELDS
};

#ifdef __cplusplus
}
#endif

#endif//TLSUV_SRC_T_H

