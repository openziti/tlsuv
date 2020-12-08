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
 * @file um_http_src_t.h
 * @brief header file for um_http_src_t type
 *
 */

#ifndef UM_HTTP_SRC_T_H
#define UM_HTTP_SRC_T_H

#include <uv_link_t.h>

#ifdef __cplusplus
extern "C" {
#endif

// forward ref
typedef struct um_http_s um_http_t;

/**
 * Source link types
 */
typedef struct um_src_s um_src_t;

typedef void (*um_src_connect_cb)(um_src_t *sl, int status, void *connect_ctx);
typedef void (*um_src_cancel_t)(um_src_t *sl);
typedef  int (*um_src_connect_t)(um_src_t *sl, const char *host, const char *port, um_src_connect_cb cb, void *connect_ctx);
typedef void (*um_src_release_t)(um_src_t *sl);

#define UM_SRC_FIELDS                       \
    uv_link_t *link;                        \
    uv_loop_t *loop;                        \
    void *connect_ctx;                      \
    um_src_connect_t connect;          \
    um_src_connect_cb connect_cb;      \
    um_src_cancel_t cancel;            \
    um_src_release_t release;          \


typedef struct um_src_s {
    UM_SRC_FIELDS
} um_src_t;

#ifdef __cplusplus
}
#endif

#endif //UM_HTTP_SRC_T_H