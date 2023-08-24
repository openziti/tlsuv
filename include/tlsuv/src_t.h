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


struct tlsuv_src_s {
    tlsuv_SRC_FIELDS
};

#ifdef __cplusplus
}
#endif

#endif//TLSUV_SRC_T_H

