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
 * @file tcp_src.h
 * @brief header file for tcp_src, which can be used as a source link in um_http requests
 *
 */

#ifndef TLSUV_TCP_SRC_H
#define TLSUV_TCP_SRC_H

#include "connector.h"
#include "src_t.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Inherits from um_http_source_t and is used to register source link for `um_http`.
 */
typedef struct tcp_src_s {
    tlsuv_SRC_FIELDS
    const tlsuv_connector_t *connector;
    tlsuv_connector_req conn_req;

    uv_tcp_t *conn;
    unsigned int keepalive;
    int nodelay:1;
} tcp_src_t;

/**
 * Initialize a `tcp_src_t` handle
 * 
 * @param l the uv loop
 * @param tl the tcp_src link to initialize
 */
int tcp_src_init(uv_loop_t *l, tcp_src_t *tl);

void tcp_src_set_connector(tcp_src_t *ts, const tlsuv_connector_t *connector);

int tcp_src_nodelay(tcp_src_t *ts, int val);

int tcp_src_keepalive(tcp_src_t *ts, int on, unsigned int val);

void tcp_src_free(tcp_src_t *ts);

#ifdef __cplusplus
}
#endif

#endif//TLSUV_TCP_SRC_H

