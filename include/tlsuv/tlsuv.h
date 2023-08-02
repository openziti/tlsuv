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

#ifndef TLSUV_H
#define TLSUV_H

#include <uv.h>
#include <uv_link_t.h>

#include "tcp_src.h"
#include "tls_engine.h"
#include "tls_link.h"

#ifdef __cplusplus
extern "C" {
#endif

const char* tlsuv_version();

typedef struct tlsuv_stream_s tlsuv_stream_t;

typedef void(*tlsuv_log_func)(int level, const char *file, unsigned int line, const char *msg);
void tlsuv_set_debug(int level, tlsuv_log_func output_f);

int tlsuv_stream_init(uv_loop_t *l, tlsuv_stream_t *clt, tls_context *tls);
int tlsuv_stream_keepalive(tlsuv_stream_t *clt, int keepalive, unsigned int delay);
int tlsuv_stream_nodelay(tlsuv_stream_t *clt, int nodelay);

int tlsuv_stream_connect(uv_connect_t *req, tlsuv_stream_t *clt, const char *host, int port, uv_connect_cb cb);

int tlsuv_stream_connect_addr(uv_connect_t *req, tlsuv_stream_t *clt, const struct addrinfo *addr, uv_connect_cb cb);

int tlsuv_stream_read(tlsuv_stream_t *clt, uv_alloc_cb, uv_read_cb);

int tlsuv_stream_write(uv_write_t *req, tlsuv_stream_t *clt, uv_buf_t *buf, uv_write_cb cb);

int tlsuv_stream_close(tlsuv_stream_t *clt, uv_close_cb close_cb);

int tlsuv_stream_free(tlsuv_stream_t *clt);

struct tlsuv_stream_s {
    UV_LINK_FIELDS

    uv_loop_t *loop;
    tcp_src_t *socket;
    tls_link_t tls_link;

    tls_context *tls;
    tlsuv_engine_t tls_engine;

    char *host;
    uv_connect_t *conn_req; //a place to stash a connection request
    uv_close_cb close_cb;
};

size_t tlsuv_base64url_decode(const char *in, char **out, size_t *out_len);
#ifdef __cplusplus
}
#endif

#endif//TLSUV_H
