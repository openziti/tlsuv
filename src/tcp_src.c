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

#include "uv_mbed/um_http.h"
#include "uv_mbed/tcp_src.h"
#include "um_debug.h"

// connect and release method for um_http custom source link
static int tcp_src_connect(um_http_src_t *sl, um_http_src_connect_cb cb);
static void tcp_src_release(um_http_src_t *sl);

int tcp_src_init(uv_loop_t *l, tcp_src_t *tl) {
    tl->loop = l;
    tl->clt = NULL;
    tl->link = malloc(sizeof(uv_link_source_t));
    tl->connect = tcp_src_connect;
    tl->connect_cb = NULL;
    tl->release = tcp_src_release;

    return 0;
}

static void tcp_connect_cb(uv_connect_t *req, int status) {
    tcp_src_t *sl = req->data;

    UM_LOG(VERB, "connected status = %d", status);
    if (status == 0) {
        uv_link_source_init((uv_link_source_t *)sl->link, (uv_stream_t *) &sl->conn);
    }
    
    sl->connect_cb((um_http_src_t *)sl, status);
    free(req);
}

static void resolve_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addr) {
    tcp_src_t *sl = req->data;

    UM_LOG(VERB, "resolved status = %d", status);
    if (status == 0) {
        uv_connect_t *conn_req = malloc(sizeof(uv_connect_t));
        conn_req->data = sl;
        uv_tcp_init(sl->loop, &sl->conn);
        uv_tcp_connect(conn_req, &sl->conn, addr->ai_addr, tcp_connect_cb);
        uv_freeaddrinfo(addr);
    } else {
        sl->connect_cb((um_http_src_t *)sl, status);
    }
    free(req);
}

static int tcp_src_connect(um_http_src_t *sl, um_http_src_connect_cb cb) {
    uv_getaddrinfo_t *resolv_req = malloc(sizeof(uv_getaddrinfo_t));

    sl->connect_cb = cb;
    resolv_req->data = sl;
    uv_getaddrinfo(sl->loop, resolv_req, resolve_cb, sl->clt->host, sl->clt->port, NULL);

    return 0;
}

static void tcp_src_release(um_http_src_t *sl) {
    free(sl->link);
}
