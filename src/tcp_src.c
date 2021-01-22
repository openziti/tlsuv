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
static int tcp_src_connect(um_src_t *sl, const char *host, const char *service, um_src_connect_cb cb, void *ctx);
static void tcp_src_release(um_src_t *sl);
static void tcp_src_cancel(um_src_t *sl);

int tcp_src_init(uv_loop_t *l, tcp_src_t *tl) {
    tl->loop = l;
    tl->link = calloc(1, sizeof(uv_link_source_t));
    tl->conn = NULL;
    tl->connect = tcp_src_connect;
    tl->connect_cb = NULL;
    tl->release = tcp_src_release;
    tl->cancel = tcp_src_cancel;
    tl->keepalive = 0;
    tl->nodelay = 0;
    return 0;
}

int tcp_src_nodelay(tcp_src_t *ts, int val) {
    ts->nodelay = val;
    if (ts->conn)
        return uv_tcp_nodelay(ts->conn, val);
    return 0;
}

int tcp_src_keepalive(tcp_src_t *ts, int on, unsigned int val) {
    ts->keepalive = on ? val : 0;
    return ts->conn ? uv_tcp_keepalive(ts->conn, on, val) : 0;
}

static void tcp_connect_cb(uv_connect_t *req, int status) {
    tcp_src_t *sl = req->data;

    // old request
    if (req->handle != (uv_stream_t *)sl->conn) {
        free(req);
        return;
    }

    UM_LOG(ERR, "connected status = %d(%p)", status, req->handle);
    if (status == 0) {
        uv_link_source_init((uv_link_source_t *) sl->link, (uv_stream_t *) sl->conn);
        uv_tcp_nodelay(sl->conn, sl->nodelay);
        uv_tcp_keepalive(sl->conn, sl->keepalive > 0, sl->keepalive);
    } else {
        UM_LOG(ERR, "failed to connect: %d(%s)", status, uv_strerror(status));
    }

    sl->connect_cb((um_src_t *)sl, status, sl->connect_ctx);
    free(req);
}

static void resolve_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addr) {
    tcp_src_t *sl = req->data;
    uv_connect_t *conn_req = NULL;

    UM_LOG(TRACE, "resolved status = %d", status);
    if (status == 0) {
        sl->conn = calloc(1, sizeof(uv_tcp_t));
        status = uv_tcp_init_ex(req->loop, sl->conn, addr->ai_family);
    }

    if (status == 0) {
        conn_req = calloc(1, sizeof(uv_connect_t));
        conn_req->data = sl;
        status = uv_tcp_connect(conn_req, sl->conn, addr->ai_addr, tcp_connect_cb);
    }

    if (status != 0) {
        UM_LOG(ERR, "connect failed: %d(%s)", status, uv_strerror(status));
        sl->connect_cb((um_src_t *)sl, status, sl->connect_ctx);
        if (conn_req)
            free(conn_req);
    }

    uv_freeaddrinfo(addr);
    free(req);
}

static int tcp_src_connect(um_src_t *sl, const char* host, const char *service, um_src_connect_cb cb, void *ctx) {
    tcp_src_t *tcp = (tcp_src_t *) sl;

    sl->connect_cb = cb;
    sl->connect_ctx = ctx;

    if (tcp->conn) {
        UM_LOG(WARN, "old handle present");
        uv_tcp_close_reset(tcp->conn, (uv_close_cb) free);
        tcp->conn = NULL;
    }

    uv_getaddrinfo_t *resolv_req = calloc(1, sizeof(uv_getaddrinfo_t));
    resolv_req->data = sl;

    int rc = uv_getaddrinfo(sl->loop, resolv_req, resolve_cb, host, service, NULL);
    if (rc != 0) {
        free(resolv_req);
    }
    return rc;
}

static void tcp_src_cancel(um_src_t *sl) {
    tcp_src_t *tl = (tcp_src_t*)sl;
    if (tl->conn) {
        uv_tcp_close_reset(tl->conn, (uv_close_cb) free);
        tl->conn = NULL;
    }
}

static void tcp_src_release(um_src_t *sl) {
    tcp_src_cancel(sl);
    free(sl->link);
    sl->link = NULL;
}
