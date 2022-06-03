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

static void free_handle(uv_handle_t *h);

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

void tcp_src_free(tcp_src_t *ts) {
    if (ts) {
        free(ts->link);
        ts->link = NULL;
    }
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

    if (sl == NULL) {
        UM_LOG(TRACE, "connect requests was cancelled");
        uv_close((uv_handle_t *) req->handle, free_handle);
        free(req);
        return;
    }

    sl->conn_req = NULL;
    if (status == UV_ECANCELED) {
        UM_LOG(TRACE, "connect was cancelled: handle(%p) closing(%d)", req->handle, uv_is_closing((const uv_handle_t *) req->handle));
        uv_close((uv_handle_t *) req->handle, free_handle);
        free(req);
        return;
    }

    if (status == 0) {
        sl->conn = (uv_tcp_t *)req->handle;
        uv_tcp_nodelay(sl->conn, 1);
        uv_tcp_keepalive(sl->conn, sl->keepalive > 0, sl->keepalive);

        uv_link_source_init((uv_link_source_t *) sl->link, (uv_stream_t *) sl->conn);
        sl->link->data = sl;
    } else {
        UM_LOG(ERR, "failed to connect: %d(%s)", status, uv_strerror(status));
        sl->conn = NULL;
        uv_close((uv_handle_t *) req->handle, free_handle);
    }

    sl->connect_cb((um_src_t *)sl, status, sl->connect_ctx);
    free(req);
}

static void resolve_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addr) {
    tcp_src_t *sl = req->data;

    if (sl != NULL) {
        UM_LOG(TRACE, "resolved status = %d", status);
        uv_tcp_t *conn = NULL;
        if (status == 0) {
            conn = calloc(1, sizeof(uv_tcp_t));
            status = uv_tcp_init_ex(req->loop, conn, addr->ai_family);
        }

        if (status == 0) {
            sl->conn_req = calloc(1, sizeof(uv_connect_t));
            sl->conn_req->data = sl;
            status = uv_tcp_connect(sl->conn_req, conn, addr->ai_addr, tcp_connect_cb);
        }

        if (status != 0) {
            UM_LOG(ERR, "connect failed: %d(%s)", status, uv_strerror(status));
            sl->connect_cb((um_src_t *) sl, status, sl->connect_ctx);
            if (sl->conn_req) {
                free(sl->conn_req);
                sl->conn_req = NULL;
                if (conn) {
                    uv_close((uv_handle_t *) conn, free_handle);
                }
            }
        }

        sl->resolve_req = NULL;
    }

    uv_freeaddrinfo(addr);
    free(req);
}

static void free_handle(uv_handle_t *h) {
    free(h);
}

static void link_close_cb(uv_link_t *l) {
    tcp_src_t *tcp = l->data;
    if (tcp->conn) {
        free_handle((uv_handle_t *) tcp->conn);
        tcp->conn = NULL;
    }
}

static int tcp_src_connect(um_src_t *sl, const char* host, const char *service, um_src_connect_cb cb, void *ctx) {
    tcp_src_t *tcp = (tcp_src_t *) sl;

    sl->connect_cb = cb;
    sl->connect_ctx = ctx;

    if (tcp->conn) {
        tcp->link->methods->close(tcp->link, tcp->link, link_close_cb);
        tcp->conn = NULL;
    }

    tcp->resolve_req = calloc(1, sizeof(uv_getaddrinfo_t));
    tcp->resolve_req->data = tcp;

    UM_LOG(DEBG, "resolving '%s:%s'", host, service);
    int rc = uv_getaddrinfo(sl->loop, tcp->resolve_req, resolve_cb, host, service, NULL);

    if (rc != 0) {
        free(tcp->resolve_req);
        tcp->resolve_req = NULL;
    }
    return rc;
}

static void tcp_src_cancel(um_src_t *sl) {
    tcp_src_t *tl = (tcp_src_t*)sl;
    uv_link_source_t *ts = (uv_link_source_t *) tl->link;

    if (tl->resolve_req) {
        tl->resolve_req->data = NULL;
        tl->resolve_req = NULL;
    }

    if (tl->conn_req) {
        tl->conn_req->data = NULL;
        tl->conn_req = NULL;
    }

    if (tl->conn && !uv_is_closing(tl->conn)) {
        ts->methods->close(ts, ts, link_close_cb);
    }
}

static void tcp_src_release(um_src_t *sl) {
    tcp_src_t *tcp = sl;

    free(tcp->conn);
    tcp->conn = NULL;
}
