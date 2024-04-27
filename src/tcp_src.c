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

#include "tlsuv/tcp_src.h"
#include "tlsuv/http.h"
#include "um_debug.h"

// connect and release method for um_http custom source link
static int tcp_src_connect(tlsuv_src_t *sl, const char *host, const char *service, tlsuv_src_connect_cb cb, void *ctx);
static void tcp_src_release(tlsuv_src_t *sl);
static void tcp_src_cancel(tlsuv_src_t *sl);

static void free_handle(uv_handle_t *h);

int tcp_src_init(uv_loop_t *l, tcp_src_t *tl) {
    tl->loop = l;
    tl->link = calloc(1, sizeof(uv_link_source_t));
    tl->conn = NULL;
    tl->connector = tlsuv_global_connector();
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

static void on_connect(uv_os_sock_t s, int status, void *ctx) {
    tcp_src_t *tcp = ctx;
    tcp->conn_req = NULL;

    if (status == 0) {
        tcp->conn = calloc(1, sizeof(*tcp->conn));
        uv_tcp_init(tcp->loop, tcp->conn);
        uv_tcp_open(tcp->conn, s);
        tcp_src_nodelay(tcp, tcp->nodelay);
        tcp_src_keepalive(tcp, tcp->keepalive != 0, tcp->keepalive);

        uv_link_source_init((uv_link_source_t *) tcp->link, (uv_stream_t *) tcp->conn);
        tcp->link->data = tcp;
    }

    tcp->connect_cb((tlsuv_src_t *) tcp, status, tcp->connect_ctx);
}

/*
static void tcp_connect_cb(uv_connect_t *req, int status) {
    tcp_src_t *sl = req->data;

    if (sl == NULL) {
        UM_LOG(TRACE, "connect requests was cancelled");
        if (!uv_is_closing((const uv_handle_t *) req->handle))
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

    sl->connect_cb((tlsuv_src_t *)sl, status, sl->connect_ctx);
    free(req);
}

static void resolve_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addr) {
    tcp_src_t *sl = req->data;

    if (sl != NULL) {
        sl->resolve_req = NULL;
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
            if (sl->conn_req) {
                free(sl->conn_req);
                sl->conn_req = NULL;
                if (conn) {
                    uv_close((uv_handle_t *) conn, free_handle);
                }
            }
            sl->connect_cb((tlsuv_src_t *) sl, status, sl->connect_ctx);
        }
    }

    uv_freeaddrinfo(addr);
    free(req);
}
 */

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

static int tcp_src_connect(tlsuv_src_t *sl, const char* host, const char *service, tlsuv_src_connect_cb cb, void *ctx) {
    tcp_src_t *tcp = (tcp_src_t *) sl;

    sl->connect_cb = cb;
    sl->connect_ctx = ctx;

    if (tcp->conn) {
        if (!uv_is_closing((const uv_handle_t *) tcp->conn)) {
            tcp->link->methods->close(tcp->link, tcp->link, link_close_cb);
        } else {
            tcp->conn = NULL;
        }
    }
    tcp->conn_req = tcp->connector->connect(tcp->loop, tcp->connector, host, service, on_connect, tcp);

    return 0;
}

static void tcp_src_cancel(tlsuv_src_t *sl) {
    tcp_src_t *tl = (tcp_src_t*)sl;
    uv_link_source_t *ts = (uv_link_source_t *) tl->link;

    if (tl->conn_req) {
        tl->connector->cancel(tl->conn_req);
    }

    if (tl->conn && !uv_is_closing((const uv_handle_t *) tl->conn)) {
        ts->methods->close((uv_link_t *) ts, (uv_link_t *) ts, link_close_cb);
    }
}

static void tcp_src_release(tlsuv_src_t *sl) {
    tcp_src_t *tcp = (tcp_src_t *) sl;

    free(tcp->conn);
    tcp->conn = NULL;
}
