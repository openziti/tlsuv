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

#include "tlsuv/tlsuv.h"
#include "um_debug.h"
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#if _WIN32
#include "win32_compat.h"
#endif

#define to_str1(s) #s
#define to_str(s) to_str1(s)

#ifdef TLSUV_VERSION
#define TLSUV_VERS to_str(TLSUV_VERSION)
#else
#define TLSUV_VERS "<unknown>"
#endif

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str);
static void tcp_connect_cb(uv_connect_t* req, int status);
static int mbed_ssl_send(void* ctx, const uint8_t *buf, size_t len);

static const uv_link_methods_t mbed_methods = {
        .close = uv_link_default_close,
        .read_start = uv_link_default_read_start,
        .write = uv_link_default_write,
        .alloc_cb_override = uv_link_default_alloc_cb_override,
        .read_cb_override = uv_link_default_read_cb_override,
};

static tls_context *DEFAULT_TLS = NULL;

static void free_default_tls() {
    if (DEFAULT_TLS) {
        DEFAULT_TLS->api->free_ctx(DEFAULT_TLS);
        DEFAULT_TLS = NULL;
    }
}

tls_context *get_default_tls() {
    if (DEFAULT_TLS == NULL) {
        DEFAULT_TLS = default_tls_context(NULL, 0);
        atexit(free_default_tls);
    }
    return DEFAULT_TLS;
}

const char* tlsuv_version() {
    return TLSUV_VERS;
}

int tlsuv_stream_init(uv_loop_t *l, tlsuv_stream_t *clt, tls_context *tls) {
    clt->loop = l;

    clt->socket = calloc(1, sizeof(*clt->socket));
    tcp_src_init(l, clt->socket);

    uv_link_init((uv_link_t *) clt, &mbed_methods);
    clt->tls = tls != NULL ? tls : get_default_tls();
    clt->tls_engine = NULL;
    clt->host = NULL;
    clt->conn_req = NULL;
    clt->close_cb = NULL;

    return 0;
}

static void on_mbed_close(uv_link_t *l) {
    tlsuv_stream_t *mbed = (tlsuv_stream_t *) l;
    if (mbed->conn_req) {
        uv_connect_t *cr = mbed->conn_req;
        mbed->conn_req = NULL;
        cr->cb(cr, UV_ECANCELED);
    }
    if (mbed->socket) {
        mbed->socket->cancel((tlsuv_src_t *) mbed->socket);
        mbed->socket->release((tlsuv_src_t *) mbed->socket);
        tcp_src_free(mbed->socket);
        free(mbed->socket);
        mbed->socket = NULL;
    }
    if(mbed->close_cb) mbed->close_cb((uv_handle_t *) mbed);
}

int tlsuv_stream_close(tlsuv_stream_t *clt, uv_close_cb close_cb) {
    clt->close_cb = close_cb;
    uv_link_propagate_close((uv_link_t *) clt, (uv_link_t *) clt, on_mbed_close);
    return 0;
}

int tlsuv_stream_keepalive(tlsuv_stream_t *clt, int keepalive, unsigned int delay) {
    return tcp_src_keepalive(clt->socket, keepalive, delay);
}

int tlsuv_stream_nodelay(tlsuv_stream_t *clt, int nodelay) {
    return tcp_src_nodelay(clt->socket, nodelay);
}

static void on_tls_hs(tls_link_t *tls_link, int status) {
    tlsuv_stream_t *mbed = tls_link->data;

    uv_connect_t *req = mbed->conn_req;
    if (req == NULL) {
        return;
    }

    if (status == TLS_HS_COMPLETE) {
        req->cb(req, 0);
    } else if (status == TLS_HS_ERROR) {
        req->cb(req, UV_ECONNABORTED);
    } else {
        UM_LOG(WARN, "unexpected handshake status[%d]", status);
        req->cb(req, UV_EINVAL);
    }
    mbed->conn_req = NULL;
}

static void on_src_connect(tlsuv_src_t *src, int status, void *ctx) {
    tlsuv_stream_t *clt = ctx;

    if (status == 0) {
        if (clt->tls_engine != NULL) {
            clt->tls->api->free_engine(clt->tls_engine);
        }
        void *data = clt->data;
        clt->tls_engine = clt->tls->api->new_engine(clt->tls->ctx, clt->host);
        tlsuv_tls_link_init(&clt->tls_link, clt->tls_engine, on_tls_hs);
        uv_link_init((uv_link_t *) clt, &mbed_methods);
        clt->data = data;

        clt->tls_link.data = clt;
        uv_link_chain(src->link, (uv_link_t *)&clt->tls_link);
        uv_link_chain((uv_link_t *) &clt->tls_link, (uv_link_t *) clt);
        uv_link_read_start((uv_link_t *) clt);
    } else {
        UM_LOG(WARN, "failed to connect");
        clt->conn_req->cb(clt->conn_req, status);
        clt->conn_req = NULL;
    }
}

int tlsuv_stream_connect(uv_connect_t *req, tlsuv_stream_t *clt, const char *host, int port, uv_connect_cb cb) {
    if (!req) {
        return UV_EINVAL;
    }
    if (port <= 0 || port > UINT16_MAX) {
        return UV_EINVAL;
    }
    if (clt->conn_req != NULL) {
        return UV_EALREADY;
    }

    char portstr[6];
    snprintf(portstr, sizeof(portstr), "%d", port);

    req->handle = (uv_stream_t *) clt;
    req->cb = cb;
    if (clt->host) free (clt->host);
    clt->host = strdup(host);
    clt->conn_req = req;

    if (!clt->socket) {
        clt->socket = calloc(1, sizeof(*clt->socket));
        tcp_src_init(clt->loop, clt->socket);
    }

    return clt->socket->connect((tlsuv_src_t *) clt->socket, host, portstr, on_src_connect, clt);
}

int tlsuv_stream_read(tlsuv_stream_t *clt, uv_alloc_cb alloc_cb, uv_read_cb read_cb) {
    clt->alloc_cb = (uv_link_alloc_cb) alloc_cb;
    clt->read_cb = (uv_link_read_cb) read_cb;
    return 0;
}

static void on_mbed_link_write(uv_link_t* l, int status, void *ctx) {
    uv_write_t *wr = ctx;
    wr->cb(wr, status);
}

int tlsuv_stream_write(uv_write_t *req, tlsuv_stream_t *clt, uv_buf_t *buf, uv_write_cb cb) {
    req->handle = (uv_stream_t *) clt;
    req->cb = cb;
    return uv_link_write((uv_link_t *) clt, buf, 1, NULL, on_mbed_link_write, req);
}

int tlsuv_stream_free(tlsuv_stream_t *clt) {
    if (clt->host) {
        free(clt->host);
        clt->host = NULL;
    }
    if (clt->tls_engine) {
        clt->tls->api->free_engine(clt->tls_engine);
        clt->tls_engine = NULL;
    }
    if (clt->socket) {
        tcp_src_free(clt->socket);
        free(clt->socket);
        clt->socket = NULL;
    }
    return 0;
}

