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

#include <stdlib.h>
#include <string.h>
#include "uv_mbed/uv_mbed.h"
#include <uv.h>
#include "um_debug.h"

#define to_str1(s) #s
#define to_str(s) to_str1(s)

#ifdef UV_MBED_VERSION
#define UM_VERS to_str(UV_MBED_VERSION)
#else
#define UM_VERS "<unknown>"
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

tls_context *get_default_tls() {
    if (DEFAULT_TLS == NULL) {
        DEFAULT_TLS = default_tls_context(NULL, 0);
    }
    return DEFAULT_TLS;
}

const char* uv_mbed_version() {
    return UM_VERS;
}

int uv_mbed_init(uv_loop_t *l, uv_mbed_t *mbed, tls_context *tls) {
    mbed->loop = l;

    mbed->socket = calloc(1, sizeof(*mbed->socket));
    tcp_src_init(l, mbed->socket);

    uv_link_init((uv_link_t *) mbed, &mbed_methods);
    mbed->tls = tls != NULL ? tls : get_default_tls();
    mbed->tls_engine = NULL;
    mbed->host = NULL;
    mbed->conn_req = NULL;
    mbed->close_cb = NULL;

    return 0;
}

static void on_mbed_close(uv_link_t *l) {
    uv_mbed_t *mbed = (uv_mbed_t *) l;
    if (mbed->conn_req) {
        uv_connect_t *cr = mbed->conn_req;
        mbed->conn_req = NULL;
        cr->cb(cr, UV_ECANCELED);
    }
    if (mbed->socket) {
        mbed->socket->cancel((um_src_t *) mbed->socket);
        mbed->socket->release((um_src_t *) mbed->socket);
        tcp_src_free(mbed->socket);
        free(mbed->socket);
        mbed->socket = NULL;
    }
    if(mbed->close_cb) mbed->close_cb((uv_handle_t *) mbed);
}

int uv_mbed_close(uv_mbed_t *mbed, uv_close_cb close_cb) {
    mbed->close_cb = close_cb;
    uv_link_propagate_close((uv_link_t *) mbed, (uv_link_t *) mbed, on_mbed_close);
    return 0;
}

int uv_mbed_keepalive(uv_mbed_t *mbed, int keepalive, unsigned int delay) {
    return tcp_src_keepalive(mbed->socket, keepalive, delay);
}

int uv_mbed_nodelay(uv_mbed_t *mbed, int nodelay) {
    return tcp_src_nodelay(mbed->socket, nodelay);
}

static void on_tls_hs(tls_link_t *tls_link, int status) {
    uv_mbed_t *mbed = tls_link->data;

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

static void on_src_connect(um_src_t *src, int status, void *ctx) {
    uv_mbed_t *mbed = ctx;

    if (status == 0) {
        if (mbed->tls_engine != NULL) {
            mbed->tls->api->free_engine(mbed->tls_engine);
        }
        void *data = mbed->data;
        mbed->tls_engine = mbed->tls->api->new_engine(mbed->tls->ctx, mbed->host);
        um_tls_init(&mbed->tls_link, mbed->tls_engine, on_tls_hs);
        uv_link_init((uv_link_t *) mbed, &mbed_methods);
        mbed->data = data;

        mbed->tls_link.data = mbed;
        uv_link_chain(src->link, (uv_link_t *)&mbed->tls_link);
        uv_link_chain((uv_link_t *) &mbed->tls_link, (uv_link_t *) mbed);
        uv_link_read_start((uv_link_t *) mbed);
    } else {
        UM_LOG(WARN, "failed to connect");
        mbed->conn_req->cb(mbed->conn_req, status);
        mbed->conn_req = NULL;
    }
}

int uv_mbed_connect(uv_connect_t *req, uv_mbed_t *mbed, const char *host, int port, uv_connect_cb cb) {
    if (!req) {
        return UV_EINVAL;
    }
    if (mbed->conn_req != NULL) {
        return UV_EALREADY;
    }

    char portstr[6];
    sprintf(portstr, "%d", port);

    req->handle = (uv_stream_t *) mbed;
    req->cb = cb;
    if (mbed->host) free (mbed->host);
    mbed->host = strdup(host);
    mbed->conn_req = req;

    return mbed->socket->connect((um_src_t *) mbed->socket, host, portstr, on_src_connect, mbed);
}

int uv_mbed_read(uv_mbed_t *mbed, uv_alloc_cb alloc_cb, uv_read_cb read_cb) {
    mbed->alloc_cb = (uv_link_alloc_cb) alloc_cb;
    mbed->read_cb = (uv_link_read_cb) read_cb;
    return 0;
}

static void on_mbed_link_write(uv_link_t* l, int status, void *ctx) {
    uv_write_t *wr = ctx;
    wr->cb(wr, status);
}

int uv_mbed_write(uv_write_t *req, uv_mbed_t *mbed, uv_buf_t *buf, uv_write_cb cb) {
    req->handle = (uv_stream_t *) mbed;
    req->cb = cb;
    return uv_link_write((uv_link_t *) mbed, buf, 1, NULL, on_mbed_link_write, req);
}

int uv_mbed_free(uv_mbed_t *mbed) {
    if (mbed->host) {
        free(mbed->host);
        mbed->host = NULL;
    }
    if (mbed->tls_engine) {
        mbed->tls->api->free_engine(mbed->tls_engine);
        mbed->tls_engine = NULL;
    }
    if (mbed->socket) {
        tcp_src_free(mbed->socket);
        free(mbed->socket);
        mbed->socket = NULL;
    }
    return 0;
}

