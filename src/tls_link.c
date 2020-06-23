/*
Copyright 2020 NetFoundry, Inc.

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


#include <uv_link_t.h>
#include <uv_mbed/tls_engine.h>
#include "uv_mbed/tls_link.h"
#include "um_debug.h"

enum tls_state {
    initial = 0,
    handshaking = 1,
    connected = 2,
};

static int tls_read_start(uv_link_t *l);
static void tls_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf);
static int tls_write(uv_link_t *link, uv_link_t *source, const uv_buf_t bufs[],
                     unsigned int nbufs, uv_stream_t *send_handle, uv_link_write_cb cb, void *arg);
static void tls_close(uv_link_t *link, uv_link_t *source, uv_link_close_cb cb);

static const uv_link_methods_t tls_methods = {
        .close = tls_close,
        .read_start = tls_read_start,
        .write = tls_write,
        .alloc_cb_override = uv_link_default_alloc_cb_override,
        .read_cb_override = tls_read_cb
};

static void tls_write_cb(uv_link_t *source, int status, void *arg) {
    if (arg != NULL) {
        free(arg);
    }
}

static int tls_read_start(uv_link_t *l) {
    tls_link_t *tls = (tls_link_t *) l;

    if (tls->state == initial) {
        uv_link_default_read_start(l);

        uv_buf_t buf;
        buf.base = malloc(32 * 1024);
        tls_handshake_state st = tls->engine->api->handshake(tls->engine->engine, NULL, 0, buf.base, &buf.len,
                                                             32 * 1024);
        UM_LOG(VERB, "starting TLS handshake(sending %zd bytes, st = %d)", buf.len, st);

        return uv_link_propagate_write(l->parent, l, &buf, 1, NULL, tls_write_cb, buf.base);
    } else {
        return 0;
    }
}

static void tls_read_cb(uv_link_t *l, ssize_t nread, const uv_buf_t *b) {
    tls_link_t *tls = (tls_link_t *) l;

    if (nread < 0) {
        if (b && b->base)
            free(b->base);
        uv_link_propagate_read_cb(l, nread, NULL);
        return;
    }

    tls_handshake_state hs_state = tls->engine->api->handshake_state(tls->engine->engine);
    if (hs_state == TLS_HS_CONTINUE) {
        UM_LOG(VERB, "continuing TLS handshake(%zd bytes received)", nread);
        uv_buf_t buf;
        buf.base = malloc(32 * 1024);
        tls_handshake_state st =
                tls->engine->api->handshake(tls->engine->engine, b->base, nread, buf.base, &buf.len, 32 * 1024);

        UM_LOG(VERB, "continuing TLS handshake(sending %zd bytes, st = %d)", buf.len, st);
        if (buf.len > 0) {
            uv_link_propagate_write(l->parent, l, &buf, 1, NULL, tls_write_cb, buf.base);
        }
        else {
            free(buf.base);
        }

        if (st == TLS_HS_COMPLETE) {
            UM_LOG(VERB, "handshake completed");
            tls->hs_cb(tls, TLS_HS_COMPLETE);
        }
        else if (st == TLS_HS_ERROR) {
            char err[1024];
            int errlen = 0;
            if (tls->engine->api->strerror) {
                errlen = tls->engine->api->strerror(tls->engine->engine, err, sizeof(err));
            }
            UM_LOG(ERR, "TLS handshake error %*.*s", errlen, errlen, err);
            tls->hs_cb(tls, st);
            uv_link_propagate_read_cb(l, UV_ECONNABORTED, NULL);
        }
    }
    else if (hs_state == TLS_HS_COMPLETE) {
        uv_buf_t read_buf;
        uv_link_propagate_alloc_cb(l, 32 * 1024, &read_buf);

        size_t readbuflen = read_buf.len;
        read_buf.len = 0;

        size_t out_bytes;
        char *inptr = b->base;
        size_t inlen = nread;
        int rc;
        do {
            rc = tls->engine->api->read(tls->engine->engine, inptr, inlen,
                    read_buf.base + read_buf.len, &out_bytes, readbuflen - read_buf.len);

            UM_LOG(VERB, "produced %zd application byte (rc=%d)", out_bytes, rc);
            read_buf.len += out_bytes;
            inptr = NULL;
            inlen = 0;
        } while (rc == TLS_MORE_AVAILABLE && out_bytes > 0);

        uv_link_propagate_read_cb(l, read_buf.len, &read_buf);
    }
    else {
        UM_LOG(VERB, "hs_state = %d", hs_state);
    }

    if (b != NULL && b->base != NULL) {
        free(b->base);
    }
}

static int tls_write(uv_link_t *l, uv_link_t *source, const uv_buf_t bufs[],
                     unsigned int nbufs, uv_stream_t *send_handle, uv_link_write_cb cb, void *arg) {
    tls_link_t *tls = (tls_link_t *) l;
    uv_buf_t buf;
    buf.base = malloc(32 * 1024);
    tls->engine->api->write(tls->engine->engine, bufs[0].base, bufs[0].len, buf.base, &buf.len, 32 * 1024);
    int rc = uv_link_propagate_write(l->parent, l, &buf, 1, NULL, tls_write_cb, buf.base);

    cb(source, 0, arg);

    return rc;
}

static void tls_close(uv_link_t *l, uv_link_t *source, uv_link_close_cb close_cb) {
    UM_LOG(VERB, "closing TLS link");
//    um_http_t *clt = l->data;
//
//    clt->tls->api->free_engine(clt->engine);
//    clt->engine = NULL;

    close_cb(source);
}

int um_tls_init(tls_link_t *tls, tls_engine *engine, tls_handshake_cb cb) {
    uv_link_init((uv_link_t *) tls, &tls_methods);
    tls->engine = engine;
    tls->hs_cb = cb;
    return 0;
}
