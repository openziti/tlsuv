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


#include <uv_link_t.h>
#include <tlsuv/tls_engine.h>
#include "tlsuv/tls_link.h"
#include "um_debug.h"

static int tls_read_start(uv_link_t *l);
static void tls_alloc(uv_link_t *l, size_t suggested, uv_buf_t *buf);
static void tls_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf);
static int tls_write(uv_link_t *link, uv_link_t *source, const uv_buf_t bufs[],
                     unsigned int nbufs, uv_stream_t *send_handle, uv_link_write_cb cb, void *arg);
static void tls_close(uv_link_t *link, uv_link_t *source, uv_link_close_cb cb);

static const uv_link_methods_t tls_methods = {
        .close = tls_close,
        .read_start = tls_read_start,
        .write = tls_write,
        .alloc_cb_override = tls_alloc,
        .read_cb_override = tls_read_cb
};

typedef struct tls_link_write_s {
    char *tls_buf;
    uv_link_write_cb cb;
    void *ctx;

} tls_link_write_t;

static const int TLS_BUF_SZ = 32 * 1024;

void tls_alloc(uv_link_t *l, size_t suggested, uv_buf_t *buf) {
    tls_link_t *tls_link = (tls_link_t *) l;
    tls_handshake_state st = tls_link->engine->api->handshake_state(tls_link->engine->engine);
    switch (st) {
        case TLS_HS_BEFORE:
        case TLS_HS_CONTINUE:
            buf->base = malloc(suggested);
            buf->len = suggested;
            break;
        case TLS_HS_COMPLETE:
            uv_link_propagate_alloc_cb(l, suggested, buf);
            break;
        default:
            UM_LOG(ERR, "TLS(%p) in bad state", tls_link);
            break;
    }
}

static void tls_write_free_cb(uv_link_t *source, int status, void *arg) {
    if (arg)
        free(arg);
}

static void tls_write_cb(uv_link_t *source, int status, void *arg) {
    tls_link_write_t *wr = arg;
    uv_link_t *tls_link = source->child;
    if (wr->cb) {
        wr->cb(tls_link, status, wr->ctx);
    }

    if (wr->tls_buf) {
        free(wr->tls_buf);
    }
    free(wr);
}

static int tls_read_start(uv_link_t *l) {
    tls_link_t *tls = (tls_link_t *) l;

    tls_handshake_state st = tls->engine->api->handshake_state(tls->engine->engine);
    UM_LOG(TRACE, "TLS(%p) starting handshake(st = %d)", tls, st);
    if (st == TLS_HS_CONTINUE) {
        UM_LOG(TRACE, "TLS(%p) is in the middle of handshake, resetting", tls);
        if (tls->engine->api->reset) {
            tls->engine->api->reset(tls->engine->engine);
        }
    }

    uv_link_default_read_start(l);

    uv_buf_t buf;
    buf.base = malloc(TLS_BUF_SZ);
    st = tls->engine->api->handshake(tls->engine->engine, NULL, 0, buf.base, &buf.len,
                                                         TLS_BUF_SZ);
    UM_LOG(TRACE, "TLS(%p) starting handshake(sending %zd bytes, st = %d)", tls, buf.len, st);

    tls_link_write_t *wr = calloc(1, sizeof(tls_link_write_t));
    wr->tls_buf = buf.base;
    return uv_link_propagate_write(l->parent, l, &buf, 1, NULL, tls_write_cb, wr);
}

static void tls_read_cb(uv_link_t *l, ssize_t nread, const uv_buf_t *b) {
    tls_link_t *tls = (tls_link_t *) l;

    tls_handshake_state hs_state = tls->engine->api->handshake_state(tls->engine->engine);
    UM_LOG(TRACE, "TLS(%p)[%d]: %zd", tls, hs_state, nread);

    if (nread < 0) {
        UM_LOG(ERR, "TLS read %d(%s)", nread, uv_strerror(nread));
        if (hs_state == TLS_HS_CONTINUE) {
            tls->engine->api->reset(tls->engine->engine);
            tls->hs_cb(tls, TLS_HS_ERROR);
            free(b->base);
        } else {
            uv_link_propagate_read_cb(l, nread, b);
        }
        return;
    }

    if (hs_state == TLS_HS_CONTINUE) {
        if (nread == 0) {
            UM_LOG(ERR, "should not be here");
            return;
        }

        UM_LOG(TRACE, "TLS(%p) continuing handshake(%zd bytes received)", tls, nread);
        uv_buf_t buf;
        buf.base = malloc(TLS_BUF_SZ);
        tls_handshake_state st =
                tls->engine->api->handshake(tls->engine->engine, b->base, nread, buf.base, &buf.len, TLS_BUF_SZ);

        UM_LOG(TRACE, "TLS(%p) continuing handshake(sending %zd bytes, st = %d)", tls, buf.len, st);
        if (buf.len > 0) {
            tls_link_write_t *wr = calloc(1, sizeof(tls_link_write_t));
            wr->tls_buf = buf.base;
            int rc = uv_link_propagate_write(l->parent, l, &buf, 1, NULL, tls_write_cb, wr);
            if (rc != 0) {
                UM_LOG(WARN, "TLS(%p) failed to write during handshake %d(%s)", tls, rc, uv_strerror(rc));
                tls_write_cb(l->parent, rc, wr);
            }
        }
        else {
            free(buf.base);
        }

        if (st == TLS_HS_COMPLETE) {
            UM_LOG(TRACE, "TLS(%p) handshake completed", tls);
            tls->hs_cb(tls, TLS_HS_COMPLETE);
        }
        else if (st == TLS_HS_ERROR) {
            const char *err = NULL;
            if (tls->engine->api->strerror) {
                err = tls->engine->api->strerror(tls->engine->engine);
            }
            UM_LOG(ERR, "TLS(%p) handshake error %s", tls, err);
            tls->hs_cb(tls, st);
            uv_link_propagate_read_cb(l, UV_ECONNABORTED, NULL);
        }
        if (b->base) free(b->base);
    } else if (hs_state == TLS_HS_COMPLETE) {
        UM_LOG(TRACE, "TLS(%p) processing %zd bytes", tls, nread);

        size_t bufsize = b->len;
        char *inptr = b->base;
        size_t inlen = nread;
        enum TLS_RESULT rc = TLS_MORE_AVAILABLE;
        while(rc == TLS_MORE_AVAILABLE || rc == TLS_READ_AGAIN) {
            ssize_t out_bytes = 0;
            rc = tls->engine->api->read(tls->engine->engine, inptr, inlen, b->base, (size_t *)&out_bytes, b->len);
            UM_LOG(TRACE, "TLS(%p) produced %zd application byte (rc=%d)", tls, out_bytes, rc);

            switch (rc) {
                case TLS_OK: {
                    uv_link_propagate_read_cb(l, out_bytes, b);
                    break;
                }
                case TLS_EOF: {
                    if (out_bytes > 0) {
                        uv_link_propagate_read_cb(l, out_bytes, b);
                        uv_link_propagate_alloc_cb(l, bufsize, (uv_buf_t *)b);
                    }
                    uv_link_propagate_read_cb(l, UV_EOF, b);
                    break;
                }
                case TLS_READ_AGAIN:
                case TLS_MORE_AVAILABLE: {
                    uv_link_propagate_read_cb(l, out_bytes, b);
                    inlen = 0;
                    inptr = NULL;
                    uv_link_propagate_alloc_cb(l, bufsize, (uv_buf_t *)b);
                    if (b->base == NULL || b->len == 0) {
                        uv_link_propagate_read_cb(l, UV_ENOBUFS, b);
                        return;
                    }
                    break;
                }
                case TLS_HAS_WRITE: {
                    uv_buf_t buf;
                    buf.base = malloc(TLS_BUF_SZ);
                    int tls_rc = tls->engine->api->write(tls->engine->engine, NULL, 0, buf.base, &buf.len, TLS_BUF_SZ);
                    uv_link_propagate_write(l->parent, l, &buf, 1, NULL, tls_write_free_cb, buf.base);
                    break;
                }
                case TLS_ERR:
                default:
                    if (out_bytes > 0) {
                        uv_link_propagate_read_cb(l, out_bytes, b);
                        uv_link_propagate_alloc_cb(l, bufsize, (uv_buf_t*)b);
                    }
                    if (rc != TLS_ERR) {
                        UM_LOG(ERR, "aborting after unexpected TLS engine result: %d", rc);
                    } else {
                        UM_LOG(ERR, "aborting after TLS engine error: %s", tls->engine->api->strerror(tls->engine->engine));
                    }
                    uv_link_propagate_read_cb(l, UV_ECONNABORTED, b);
                    break;
            }
        }
    }
    else {
        UM_LOG(VERB, "hs_state = %d", hs_state);
    }
}

static int tls_write(uv_link_t *l, uv_link_t *source, const uv_buf_t bufs[],
                     unsigned int nbufs, uv_stream_t *send_handle, uv_link_write_cb cb, void *arg) {
    tls_link_t *tls = (tls_link_t *) l;
    uv_buf_t buf = uv_buf_init(NULL, 0);
    int tls_rc = 0;
    for (int i = 0; i < nbufs; i++) {
        tls_rc = tls->engine->api->write(tls->engine->engine, bufs[i].base, bufs[i].len, NULL, &buf.len, 0);
        if (tls_rc < 0) {
            UM_LOG(ERR, "TLS(%p) engine failed to wrap: %d(%s)", tls, tls_rc, tls->engine->api->strerror(tls->engine->engine));
            free(buf.base);
            return tls_rc;
        }
    }
    

    if (tls_rc > 0) {
        buf.base = malloc(tls_rc);
        tls_rc = tls->engine->api->write(tls->engine->engine, NULL, 0, buf.base, &buf.len, tls_rc);
        if (tls_rc < 0) {
            UM_LOG(ERR, "TLS(%p) engine failed to wrap: %d(%s)", tls, tls_rc, tls->engine->api->strerror(tls->engine->engine));
            free(buf.base);
            return tls_rc;
        }
    } else if (tls_rc == 0) { // nothing to send
        tls_write_cb(l, 0, arg);
        return 0;
    }
    
    tls_link_write_t *wr = calloc(1, sizeof(tls_link_write_t));
    wr->tls_buf = buf.base;
    wr->cb = cb;
    wr->ctx = arg;
    return uv_link_propagate_write(l->parent, l, &buf, 1, send_handle, tls_write_cb, wr);
}

static void tls_close(uv_link_t *l, uv_link_t *source, uv_link_close_cb close_cb) {
    UM_LOG(TRACE, "closing TLS link");
    tls_link_t *tls = (tls_link_t *) l;
    if (tls->engine->api->reset) {
        tls->engine->api->reset(tls->engine->engine);
    }
    close_cb(source);
}

int tlsuv_tls_link_init(tls_link_t *tls, tls_engine *engine, tls_handshake_cb cb) {
    uv_link_init((uv_link_t *) tls, &tls_methods);
    tls->engine = engine;
    tls->hs_cb = cb;
    return 0;
}
