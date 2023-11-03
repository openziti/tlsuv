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
#include "util.h"

static int tls_read_start(uv_link_t *l);
static void tls_alloc(uv_link_t *l, size_t suggested, uv_buf_t *buf);
static void tls_read_cb(uv_link_t *link, ssize_t nread, const uv_buf_t *buf);
static int tls_write(uv_link_t *link, uv_link_t *source, const uv_buf_t bufs[],
                     unsigned int nbufs, uv_stream_t *send_handle, uv_link_write_cb cb, void *arg);
static void tls_close(uv_link_t *link, uv_link_t *source, uv_link_close_cb cb);
static void tls_link_flush_io(tls_link_t *, uv_link_write_cb , void *);

static const uv_link_methods_t tls_methods = {
    .close = tls_close,
    .read_start = tls_read_start,
    .read_stop = uv_link_default_read_stop,
    .write = tls_write,
    .alloc_cb_override = tls_alloc,
    .read_cb_override = tls_read_cb
};

#define TLS_BUF_SZ (32 * 1024)
WRAPAROUND_BUFFER(ssl_buf_s, TLS_BUF_SZ);

void tls_alloc(uv_link_t *l, size_t suggested, uv_buf_t *buf) {
    tls_link_t *tls_link = (tls_link_t *) l;

    WAB_PUT_SPACE(*tls_link->ssl_in, buf->base, buf->len);
    UM_LOG(INFO, "allocated %zd", buf->len);
}

static int tls_read_start(uv_link_t *l) {
    tls_link_t *tls = (tls_link_t *) l;

    tls_handshake_state st = tls->engine->handshake_state(tls->engine);
    UM_LOG(TRACE, "TLS(%p) starting handshake(st = %d)", tls, st);
    if (st == TLS_HS_CONTINUE) {
        UM_LOG(TRACE, "TLS(%p) is in the middle of handshake, resetting", tls);
        if (tls->engine->reset) {
            tls->engine->reset(tls->engine);

        }
    }

    uv_link_default_read_start(l);

    st = tls->engine->handshake(tls->engine);
    UM_LOG(TRACE, "TLS(%p) started handshake(st = %d)", tls, st);
    tls_link_flush_io(tls, NULL, NULL);

    return 0;
}

static void tls_read_cb(uv_link_t *l, ssize_t nread, const uv_buf_t *b) {
    tls_link_t *tls = (tls_link_t *) l;
    tls_handshake_state hs_state = tls->engine->handshake_state(tls->engine);
    UM_LOG(INFO, "TLS(%p)[%d]: %zd", tls, hs_state, nread);

    if (nread >= 0) {
        WAB_UPDATE_PUT(*tls->ssl_in, nread);
    } else if (nread == UV_ENOBUFS) {
        // our ssl buf is full
    } else {
        UM_LOG(ERR, "TLS read %zd(%s)", nread, uv_strerror((int)nread));
        if (hs_state == TLS_HS_CONTINUE) {
            tls->engine->reset(tls->engine);
            tls->hs_cb(tls, TLS_HS_ERROR);
        } else {
            uv_buf_t buf;
            uv_link_propagate_alloc_cb(l, TLS_BUF_SZ, &buf);
            uv_link_propagate_read_cb(l, nread, &buf);
        }
        return;
    }

    if (hs_state == TLS_HS_CONTINUE) {
        if (nread == 0) {
            UM_LOG(ERR, "should not be here");
            return;
        }

        UM_LOG(TRACE, "TLS(%p) continuing handshake(%zd bytes received)", tls, nread);
        tls_handshake_state st = tls->engine->handshake(tls->engine);
        tls_link_flush_io(tls, NULL, NULL);

        if (st == TLS_HS_COMPLETE) {
            UM_LOG(TRACE, "TLS(%p) handshake completed", tls);
            tls->hs_cb(tls, TLS_HS_COMPLETE);
        } else if (st == TLS_HS_ERROR) {
            const char *err = NULL;
            if (tls->engine->strerror) {
                err = tls->engine->strerror(tls->engine);
            }
            UM_LOG(ERR, "TLS(%p) handshake error %s", tls, err);
            tls->hs_cb(tls, st);
            uv_link_propagate_read_cb(l, UV_ECONNABORTED, NULL);
        }
    } else if (hs_state == TLS_HS_COMPLETE) {
        UM_LOG(TRACE, "TLS(%p) processing %zd bytes", tls, nread);

        enum TLS_RESULT rc = TLS_MORE_AVAILABLE;
        while(rc == TLS_MORE_AVAILABLE) {
            uv_buf_t buf;
            uv_link_propagate_alloc_cb(l, 64 * 1024, &buf);

            if (buf.base == NULL || buf.len == 0) {
                uv_link_propagate_read_cb(l, UV_ENOBUFS, &buf);
                break;
            }

            size_t read_len;
            rc = tls->engine->read(tls->engine, buf.base, (size_t *)&read_len, buf.len);
            UM_LOG(INFO, "TLS(%p) produced %zd application byte (rc=%d)", tls, read_len, rc);

            if (read_len > 0) {
                uv_link_propagate_read_cb(l, (ssize_t)read_len, &buf);
                continue;
            }

            if (rc == TLS_AGAIN) {
                uv_link_propagate_read_cb(l, 0, &buf);
            } else if (rc == TLS_EOF) {
                uv_link_propagate_read_cb(l, UV_EOF, &buf);
            } else if (rc == TLS_ERR) {
                uv_link_propagate_read_cb(l, UV_ECONNABORTED, &buf);
            } else {
                UM_LOG(ERR, "aborting after unexpected TLS engine result: %d", rc);
                uv_link_propagate_read_cb(l, UV_ECONNABORTED, &buf);
            }
        }
    } else {
        UM_LOG(WARN, "SHOULD NOT BE here hs_state = %d", hs_state);
    }
}

static int tls_write(uv_link_t *l, uv_link_t *source, const uv_buf_t bufs[],
                     unsigned int nbufs, uv_stream_t *send_handle, uv_link_write_cb cb, void *arg) {
    tls_link_t *tls = (tls_link_t *) l;

    int tls_rc;
    int i = 0;
    while(i < nbufs) {
        uv_buf_t b = bufs[i];
        while(b.len > 0) {
            tls_rc = tls->engine->write(tls->engine, b.base, b.len);
            if (tls_rc < 0) {
                goto error;
            }
            b.base += tls_rc;
            b.len -= tls_rc;
        }
        i++;
    }

    // make sure callback is called after the last SSL bytes are put on the wire
    tls_link_flush_io(tls, cb, arg);
    return 0;

    error:
    UM_LOG(ERR, "TLS(%p) engine failed to wrap: %d(%s)", tls, tls_rc, tls->engine->strerror(tls->engine));
    cb(l, tls_rc, arg);
    return tls_rc;
}

static void tls_close(uv_link_t *l, uv_link_t *source, uv_link_close_cb close_cb) {
    UM_LOG(TRACE, "closing TLS link");
    tls_link_t *tls = (tls_link_t *) l;
    if (tls->engine->reset) {
        tls->engine->reset(tls->engine);
    }
    close_cb(source);
}

struct flush_req {
    char *b;
    uv_link_write_cb cb;
    void *ctx;
};

static void tls_link_io_write_cb(uv_link_t *l, int status, void *data) {
    struct flush_req *req = data;
    if (req->cb) {
        req->cb(l, status, req->ctx);
    }
    free(req->b);
    free(req);
}

static void tls_link_flush_io(tls_link_t *tls, uv_link_write_cb cb, void *ctx) {
    struct flush_req *req = NULL;
    char *p;
    size_t len;
    size_t total = 0;
    WAB_GET_SPACE(*tls->ssl_out, p, len);
    while (len > 0) {
        if (req == NULL) {
            req = calloc(1, sizeof(struct flush_req));
            req->b = malloc(TLS_BUF_SZ);
        }
        UM_LOG(INFO, "writing %zd bytes", len);
        memcpy(req->b + total, p, len);
        total += len;
        WAB_UPDATE_GET(*tls->ssl_out, len);
        WAB_GET_SPACE(*tls->ssl_out, p, len);
    }
    if (req) {
        uv_buf_t b = uv_buf_init(req->b, total);
        req->cb = cb;
        req->ctx = ctx;
        uv_link_propagate_write(tls->parent, (uv_link_t *) tls, &b, 1, NULL, tls_link_io_write_cb, req);
    } else {
        // this should not happen but just in case
        if (cb) {
            cb((uv_link_t *) tls, 0, ctx);
        }
    }
    // ssl_out get caught up to put, just reset it
    WAB_INIT(*tls->ssl_out);
}

static ssize_t tls_link_io_write(io_ctx ctx, const char *data, size_t data_len) {
    tls_link_t *tls = ctx;
    if (data_len > INT_MAX) {
        data_len = INT_MAX;
    }
    UM_LOG(INFO, "io buffering %zd bytes", data_len);
    size_t ret = data_len;
    while (data_len > 0) {
        char *sslp;
        size_t len;
        WAB_PUT_SPACE(*tls->ssl_out, sslp, len);

        if (len == 0) {
            tls_link_flush_io(tls, NULL, NULL);
        }

        if (len > data_len) {
            len = data_len;
        }
        memcpy(sslp, data, len);
        WAB_UPDATE_PUT(*tls->ssl_out, len);
        data += len;
        data_len -= len;
    }

    return (ssize_t) ret;
}

static ssize_t tls_link_io_read(io_ctx ctx, char *data, size_t max) {
    tls_link_t *tls = ctx;
    char *ssl_p;
    size_t avail;
    WAB_GET_SPACE(*tls->ssl_in, ssl_p, avail);
    if (avail == 0) {
        return TLS_AGAIN;
    }

    if (max > avail) {
        max = avail;
    }

    memcpy(data, ssl_p, max);
    WAB_UPDATE_GET(*tls->ssl_in, max);
    UM_LOG(INFO, "read %zd/%zd bytes", max, avail);

    return (ssize_t)max;
}

int tlsuv_tls_link_init(tls_link_t *tls, tlsuv_engine_t engine, tls_handshake_cb cb) {
    uv_link_init((uv_link_t *) tls, &tls_methods);
    tls->engine = engine;
    tls->ssl_in = malloc(sizeof(ssl_buf_t));
    WAB_INIT(*tls->ssl_in);
    tls->ssl_out = malloc(sizeof(ssl_buf_t));
    WAB_INIT(*tls->ssl_out);

    engine->set_io(engine, tls, tls_link_io_read, tls_link_io_write);
    tls->hs_cb = cb;
    return 0;
}
