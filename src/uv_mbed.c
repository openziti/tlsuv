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
static void dns_resolve_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res);

static void tcp_connect_cb(uv_connect_t* req, int status);
static void tcp_shutdown_cb(uv_shutdown_t* req, int status) ;
static int mbed_ssl_send(void* ctx, const uint8_t *buf, size_t len);

static int mbed_tcp_write(uv_mbed_t *mbed, char *buf, size_t len, uv_write_t *wr);

struct tcp_write_ctx {
    uint8_t *buf;
    uv_write_t *req;
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
    memset(&mbed->_stream, 0, sizeof(uv_stream_t));
    mbed->_stream.loop = l;
    mbed->_stream.type = UV_STREAM;

    uv_tcp_init(l, &mbed->socket);

    mbed->tls = tls != NULL ? tls : get_default_tls();
    mbed->tls_engine = NULL;

    return 0;
}

int uv_mbed_connect_addr(uv_connect_t *req, uv_mbed_t* mbed, const struct addrinfo *addr, uv_connect_cb cb) {

    if (mbed->conn_req != NULL && mbed->conn_req != req) {
        return UV_EALREADY;
    }

    req->handle = (uv_stream_t *) mbed;
    req->cb = cb;
    mbed->conn_req = req;

    uv_connect_t *tcp_cr = calloc(1, sizeof(uv_connect_t));
    tcp_cr->data = mbed;
    return uv_tcp_connect(tcp_cr, &mbed->socket, addr->ai_addr, tcp_connect_cb);
}

static void on_close_write(uv_write_t *req, int status) {
    struct uv_mbed_s *mbed = (struct uv_mbed_s *) req->handle;

    uv_shutdown_t *sr = malloc(sizeof(uv_shutdown_t));
    sr->data = mbed;
    uv_shutdown(sr, (uv_stream_t *) &mbed->socket, tcp_shutdown_cb);
    free(req);
}

int uv_mbed_close(uv_mbed_t *mbed, uv_close_cb close_cb) {

    mbed->_stream.close_cb = close_cb;
    size_t out_size = 32 * 1024;
    char *buf = malloc(out_size);
    size_t out_len;
    mbed->tls_engine->api->close(mbed->tls_engine->engine, buf, &out_len, out_size);
    uv_write_t *wr = calloc(1, sizeof(uv_write_t));
    wr->handle = mbed;
    wr->cb = on_close_write;
    mbed_tcp_write(mbed, buf, out_len, wr);
    return 0;
}

int uv_mbed_keepalive(uv_mbed_t *mbed, int keepalive, unsigned int delay) {
    return uv_tcp_keepalive(&mbed->socket, keepalive, delay);
}

int uv_mbed_nodelay(uv_mbed_t *mbed, int nodelay) {
    return uv_tcp_nodelay(&mbed->socket, nodelay);
}

int uv_mbed_connect(uv_connect_t *req, uv_mbed_t *mbed, const char *host, int port, uv_connect_cb cb) {
    uv_loop_t *loop = mbed->_stream.loop;
    uv_getaddrinfo_t *resolve_req = calloc(1, sizeof(uv_getaddrinfo_t));
    req->handle = (uv_stream_t *) mbed;
    req->cb = cb;
    mbed->conn_req = req;
    
    resolve_req->data = mbed;
    char portstr[6];
    sprintf(portstr, "%d", port);

    mbed->tls_engine = mbed->tls->api->new_engine(mbed->tls->ctx, host);

    UM_LOG(VERB, "resolving host = %s:%s", host, portstr);
    int resolve_rc =  uv_getaddrinfo(loop, resolve_req, NULL, host, portstr, NULL);
    if (resolve_rc != 0) {
        UM_LOG(ERR, "failed to resolve host[%s]: %s", host, uv_strerror(resolve_rc));
        cb(req, resolve_rc);
        return resolve_rc;
    }

    dns_resolve_cb(resolve_req, 0, resolve_req->addrinfo);
    return 0;
}

int uv_mbed_set_blocking(uv_mbed_t *um, int blocking) {
    return uv_stream_set_blocking((uv_stream_t *) &um->socket, blocking);
}

int uv_mbed_read(uv_mbed_t *mbed, uv_alloc_cb alloc_cb, uv_read_cb read_cb) {
    mbed->_stream.alloc_cb = alloc_cb;
    mbed->_stream.read_cb = read_cb;
    return 0;
}

int uv_mbed_write(uv_write_t *req, uv_mbed_t *mbed, uv_buf_t *buf, uv_write_cb cb) {
    req->handle = (uv_stream_t *) mbed;

    size_t out_size = 32 * 1024;
    char *out = malloc(out_size);
    size_t out_len;
    int rc = mbed->tls_engine->api->write(mbed->tls_engine->engine, buf->base, buf->len, out, &out_len, out_size);
    if (rc < 0) {
        cb(req, rc);
        free(out);
        return rc;
    }

    if (rc > 0) {
        if (out_len + rc > out_size) {
            out = realloc(out, out_len + rc);
        }
        size_t addt_bytes = 0;
        rc = mbed->tls_engine->api->write(mbed->tls_engine->engine, NULL, 0, out + out_len, &addt_bytes, rc);
        if (rc < 0) {
            UM_LOG(ERR, "TLS write error: %s", mbed->tls_engine->api->strerror(mbed->tls_engine));
            cb(req, rc);
            free(out);
            return rc;
        } else {
            out_len += addt_bytes;
        }
    }


    req->cb = cb;
    return mbed_tcp_write(mbed, out, out_len, req);
}

int uv_mbed_free(uv_mbed_t *mbed) {
    mbed->tls->api->free_engine(mbed->tls_engine);
    return 0;
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str)
{
    printf("%s:%04d: %s", file, line, str );
    fflush(  stdout );
}

static void um_alloc_cb(uv_handle_t *h, size_t suggested_size, uv_buf_t *buf) {
    uv_mbed_t *mbed = h->data;

    // still in handshake, allocate memory internally
    if (mbed->tls_engine->api->handshake_state(mbed->tls_engine->engine) == TLS_HS_CONTINUE) {
        buf->base = (char*) malloc(suggested_size);
        buf->len = buf->base != NULL ? suggested_size : 0;
    } else {
        // call client alloc to allow client signal backpressure via ENOBUFS
        mbed->_stream.alloc_cb((uv_handle_t *) mbed, suggested_size, buf);
    }
}

static void dns_resolve_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    uv_mbed_t *mbed = req->data;

    uv_connect_t *cr = mbed->conn_req;
    UM_LOG(VERB, "resolved status = %d", status);
    if (status < 0) {
        UM_LOG(ERR, "failed to resolve host: %s", uv_strerror(status));
        cr->cb(cr, status);
    } else {
        int rc = uv_mbed_connect_addr(cr, mbed, res, cr->cb);
        if (rc != 0) {
            char *ip = inet_ntoa(((struct sockaddr_in *)res->ai_addr)->sin_addr);
            UM_LOG(ERR, "failed to connect to [%s]: %s", ip, uv_strerror(rc));
            cr->cb(cr, rc);
        }
    }
    uv_freeaddrinfo(res);
    free(req);
}

static void tcp_read_cb (uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    uv_mbed_t *mbed = stream->data;
    if (nread > 0) {
        if (mbed->tls_engine->api->handshake_state(mbed->tls_engine->engine) == TLS_HS_CONTINUE) {
            size_t out_size = 32 * 1024;
            char *out = malloc(out_size);
            size_t out_len;
            tls_handshake_state st = mbed->tls_engine->api->handshake(mbed->tls_engine->engine, buf->base, nread, out,
                                                                      &out_len, out_size);
            if (out_len > 0) {
                mbed_tcp_write(mbed, out, out_len, NULL);
            }
            else {
                free(out);
            }
            if (st == TLS_HS_COMPLETE && mbed->conn_req) {
                mbed->conn_req->cb(mbed->conn_req, 0);
                mbed->conn_req = NULL;
            }

            if (buf->base != NULL) {
                free(buf->base);
            }
        }
        else {
            int rc = TLS_MORE_AVAILABLE;
            ssize_t recv = 0;
            uv_buf_t local_buf;
            while (rc == TLS_MORE_AVAILABLE) {
                // NB: we use client allocated memory in buf for input and output
                rc = mbed->tls_engine->api->read(mbed->tls_engine->engine, buf->base, nread, buf->base, (size_t *) &recv,
                                                     buf->len);
                mbed->_stream.read_cb((uv_stream_t *) mbed, recv, buf);

                if (rc == TLS_MORE_AVAILABLE) {
                    // more data in TSL engine, use local buf
                    mbed->_stream.alloc_cb((uv_handle_t *) mbed, 64 * 1024, &local_buf);
                    if (local_buf.base == 0 || local_buf.len == 0) { // client can't take any more
                        mbed->_stream.read_cb((uv_stream_t*)mbed, ENOBUFS, &local_buf);
                        break;
                    } else {
                        nread = 0;
                        buf = &local_buf;
                    }
                }
            }
        }
    }

    if (nread < 0) {
        // still connecting
       if (mbed->conn_req != NULL) {
            mbed->conn_req->cb(mbed->conn_req, nread);
            mbed->conn_req = NULL;
            free(buf->base);
       }
       else {
            mbed->_stream.read_cb((uv_stream_t *) mbed, nread, buf);
        }
    }
}

static void tcp_connect_cb(uv_connect_t *req, int status) {
    uv_mbed_t *mbed = req->data;
    if (status < 0) {
        mbed->conn_req->cb(mbed->conn_req, status);
    }
    else {
        req->handle->data = mbed;
        uv_read_start(req->handle, um_alloc_cb, tcp_read_cb);
        // start handshake
        size_t out_size = 32 * 1024;
        char *out = malloc(out_size);
        size_t out_len;
        UM_LOG(VERB, "starting handshake");
        mbed->tls_engine->api->handshake(mbed->tls_engine->engine, NULL, 0, out, &out_len, out_size);
        mbed_tcp_write(mbed, out, out_len, NULL);
    }
    free(req);
}

static void on_mbed_close(uv_handle_t *h) {
    uv_mbed_t *mbed = h->data;
    mbed->_stream.close_cb((uv_handle_t *) mbed);
}

static void tcp_shutdown_cb(uv_shutdown_t* req, int status) {
    uv_mbed_t *mbed = req->data;

    uv_close((uv_handle_t *) &mbed->socket, on_mbed_close);
    free(req);
}

static void mbed_tcp_write_cb(uv_write_t *tcp_wr, int status) {
    struct tcp_write_ctx *ctx = tcp_wr->data;
    uv_write_t *ssl_wr = ctx->req;

    if (ssl_wr != NULL) {
        ssl_wr->cb(ssl_wr, status);
    }
    else if (tcp_wr->cb) {
       // tcp_wr->cb(tcp_wr, status);
    }
    free(ctx->buf);
    free(ctx);
    free(tcp_wr);
}

static int mbed_tcp_write(uv_mbed_t *mbed, char *buf, size_t len, uv_write_t *wr) {
    if (len > 0) {
        struct tcp_write_ctx *ctx = malloc(sizeof(struct tcp_write_ctx));
        ctx->buf = buf;
        memcpy(ctx->buf, buf, len);

        ctx->req = wr;

        uv_write_t *tcp_wr = calloc(1, sizeof(uv_write_t));
        tcp_wr->data = ctx;
        uv_buf_t wb = uv_buf_init((char *) ctx->buf, (unsigned int) len);
        return uv_write(tcp_wr, (uv_stream_t *) &mbed->socket, &wb, 1, mbed_tcp_write_cb);
    }
    return 0;
}

