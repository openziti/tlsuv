//
// Created by eugene on 3/14/19.
//

#include <stdlib.h>
#include <string.h>
#include "uv_mbed/uv_mbed.h"
#include "uv-common.h"

#if _WIN32
// this function is declared INLINE in a libuv .h file. As such we have had to 
// duplicate the entire function as well as include the necessary headers to 
// support the function
void uv_stream_init_dup(uv_loop_t* loop,
    uv_stream_t* handle,
    uv_handle_type type) {
    uv__handle_init(loop, (uv_handle_t*)handle, type);
    handle->write_queue_size = 0;
    handle->activecnt = 0;
    handle->stream.conn.shutdown_req = NULL;
    handle->stream.conn.write_reqs_pending = 0;

    UV_REQ_INIT(&handle->read_req, UV_READ);
    handle->read_req.event_handle = NULL;
    handle->read_req.wait_handle = INVALID_HANDLE_VALUE;
    handle->read_req.data = handle;
}
#else
// copy declaration of uv__stream_init() from libuv/src/unix/internal.h to avoid
// breaking when building for iOS-arm64, where the compiler defaults to
// '-Werror=implicit-function-declaration'
void uv__stream_init(uv_loop_t* loop, uv_stream_t* stream, uv_handle_type type);
#endif


static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str);
static void init_ssl(uv_mbed_t *mbed);
static void dns_resolve_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res);

static void tcp_connect_cb(uv_connect_t* req, int status);
static void tcp_shutdown_cb(uv_shutdown_t* req, int status) ;
static int mbed_ssl_send(void* ctx, const uint8_t *buf, size_t len);

static void mbed_tcp_write(uv_mbed_t *mbed, const char *buf, size_t len, uv_write_t *wr);

struct tcp_write_ctx {
    uint8_t *buf;
    uv_write_t *req;
};

static tls_context *DEFAULT_TLS = NULL;

static tls_context *get_default_tls() {
    if (DEFAULT_TLS == NULL) {
        DEFAULT_TLS = default_tls_context(NULL, 0);
    }
    return DEFAULT_TLS;
}

int uv_mbed_init(uv_loop_t *l, uv_mbed_t *mbed, tls_context *tls) {
#if _WIN32
    uv_stream_init_dup(l, (uv_stream_t*)mbed, UV_STREAM);
#else
    uv__stream_init(l, (uv_stream_t*)mbed, UV_STREAM);
#endif
    
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
    char buf[32 * 1024];
    size_t out_len;
    mbed->tls_engine->api->close(mbed->tls_engine->engine, buf, &out_len, sizeof(buf));
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
    uv_getaddrinfo_t *resolve_req = malloc(sizeof(uv_getaddrinfo_t));
    req->handle = (uv_stream_t *) mbed;
    req->cb = cb;
    mbed->conn_req = req;
    
    resolve_req->data = mbed;
    char portstr[6];
    sprintf(portstr, "%d", port);

    mbed->tls_engine = mbed->tls->api->new_engine(mbed->tls->ctx, host);

    return uv_getaddrinfo(loop, resolve_req, dns_resolve_cb, host, portstr, NULL);
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

    int rc = 0;
    int sent = 0;
    char out[32 * 1024];
    size_t out_len;
    mbed->tls_engine->api->write(mbed->tls_engine->engine, buf->base, buf->len, out, &out_len, sizeof(out));

    req->cb = cb;
    mbed_tcp_write(mbed, out, out_len, req);
    return 0;
}

int uv_mbed_free(uv_mbed_t *mbed) {
    mbed->tls->api->free_engine(mbed->tls_engine);
    return 0;
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void) level);
    printf("%s:%04d: %s", file, line, str );
    fflush(  stdout );
}

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char*) malloc(suggested_size);
    buf->len = buf->base != NULL ? suggested_size : 0;
}

static void dns_resolve_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    uv_mbed_t *mbed = req->data;

    uv_connect_t *cr = mbed->conn_req;
    if (status < 0) {
        cr->cb(cr, status);
    }
    else {
        uv_mbed_connect_addr(cr, mbed, res, cr->cb);
    }
    uv_freeaddrinfo(res);
    free(req);
}

static void tcp_read_cb (uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    uv_mbed_t *mbed = stream->data;
    if (nread > 0) {
        if (mbed->tls_engine->api->handshake_state(mbed->tls_engine->engine) == TLS_HS_CONTINUE) {
            char out[32 * 1024];
            size_t out_len;
            tls_handshake_state st = mbed->tls_engine->api->handshake(mbed->tls_engine->engine, buf->base, nread, out,
                                                                      &out_len, sizeof(out));
            if (out_len > 0) {
                mbed_tcp_write(mbed, out, out_len, NULL);
            }
            if (st == TLS_HS_COMPLETE && mbed->conn_req) {
                mbed->conn_req->cb(mbed->conn_req, 0);
                mbed->conn_req = NULL;
            }
        }
        else {
            int rc;
            char *input = buf->base;
            do {
                uv_buf_t b = uv_buf_init(NULL, 0);
                mbed->_stream.alloc_cb((uv_handle_t *) mbed, 64 * 1024, &b);
                ssize_t recv = 0;
                if (b.base == NULL || b.len == 0) {
                    recv = UV_ENOBUFS;
                    rc = TLS_OK;
                }
                else {
                    rc = mbed->tls_engine->api->read(mbed->tls_engine->engine, input, nread, b.base, (size_t *) &recv,
                                                     b.len);
                    input = NULL;
                }
                mbed->_stream.read_cb((uv_stream_t *) mbed, recv, &b);
            } while (rc == TLS_MORE_AVAILABLE);
        }
    }

    if (nread < 0) {
        // still connecting
       if (mbed->conn_req != NULL) {
            mbed->conn_req->cb(mbed->conn_req, nread);
            mbed->conn_req = NULL;
       }
       else if (mbed->_stream.alloc_cb != NULL) {
            uv_buf_t b = uv_buf_init(NULL, 0);
            mbed->_stream.alloc_cb((uv_handle_t *) mbed, 1024, &b);
            mbed->_stream.read_cb((uv_stream_t *) mbed, nread, &b);
        }
    }

    if (buf->base != NULL) {
        free(buf->base);
    }
}

static void tcp_connect_cb(uv_connect_t *req, int status) {
    uv_mbed_t *mbed = req->data;
    if (status < 0) {
        mbed->conn_req->cb(mbed->conn_req, status);
    }
    else {
        req->handle->data = mbed;
        uv_read_start(req->handle, alloc_cb, tcp_read_cb);
        // start handshake
        char out[32 * 1024];
        size_t out_len;
        mbed->tls_engine->api->handshake(mbed->tls_engine->engine, NULL, 0, out, &out_len, sizeof(out));
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

static void mbed_tcp_write(uv_mbed_t *mbed, const char *buf, size_t len, uv_write_t *wr) {
    if (len > 0) {
        struct tcp_write_ctx *ctx = malloc(sizeof(struct tcp_write_ctx));
        ctx->buf = malloc(len);
        memcpy(ctx->buf, buf, len);

        ctx->req = wr;

        uv_write_t *tcp_wr = calloc(1, sizeof(uv_write_t));
        tcp_wr->data = ctx;
        uv_buf_t wb = uv_buf_init((char *) ctx->buf, (unsigned int) len);
        uv_write(tcp_wr, (uv_stream_t *) &mbed->socket, &wb, 1, mbed_tcp_write_cb);
    }
}

