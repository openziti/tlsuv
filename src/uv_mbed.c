//
// Created by eugene on 3/14/19.
// Modified by ssrlive
//

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include "uv_mbed/uv_mbed.h"
#include "bio.h"

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str);
static void init_ssl(uv_mbed_t *mbed, int dump_level);
static void dns_resolve_done_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res);

static int uv_mbed_connect_addr(uv_connect_t *req, uv_mbed_t* mbed, const struct addrinfo *addr, uv_connect_cb cb);
static void tcp_connect_established_cb(uv_connect_t* req, int status);
static void tcp_shutdown_cb(uv_shutdown_t* req, int status) ;

static void mbed_ssl_process_in(uv_mbed_t *mbed);

static void mbed_ssl_process_out(uv_mbed_t *mbed, uv_write_t *wr);
static int mbed_ssl_recv(void* ctx, uint8_t *buf, size_t len);
static int mbed_ssl_send(void* ctx, const uint8_t *buf, size_t len);

static void mbed_continue_handshake(uv_mbed_t *mbed);

struct tcp_write_ctx {
    uint8_t *buf;
    uv_write_t *req;
};

int uv_mbed_init(uv_loop_t *loop, uv_mbed_t *mbed, int dump_level) {
    uv_tcp_init(loop, &mbed->socket);
    init_ssl(mbed, dump_level);
    return 0;
}

int uv_mbed_set_ca(uv_mbed_t *mbed, mbedtls_x509_crt* ca) {
    mbedtls_ssl_conf_ca_chain(&mbed->ssl_config, ca, NULL);
    return 0;
}

int uv_mbed_set_cert(uv_mbed_t *mbed, mbedtls_x509_crt *cert, mbedtls_pk_context *privkey) {
    mbedtls_ssl_conf_own_cert(&mbed->ssl_config, cert, privkey);
    return 0;
}

static int uv_mbed_connect_addr(uv_connect_t *req, uv_mbed_t* mbed, const struct addrinfo *addr, uv_connect_cb cb) {
    uv_connect_t *tcp_cr;
    uv_stream_t *stream = &mbed->_stream;

    if (mbed->connect_req != NULL && mbed->connect_req != req) {
        return UV_EALREADY;
    }
    req->handle = stream;
    req->cb = cb;
    mbed->connect_req = req;

    tcp_cr = (uv_connect_t *) calloc(1, sizeof(uv_connect_t));
    tcp_cr->data = mbed;
    return uv_tcp_connect(tcp_cr, &mbed->socket, addr->ai_addr, tcp_connect_established_cb);
}

static void on_close_write(uv_write_t *req, int status) {
    uv_mbed_t *mbed = container_of(req->handle, uv_mbed_t, _stream);

    uv_shutdown_t *sr = (uv_shutdown_t *)calloc(1, sizeof(uv_shutdown_t));
    sr->data = mbed;
    uv_shutdown(sr, (uv_stream_t *) &mbed->socket, tcp_shutdown_cb);
    free(req);
}

int uv_mbed_close(uv_mbed_t *mbed, uv_mbed_close_cb close_cb, void *p) {
    int rc;
    uv_write_t *wr;
    mbed->close_cb = close_cb;
    mbed->close_cb_p = p;
    rc = mbedtls_ssl_close_notify(&mbed->ssl);

    wr = (uv_write_t *) calloc(1, sizeof(uv_write_t));
    wr->handle = (uv_stream_t *)mbed;
    wr->cb = on_close_write;
    mbed_ssl_process_out(mbed, wr);
    return 0;
}

int uv_mbed_connect(uv_connect_t *req, uv_mbed_t *mbed, const char *host, int port, uv_connect_cb cb) {
    char portstr[6] = { 0 };
    uv_loop_t *loop = mbed->socket.loop;
    uv_getaddrinfo_t *resolve_req = (uv_getaddrinfo_t *)calloc(1, sizeof(uv_getaddrinfo_t));
    req->handle = (uv_stream_t *) mbed;
    req->cb = cb;

    mbed->connect_req = req;

    resolve_req->data = mbed;
    sprintf(portstr, "%d", port);
    return uv_getaddrinfo(loop, resolve_req, dns_resolve_done_cb, host, portstr, NULL);
}

int uv_mbed_set_blocking(uv_mbed_t *um, int blocking) {
    return uv_stream_set_blocking((uv_stream_t *) &um->socket, blocking);
}

int uv_mbed_read(uv_mbed_t *mbed, uv_alloc_cb alloc_cb, uv_read_cb read_cb) {
    mbed->alloc_cb = alloc_cb;
    mbed->read_cb = read_cb;
    return 0;
}

int uv_mbed_write(uv_write_t *req, uv_mbed_t *mbed, uv_buf_t *buf, uv_write_cb cb) {
    int rc = 0;
    int sent = 0;

    req->handle = & mbed->_stream;

    while (sent < (int) buf->len) {
        rc = mbedtls_ssl_write(&mbed->ssl, (unsigned char *)(buf->base + sent), buf->len - sent);

        if (rc >= 0) {
            sent += rc;
        }

        if (rc < 0) {
            break;
        }
    }

    if (sent > 0) {
        req->cb = cb;
        mbed_ssl_process_out(mbed, req);
        rc = 0;
    }
    else {
        cb(req, rc);
    }
    return rc;
}

static void init_ssl(uv_mbed_t *mbed, int dump_level) {
    mbedtls_ctr_drbg_context *drbg;
    mbedtls_entropy_context *entropy;
    unsigned char *seed;

    mbedtls_debug_set_threshold(dump_level);

    mbedtls_ssl_config_init(&mbed->ssl_config);
    mbedtls_ssl_conf_dbg(&mbed->ssl_config, tls_debug_f, stdout);
    mbedtls_ssl_config_defaults(&mbed->ssl_config,
                                 MBEDTLS_SSL_IS_CLIENT,
                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                 MBEDTLS_SSL_PRESET_DEFAULT );
    mbedtls_ssl_conf_authmode(&mbed->ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
    drbg = (mbedtls_ctr_drbg_context *) calloc(1, sizeof(mbedtls_ctr_drbg_context));
    entropy = (mbedtls_entropy_context *) calloc(1, sizeof(mbedtls_entropy_context));
    mbedtls_ctr_drbg_init(drbg);
    mbedtls_entropy_init(entropy);
    seed = (unsigned char *) malloc(MBEDTLS_ENTROPY_MAX_SEED_SIZE); // uninitialized memory
    mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, entropy, seed, MBEDTLS_ENTROPY_MAX_SEED_SIZE);
    mbedtls_ssl_conf_rng(&mbed->ssl_config, mbedtls_ctr_drbg_random, drbg);

    mbedtls_ssl_init(&mbed->ssl);
    mbedtls_ssl_setup(&mbed->ssl, &mbed->ssl_config);

    mbed->ssl_in = bio_new();
    mbed->ssl_out = bio_new();
    mbedtls_ssl_set_bio(&mbed->ssl, mbed, mbed_ssl_send, mbed_ssl_recv, NULL);

    free(seed);
}

int uv_mbed_free(uv_mbed_t *mbed) {
    mbedtls_ctr_drbg_context *rng;
    mbedtls_entropy_context *ctx;
    bio_free(mbed->ssl_in);
    bio_free(mbed->ssl_out);
    mbedtls_ssl_free(&mbed->ssl);

    rng = (mbedtls_ctr_drbg_context *) mbed->ssl_config.p_rng;
    ctx = (mbedtls_entropy_context *)rng->p_entropy;
    mbedtls_entropy_free(ctx);
    free(ctx);
    mbedtls_ctr_drbg_free(rng);
    free(rng);

    mbedtls_ssl_config_free(&mbed->ssl_config);
    return 0;
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void) level);
    printf("%s:%04d: %s", file, line, str );
    fflush(  stdout );
}

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    char *base = (char*) calloc(suggested_size, sizeof(*base));
    *buf = uv_buf_init(base, suggested_size);
}

static void dns_resolve_done_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    uv_mbed_t *mbed = (uv_mbed_t *) req->data;

    uv_connect_t *cr = mbed->connect_req;
    if (status < 0) {
        cr->cb(cr, status);
    }
    else {
        uv_mbed_connect_addr(cr, mbed, res, cr->cb);
    }
    uv_freeaddrinfo(res);
    free(req);
}

static void tcp_read_done_cb (uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    uv_mbed_t *mbed = (uv_mbed_t *) stream->data;
    assert(stream == (uv_stream_t *) &mbed->socket);
    if (nread > 0) {
        bio_put(mbed->ssl_in, (uint8_t *)buf->base, (size_t) nread);
        mbed_ssl_process_in(mbed);
    }

    if (nread < 0) {
        // still connecting
        if (mbed->connect_req != NULL) {
            mbed->connect_req->cb(mbed->connect_req, nread);
            mbed->connect_req = NULL;
        }
        else if (mbed->alloc_cb != NULL) {
            uv_buf_t b = uv_buf_init(NULL, 0);
            mbed->alloc_cb((uv_handle_t *) mbed, 1024, &b);
            mbed->read_cb((uv_stream_t *) mbed, nread, &b);
        }
    }

    free(buf->base);
}

static void tcp_connect_established_cb(uv_connect_t *req, int status) {
    uv_mbed_t *mbed = (uv_mbed_t *) req->data;
    if (status < 0) {
        mbed->connect_req->cb(mbed->connect_req, status);
    }
    else {
        uv_stream_t* socket = req->handle;
        assert(socket == (uv_stream_t*)&mbed->socket);
        socket->data = mbed;
        uv_read_start(socket, alloc_cb, tcp_read_done_cb);
        mbed_ssl_process_in(mbed);
    }
    free(req);
}

static void on_mbed_close(uv_handle_t *h) {
    uv_mbed_t *mbed = (uv_mbed_t *) h->data;
    mbed->close_cb(mbed, mbed->close_cb_p);
}


static void tcp_shutdown_cb(uv_shutdown_t* req, int status) {
    uv_mbed_t *mbed = (uv_mbed_t *) req->data;

    uv_close((uv_handle_t *) &mbed->socket, on_mbed_close);
    free(req);
}

static void mbed_tcp_write_done_cb(uv_write_t *req, int status) {
    struct tcp_write_ctx *ctx = (struct tcp_write_ctx *) req->data;
    uv_write_t *ssl_wr = ctx->req;

    if (ssl_wr != NULL) {
        ssl_wr->cb(ssl_wr, status);
    }
    free(ctx->buf);
    free(ctx);
    free(req);
}

static int mbed_ssl_recv(void* ctx, uint8_t *buf, size_t len) {
    uv_mbed_t *mbed = (uv_mbed_t *) ctx;
    if (bio_available(mbed->ssl_in) == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    return (int) bio_read(mbed->ssl_in, buf, len);
}

static int mbed_ssl_send(void* ctx, const uint8_t *buf, size_t len) {
    uv_mbed_t *mbed = (uv_mbed_t *) ctx;
    struct bio *out = mbed->ssl_out;
    bio_put(out, buf, len);
    return (int) len;
}

static void mbed_hs_write_cb(uv_write_t *hsw, int status) {
    if (status != MBEDTLS_ERR_SSL_WANT_WRITE) {
        uv_mbed_t *mbed = (uv_mbed_t *) hsw->handle;
        mbed_continue_handshake(mbed);
    }
    free(hsw);
}

static void mbed_ssl_process_in(uv_mbed_t *mbed) {
    if (mbed->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
        mbed_continue_handshake(mbed);
    }
    else {
        if (mbed->read_cb != NULL) {
            if (bio_available(mbed->ssl_in) > 0) {
                size_t  recv = 0;
                uv_buf_t buf = uv_buf_init(NULL, 0);
                mbed->alloc_cb((uv_handle_t *) mbed, 64 * 1024, &buf);
                while (bio_available(mbed->ssl_in) > 0 && (buf.len - recv) > 0) {
                    int read = mbedtls_ssl_read(&mbed->ssl, (uint8_t *) buf.base + recv, buf.len - recv);
                    if (read < 0) break;
                    recv += read;
                }
                mbed->read_cb((uv_stream_t *) mbed, recv, &buf);
            }
        }
    }
}

static void mbed_continue_handshake(uv_mbed_t *mbed) {
    int rc = mbedtls_ssl_handshake(&mbed->ssl);
    if (rc == 0) {
        mbed->connect_req->cb(mbed->connect_req, 0);
        mbed->connect_req = NULL;
    }
    else if (rc == MBEDTLS_ERR_SSL_WANT_WRITE || rc == MBEDTLS_ERR_SSL_WANT_READ) {
        uv_write_t *hsw = (uv_write_t *) calloc(1, sizeof(uv_write_t));
        hsw->cb = mbed_hs_write_cb;
        hsw->handle = (uv_stream_t *) mbed;
        mbed_ssl_process_out(mbed, hsw);
    }
}

static void mbed_ssl_process_out(uv_mbed_t *mbed, uv_write_t *wr) {
    struct bio *out = mbed->ssl_out;
    size_t avail = bio_available(out);

    if (avail <= 0) {
        // how did we get here?
        wr->cb(wr, MBEDTLS_ERR_SSL_WANT_WRITE);
    }

    while (avail > 0) {
        int len;
        uv_write_t *tcp_wr;
        uv_buf_t wb;
        struct tcp_write_ctx *ctx = (struct tcp_write_ctx *) calloc(1, sizeof(*ctx));
        ctx->buf = (uint8_t *)calloc(avail, sizeof(uint8_t));

        len = (int) bio_read(out, ctx->buf, avail);
        if (len == avail) {
            ctx->req = wr;
        } else {
            ctx->req = NULL;
        }
        tcp_wr = (uv_write_t *) calloc(1, sizeof(uv_write_t));
        tcp_wr->data = ctx;
        wb = uv_buf_init((char *) ctx->buf, (unsigned int) len);
        uv_write(tcp_wr, (uv_stream_t *) &mbed->socket, &wb, 1, mbed_tcp_write_done_cb);
        avail = bio_available(out);
    }
}

