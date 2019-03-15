//
// Created by eugene on 3/14/19.
//

#include <stdlib.h>
#include <string.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include "uv_mbed.h"
#include "bio.h"


void uv__stream_init(uv_loop_t* loop, uv_stream_t* s, uv_handle_type type);

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str);
static void init_ssl(uv_mbed_t *mbed);
static void dns_resolve_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res);

static void tcp_connect_cb(uv_connect_t* req, int status);
static void tcp_shutdown_cb(uv_shutdown_t* req, int status) ;

static void mbed_ssl_free(uv_mbed_t *mbed);
static void mbed_ssl_process_in(uv_mbed_t *mbed);

static void mbed_ssl_process_out(uv_mbed_t *mbed, uv_write_t *wr);
static int mbed_ssl_recv(void* ctx, uint8_t *buf, size_t len);
static int mbed_ssl_send(void* ctx, const uint8_t *buf, size_t len);

static void mbed_continue_handshake(uv_mbed_t *mbed);

struct tcp_write_ctx {
    uint8_t *buf;
    uv_write_t *req;
};


int uv_mbed_init(uv_loop_t *l, uv_mbed_t *mbed) {
    uv__stream_init(l, (uv_stream_t *) mbed, UV_STREAM);

    uv_tcp_init(l, &mbed->socket);
    init_ssl(mbed);

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

int uv_mbed_connect_addr(uv_connect_t *req, uv_mbed_t* mbed, const struct addrinfo *addr, uv_connect_cb cb) {

    if (mbed->_stream.connect_req != NULL && mbed->_stream.connect_req != req) {
        return UV_EALREADY;
    }
    req->handle = (uv_stream_t *) mbed;
    req->cb = cb;
    mbed->_stream.connect_req = req;


    uv_connect_t *tcp_cr = calloc(1, sizeof(uv_connect_t));
    tcp_cr->data = mbed;
    return uv_tcp_connect(tcp_cr, &mbed->socket, addr->ai_addr, tcp_connect_cb);
}

int uv_mbed_close(uv_mbed_t *mbed, uv_close_cb close_cb) {
    mbed->_stream.close_cb = close_cb;
    mbedtls_ssl_close_notify(&mbed->ssl);
    uv_shutdown_t *sr = malloc(sizeof(uv_shutdown_t));
    sr->data = mbed;
    return uv_shutdown(sr, (uv_stream_t *) &mbed->socket, tcp_shutdown_cb);
}


int uv_mbed_connect(uv_connect_t *req, uv_mbed_t *mbed, const char *host, int port, uv_connect_cb cb) {
    uv_loop_t *loop = mbed->_stream.loop;
    uv_getaddrinfo_t *resolve_req = malloc(sizeof(uv_getaddrinfo_t));
    req->handle = (uv_stream_t *) mbed;
    req->cb = cb;

    mbed->_stream.connect_req = req;

    resolve_req->data = mbed;
    char portstr[6];
    sprintf(portstr, "%d", port);
    return uv_getaddrinfo(loop, resolve_req, dns_resolve_cb, host, portstr, NULL);
}

int uv_mbed_read(uv_mbed_t *mbed, uv_alloc_cb alloc_cb, uv_read_cb read_cb) {
    mbed->_stream.alloc_cb = alloc_cb;
    mbed->_stream.read_cb = read_cb;
    return 0;
}

int uv_mbed_write(uv_write_t *req, uv_mbed_t *mbed, uv_buf_t *buf, uv_write_cb cb) {
    req->handle = (uv_stream_t *) mbed;
    int rc = mbedtls_ssl_write(&mbed->ssl, buf->base, buf->len);

    if (rc >= 0) {
        req->handle = (uv_stream_t *) mbed;
        req->cb = cb;

        mbed_ssl_process_out(mbed, req);
    }
    else {
        cb(req, rc);
        return rc;
    }
    return 0;
}

static void init_ssl(uv_mbed_t *mbed) {
    char *tls_debug = getenv("MBEDTLS_DEBUG");
    if (tls_debug != NULL) {
        int level = (int) strtol(tls_debug, NULL, 10);
        mbedtls_debug_set_threshold(level);
    }

    mbedtls_ssl_config_init(&mbed->ssl_config);
    mbedtls_ssl_conf_dbg(&mbed->ssl_config, tls_debug_f, stdout);
    mbedtls_ssl_config_defaults(&mbed->ssl_config,
                                 MBEDTLS_SSL_IS_CLIENT,
                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                 MBEDTLS_SSL_PRESET_DEFAULT );
    mbedtls_ssl_conf_authmode(&mbed->ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ctr_drbg_context *drbg = calloc(1, sizeof(mbedtls_ctr_drbg_context));
    mbedtls_entropy_context *entropy = calloc(1, sizeof(mbedtls_entropy_context));
    mbedtls_ctr_drbg_init(drbg);
    mbedtls_entropy_init(entropy);
    unsigned char *seed = malloc(MBEDTLS_ENTROPY_MAX_SEED_SIZE); // uninitialized memory
    mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, entropy, seed, MBEDTLS_ENTROPY_MAX_SEED_SIZE);
    mbedtls_ssl_conf_rng(&mbed->ssl_config, mbedtls_ctr_drbg_random, drbg);

    mbedtls_ssl_init(&mbed->ssl);
    mbedtls_ssl_setup(&mbed->ssl, &mbed->ssl_config);

    mbed->ssl_in = BIO_new();
    mbed->ssl_out = BIO_new();
    mbedtls_ssl_set_bio(&mbed->ssl, mbed, mbed_ssl_send, mbed_ssl_recv, NULL);

    free(seed);
}

static void mbed_ssl_free(uv_mbed_t *mbed) {
    BIO_free(mbed->ssl_in);
    BIO_free(mbed->ssl_out);
    mbedtls_ssl_free(&mbed->ssl);

    mbedtls_ctr_drbg_context *rng = mbed->ssl_config.p_rng;
    mbedtls_entropy_free(rng->p_entropy);
    free(rng->p_entropy);
    mbedtls_ctr_drbg_free(rng);
    free(rng);

    mbedtls_ssl_config_free(&mbed->ssl_config);
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void) level);
    printf("%s:%04d: %s", file, line, str );
    fflush(  stdout );
}

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char*) malloc(suggested_size);
    buf->len = suggested_size;
}

static void dns_resolve_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    uv_mbed_t *mbed = req->data;

    uv_connect_t *cr = mbed->_stream.connect_req;
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
        BIO_put(mbed->ssl_in, buf->base, (size_t) nread);
        mbed_ssl_process_in(mbed);
    }

    if (nread < 0) {
        // still connecting
        if (mbed->_stream.connect_req != NULL) {
            mbed->_stream.connect_req->cb(mbed->_stream.connect_req, nread);
            mbed->_stream.connect_req = NULL;
        }
        else if (mbed->_stream.alloc_cb != NULL) {
            uv_buf_t b = uv_buf_init(NULL, 0);
            mbed->_stream.alloc_cb((uv_handle_t *) mbed, 1024, &b);
            mbed->_stream.read_cb((uv_stream_t *) mbed, nread, &b);
        }
    }

    free(buf->base);
}

static void tcp_connect_cb(uv_connect_t *req, int status) {
    uv_mbed_t *mbed = req->data;
    if (status < 0) {
        mbed->_stream.connect_req->cb(mbed->_stream.connect_req, status);
    }
    else {
        req->handle->data = mbed;
        uv_read_start(req->handle, alloc_cb, tcp_read_cb);
        mbed_ssl_process_in(mbed);
    }
    free(req);
}

static void tcp_shutdown_cb(uv_shutdown_t* req, int status) {
    uv_mbed_t *mbed = req->data;

    mbed_ssl_free(mbed);
    mbed->_stream.close_cb((uv_handle_t *) mbed);

    free(req);
}

static void mbed_tcp_write_cb(uv_write_t *tcp_wr, int status) {
    struct tcp_write_ctx *ctx = tcp_wr->data;
    uv_write_t *ssl_wr = ctx->req;

    if (ssl_wr != NULL) {
        ssl_wr->cb(ssl_wr, status);
    }
    else if (tcp_wr->cb) {
        tcp_wr->cb(tcp_wr, status);
    }
    free(ctx->buf);
    free(ctx);
    free(tcp_wr);
}

static int mbed_ssl_recv(void* ctx, uint8_t *buf, size_t len) {
    uv_mbed_t *mbed = ctx;
    if (BIO_available(mbed->ssl_in) == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    return BIO_read(mbed->ssl_in, buf, len);
}

static int mbed_ssl_send(void* ctx, const uint8_t *buf, size_t len) {
    uv_mbed_t *mbed = ctx;
    BIO *out = mbed->ssl_out;
    BIO_put(out, buf, len);
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
        if (mbed->_stream.read_cb != NULL) {
            uv_buf_t buf = uv_buf_init(NULL, 0);
            mbed->_stream.alloc_cb((uv_handle_t *) mbed, 8 * 1024, &buf);
            int recv = mbedtls_ssl_read(&mbed->ssl, (uint8_t *)buf.base, buf.len);
            mbed->_stream.read_cb((uv_stream_t *) mbed, recv, &buf);
        }
    }
}

static void mbed_continue_handshake(uv_mbed_t *mbed) {
    int rc = mbedtls_ssl_handshake(&mbed->ssl);
    if (rc == 0) {
        mbed->_stream.connect_req->cb(mbed->_stream.connect_req, 0);
        mbed->_stream.connect_req = NULL;
    }
    else if (rc == MBEDTLS_ERR_SSL_WANT_WRITE || rc == MBEDTLS_ERR_SSL_WANT_READ) {
        uv_write_t *hsw = calloc(1, sizeof(uv_write_t));
        hsw->cb = mbed_hs_write_cb;
        hsw->handle = (uv_stream_t *) mbed;
        mbed_ssl_process_out(mbed, hsw);
    }
}

static void mbed_ssl_process_out(uv_mbed_t *mbed, uv_write_t *wr) {
    BIO *out = mbed->ssl_out;
    size_t avail = BIO_available(out);
    if (avail > 0) {
        struct tcp_write_ctx *ctx = malloc(sizeof(struct tcp_write_ctx));
        ctx->buf = malloc(avail);
        ctx->req = wr;

        int len = BIO_read(out, ctx->buf, avail);
        uv_write_t *tcp_wr = calloc(1, sizeof(uv_write_t));
        tcp_wr->data = ctx;
        uv_buf_t wb = uv_buf_init((char *) ctx->buf, (unsigned int) len);
        uv_write(tcp_wr, (uv_stream_t *) &mbed->socket, &wb, 1, mbed_tcp_write_cb);

    }
    else {
        wr->cb(wr, MBEDTLS_ERR_SSL_WANT_WRITE);
    }
}

