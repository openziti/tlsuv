//
// Created by eugene on 3/14/19.
//

#ifndef UV_MBED_H
#define UV_MBED_H

#include <uv.h>
#include <mbedtls/ssl.h>

typedef struct uv_mbed_s uv_mbed_t;
typedef struct bio BIO;

int uv_mbed_init(uv_loop_t *l, uv_mbed_t *mbed);
int uv_mbed_set_ca(uv_mbed_t *mbed, mbedtls_x509_crt* ca);
int uv_mbed_set_cert(uv_mbed_t *mbed, mbedtls_x509_crt *cert, mbedtls_pk_context *privkey);

int uv_mbed_connect(uv_connect_t *req, uv_mbed_t* mbed, const char *host, int port, uv_connect_cb cb);
int uv_mbed_connect_addr(uv_connect_t *req, uv_mbed_t* mbed, const struct addrinfo *addr, uv_connect_cb cb);

int uv_mbed_read(uv_mbed_t* client, uv_alloc_cb, uv_read_cb);

int uv_mbed_write(uv_write_t *req, uv_mbed_t *mbed, uv_buf_t *buf, uv_write_cb cb);

int uv_mbed_close(uv_mbed_t* session, uv_close_cb close_cb);

struct uv_mbed_s {
    uv_stream_t _stream;

    uv_tcp_t socket;
    mbedtls_ssl_config ssl_config;
    mbedtls_ssl_context ssl;

    BIO* ssl_in;
    BIO* ssl_out;
};



#endif //UV_MBED_H
