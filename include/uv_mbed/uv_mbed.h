//
// Created by eugene on 3/14/19.
//

#ifndef UV_MBED_H
#define UV_MBED_H

#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

struct uv_mbed_s;
typedef struct uv_mbed_s uv_mbed_t;

uv_mbed_t * uv_mbed_init(uv_loop_t *loop, void *user_data, int dump_level);
void * uv_mbed_user_data(uv_mbed_t *mbed);
int uv_mbed_set_ca(uv_mbed_t *mbed, const char *root_cert_file);
//int uv_mbed_set_cert(uv_mbed_t *mbed, mbedtls_x509_crt *cert, mbedtls_pk_context *privkey);
int uv_mbed_keepalive(uv_mbed_t *mbed, int keepalive, unsigned int delay);
int uv_mbed_nodelay(uv_mbed_t *mbed, int nodelay);
int uv_mbed_set_blocking(uv_mbed_t* mbed, int blocking);

typedef void (*uv_mbed_connect_cb)(uv_mbed_t* mbed, int status, void *p);
int uv_mbed_connect(uv_mbed_t* mbed, const char *host, int port, uv_mbed_connect_cb cb, void *p);

typedef void (*uv_mbed_alloc_cb)(uv_mbed_t *mbed, size_t suggested_size, uv_buf_t* buf, void *p);
typedef void (*uv_mbed_read_cb)(uv_mbed_t *mbed, ssize_t nread, uv_buf_t* buf, void *p);
int uv_mbed_read(uv_mbed_t *mbed, uv_mbed_alloc_cb, uv_mbed_read_cb, void*);

typedef void (*uv_mbed_write_cb)(uv_mbed_t *mbed, int status, void *p);
int uv_mbed_write(uv_mbed_t *mbed, const uv_buf_t *buf, uv_mbed_write_cb cb, void *p);

typedef void (*uv_mbed_close_cb)(uv_mbed_t *mbed, void *p);
int uv_mbed_close(uv_mbed_t *mbed, uv_mbed_close_cb close_cb, void *p);
int uv_mbed_free(uv_mbed_t *mbed);

#ifdef __cplusplus
}
#endif

#endif //UV_MBED_H
