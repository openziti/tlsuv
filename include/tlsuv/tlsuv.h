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

#ifndef TLSUV_H
#define TLSUV_H

#include "connector.h"
#include "tls_engine.h"
#include "queue.h"

#ifdef __cplusplus
extern "C" {
#endif

const char* tlsuv_version();

/**
 * \brief set the path to the TLS config file.
 *
 * This is used to load the default TLS context if current engine supports it
 * @param path path to the config file
 * @return 0 on success, or error code
 */
extern int tlsuv_set_config_path(const char *path);

/**
 * \brief Override the use of the standard library’s malloc(3), calloc(3), realloc(3), free(3),
 * memory allocation functions.
 *
 * calling with method will also use passed functions to call uv_replace_allocator(),
 * and appropriate function(s) in selected TLS engine (if supported)
 * @param malloc_f
 * @param realloc_f
 * @param calloc_f
 * @param free_f
 */
void tlsuv_set_allocator(uv_malloc_func malloc_f,
                         uv_realloc_func realloc_f,
                         uv_calloc_func calloc_f,
                         uv_free_func free_f);

typedef struct tlsuv_stream_s tlsuv_stream_t;

typedef void(*tlsuv_log_func)(int level, const char *file, unsigned int line, const char *msg);
void tlsuv_set_debug(int level, tlsuv_log_func output_f);

int tlsuv_stream_init(uv_loop_t *l, tlsuv_stream_t *clt, tls_context *tls);
void tlsuv_stream_set_connector(tlsuv_stream_t *clt, const tlsuv_connector_t *connector);

int tlsuv_stream_set_protocols(tlsuv_stream_t *clt, int num, const char *protocols[]);
const char* tlsuv_stream_get_protocol(tlsuv_stream_t *clt);
int tlsuv_stream_keepalive(tlsuv_stream_t *clt, int keepalive, unsigned int delay);
int tlsuv_stream_nodelay(tlsuv_stream_t *clt, int nodelay);

/**
 * \brief connect to target server on the given port.
 *
 * connect callback will be called when TLS handshake completes
 * or any error is encountered during connect.
 *
 * @param req connect request
 * @param clt TSL stream
 * @param host server hostname
 * @param port server por
 * @param cb connect callback
 * @return 0, or error code
 */
int tlsuv_stream_connect(uv_connect_t *req, tlsuv_stream_t *clt, const char *host, int port, uv_connect_cb cb);

/**
 * \brief set target server hostname, for SNI and hostname validation
 *
 * hostname is set automatically if [tlsuv_stream_connect()] is used to connect.
 *
 * @param clt TLS stream
 * @param host target hostname
 * @return 0
 */
int tlsuv_stream_set_hostname(tlsuv_stream_t *clt, const char *host);

/**
 * connect TLS stream to server with given network address.
 *
 * connect callback will be called when TLS handshake completes.
 * use [tlsuv_stream_set_hostname()] prior to this to enable SNI and hostname validation.
 *
 * @param req connect request
 * @param clt TLS stream
 * @param addr server address
 * @param cb connect callback
 * @return 0 on success, or error code
 */
int tlsuv_stream_connect_addr(uv_connect_t *req, tlsuv_stream_t *clt, const struct addrinfo *addr, uv_connect_cb cb);

/**
 * \brief wrap TLS stream around connected or connecting socket.
 *
 * connect callback will be called when TLS handshake completes.
 * use [tlsuv_stream_set_hostname()] prior to this to enable SNI and hostname validation.
 *
 * @param req connect request
 * @param clt tls stream client
 * @param fd socket
 * @return 0 on success, or error code
 */
int tlsuv_stream_open(uv_connect_t *req, tlsuv_stream_t *clt, uv_os_sock_t fd, uv_connect_cb);

int tlsuv_stream_read_start(tlsuv_stream_t *clt, uv_alloc_cb alloc_cb, uv_read_cb read_cb);
int tlsuv_stream_read_stop(tlsuv_stream_t *clt);

/**
 * \brief try to write contents of the [buf].
 *
 * @param clt TLS stream
 * @param buf payload
 * @return
 *     number of bytes successfully writen, could be less than `buf.len`
 *     UV_EAGAIN if no data could be written at this time, could be retried later
 *     other error codes, if TLS stream encounters any error, stream should be closed.
 */
int tlsuv_stream_try_write(tlsuv_stream_t *clt, uv_buf_t *buf);

/**
 * \brief write or queue the contents of [buf].
 *
 * @param req write request
 * @param clt TLS stream
 * @param buf data
 * @param cb callback
 * @return 0, or error code
 */
int tlsuv_stream_write(uv_write_t *req, tlsuv_stream_t *clt, uv_buf_t *buf, uv_write_cb cb);

int tlsuv_stream_close(tlsuv_stream_t *clt, uv_close_cb close_cb);

int tlsuv_stream_free(tlsuv_stream_t *clt);

int tlsuv_stream_peername(const tlsuv_stream_t *clt, struct sockaddr *addr, int *namelen);

const char* tlsuv_stream_get_error(const tlsuv_stream_t *clt);

typedef struct tlsuv_write_s tlsuv_write_t;

struct tlsuv_stream_s {
    // make it (somewhat)compatible with uv_stream_t
    UV_HANDLE_FIELDS
#define UV_STREAM_PRIVATE_FIELDS
    UV_STREAM_FIELDS
#undef UV_STREAM_PRIVATE_FIELDS

    const tlsuv_connector_t *connector;
    tlsuv_connector_req connect_req;

    tls_context *tls;
    tlsuv_engine_t tls_engine;

    int authmode;
    int alpn_count;
    const char **alpn_protocols;

    char *host;
    uv_connect_t *conn_req; //a place to stash a connection request

    uv_os_sock_t sock;
    uv_poll_t watcher;

    TAILQ_HEAD(reqs, tlsuv_write_s) queue;
    size_t queue_len;
};

size_t tlsuv_base64url_decode(const char *in, char **out, size_t *out_len);
int tlsuv_base64_encode(const uint8_t *in, size_t in_len, char **out, size_t *out_len);
#ifdef __cplusplus
}
#endif

#endif//TLSUV_H
