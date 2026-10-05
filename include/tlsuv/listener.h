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

#ifndef TLSUV_LISTENER_H
#define TLSUV_LISTENER_H

#include "tlsuv.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Called once when the TLS handshake of a stream accepted by a [tlsuv_listener_t] finishes.
 *
 * @param clt accepted stream. On [status] != 0 the stream is still open; the application must close it.
 * @param status 0 on success, or a libuv error code.
 */
typedef void (*tlsuv_handshake_cb)(tlsuv_stream_t *clt, int status);



/**
 * \brief TLS server socket: accepts TCP connections and completes the TLS handshake on each.
 *
 * Requires a [tls_context] with a server engine (`new_server_engine != NULL`, i.e. not mbedtls)
 * that has an own certificate set via `set_own_cert()`. The context must be fully configured
 * before [tlsuv_listener_start_listen()].
 */
typedef struct tlsuv_listener_s tlsuv_listener_t;

/**
 * Called for every accepted TCP connection, before any TLS bytes are exchanged, and when accepting fails.
 *
 * @param l listener
 * @param peer address of the remote peer (valid only during the call); NULL when [status] != 0
 * @param status 0 for a new connection, otherwise a libuv error code:
 *        - UV_EMFILE/UV_ENFILE: the process/system is out of file descriptors. The listener shed the
 *          connections that were waiting (accepted and closed them, using a spare descriptor) so that
 *          the event loop does not spin, and keeps listening. The application is under stress: it may want
 *          to stop accepting ([tlsuv_listener_stop_listen()]) or close connections.
 *        - anything else: the listener cannot continue and has stopped, as after [tlsuv_listener_stop_listen()];
 *          the application may resume it with [tlsuv_listener_start_listen()].
 * @return for [status] == 0: memory for the new stream (uninitialised, at least [tlsuv_stream_size()] bytes),
 *         or NULL to refuse the connection. The listener runs [tlsuv_stream_init()] on it, which leaves the
 *         stream's `data` field untouched: the application must initialise `data` (zeroed memory, or
 *         [tlsuv_stream_set_data()]) in this callback, and can use it to find its per-connection context in the
 *         handshake callback. The application owns the stream from here on and must eventually
 *         [tlsuv_stream_close()] it, whatever the handshake outcome.
 *         For [status] != 0 the application may return a stream too, e.g. to find its context through the
 *         stream's `data`, or NULL. A returned stream is initialised by the listener and gets
 *         `handshake_cb(stream, status)` with the same error code; it is the application's to close.
 */
typedef tlsuv_stream_t *(*tlsuv_accept_cb)(tlsuv_listener_t *l, const struct sockaddr *peer, int status);

#define TLSUV_LISTENER_IPV6ONLY 1u

struct tlsuv_listener_s {
    // make it (somewhat) compatible with uv_handle_t: data, loop, close_cb
    UV_HANDLE_FIELDS

    tls_context *tls;
    uv_os_sock_t sock;
    uv_poll_t watcher;
    tlsuv_accept_cb accept_cb;
    tlsuv_handshake_cb handshake_cb;
    int spare_fd; // POSIX: a duplicate of `sock`, kept to be able to shed the backlog when out of descriptors
    char **alpn;
    int alpn_count;
    unsigned bound : 1;
    unsigned listening : 1;
    unsigned started : 1;
    unsigned closing : 1;
};

/**
 * \brief initialize the listener. Like libuv's init functions it leaves the `data` field untouched, so
 * [l] must have `data` initialised (zeroed memory, or set it before this call) or it is read as garbage.
 *
 * @param tls server TLS context (own certificate set before the first connection arrives); not owned by the
 *        listener, must outlive it.
 * @return 0, UV_EINVAL if [tls] is NULL, or UV_ENOTSUP if the TLS backend has no server engine
 *         (`new_server_engine == NULL`, e.g. mbedtls). The listener is not initialised on error.
 */
int tlsuv_listener_init(uv_loop_t *loop, tlsuv_listener_t *l, tls_context *tls);

/** ALPN protocols offered to every accepted connection. Strings are copied. Applies to connections accepted afterwards. */
int tlsuv_listener_set_protocols(tlsuv_listener_t *l, int count, const char *protocols[]);

/** bind to [addr] (v4 or v6). [flags]: TLSUV_LISTENER_IPV6ONLY. UV_EALREADY if already bound. */
int tlsuv_listener_bind(tlsuv_listener_t *l, const struct sockaddr *addr, unsigned flags);

/**
 * Start (or, after [tlsuv_listener_stop_listen()], resume) accepting connections.
 * `handshake_cb` fires once per stream returned by `accept_cb`. Both callbacks are required.
 *
 * @return 0, UV_EINVAL (not bound / NULL callback / closed),
 *         UV_EALREADY (already started), or a socket error
 */
int tlsuv_listener_start_listen(tlsuv_listener_t *l, int backlog, tlsuv_accept_cb accept_cb,
                                tlsuv_handshake_cb handshake_cb);

/** stop accepting; pending connections stay queued in the kernel backlog. Streams already accepted are unaffected. */
int tlsuv_listener_stop_listen(tlsuv_listener_t *l);

int tlsuv_listener_getsockname(const tlsuv_listener_t *l, struct sockaddr *name, int *namelen);

/** close the listener. Accepted streams are independent and unaffected. [close_cb] gets the listener cast to uv_handle_t*. */
int tlsuv_listener_close(tlsuv_listener_t *l, uv_close_cb close_cb);

size_t tlsuv_listener_size(void);
tlsuv_listener_t *tlsuv_listener_new(void);
void tlsuv_listener_delete(tlsuv_listener_t *l);
void tlsuv_listener_set_data(tlsuv_listener_t *l, void *data);
void *tlsuv_listener_get_data(const tlsuv_listener_t *l);

#ifdef __cplusplus
}
#endif

#endif // TLSUV_LISTENER_H
