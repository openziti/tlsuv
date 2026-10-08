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
 *
 * Once bound, a listener is also a libuv handle: a `tlsuv_listener_t *` can be cast to `uv_handle_t *` to read its
 * state (`uv_handle_get_type()`, `uv_is_active()`, `uv_is_closing()`, `uv_walk()`) and to `uv_ref()`/`uv_unref()` it,
 * e.g. to let the loop exit while the listener is still listening. `uv_handle_t *` is the only handle type to use:
 * underneath it is a `UV_POLL` handle (what `uv_handle_get_type()` reports), but it is not a `uv_stream_t` or
 * `uv_tcp_t`, so `uv_listen()`, `uv_accept()` and the other `uv_stream_*` calls do not apply; accepting is done by
 * the listener and reported through [tlsuv_accept_cb].
 * `data` and `loop` are valid from [tlsuv_listener_init()] on; everything else only after [tlsuv_listener_bind()].
 * Do not change the handle itself (`uv_close()`, `uv_poll_start()`, `uv_poll_stop()`): use
 * [tlsuv_listener_close()], [tlsuv_listener_start_listen()] and [tlsuv_listener_stop_listen()].
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
    // Must stay the first member: a tlsuv_listener_t* is also a pointer to this poll handle, which is how the
    // listener doubles as a uv_handle_t (see above). Its `data` and `loop` are the listener's; the handle itself
    // is initialised by tlsuv_listener_bind().
    uv_poll_t watcher;

    tls_context *tls;
    uv_os_sock_t sock;
    tlsuv_accept_cb accept_cb;
    tlsuv_handshake_cb handshake_cb;
    uv_close_cb close_cb; // the application's: uv_close() sets the handle's own close_cb to an internal one
    int spare_fd; // POSIX: an unused socket of `sock`'s family, closed to make room to shed the backlog when out of descriptors
    char **alpn;
    int alpn_count;
    unsigned bound : 1;
    unsigned listening : 1;
    unsigned started : 1;
    unsigned closing : 1;
};

/**
 * \brief initialize the listener. Like libuv's init functions it leaves the handle's `data` field untouched, so
 * [l] must have `data` initialised (zeroed memory, or [tlsuv_listener_set_data()] before this call) or it is read
 * as garbage.
 *
 * @param tls server TLS context (own certificate set before the first connection arrives); not owned by the
 *        listener, must outlive it.
 * @return 0, UV_EINVAL if [tls] is NULL, or UV_ENOTSUP if the TLS backend has no server engine
 *         (`new_server_engine == NULL`, e.g. mbedtls). The listener is not initialised on error.
 */
int tlsuv_listener_init(uv_loop_t *loop, tlsuv_listener_t *l, tls_context *tls);

/**
 * ALPN protocols offered to every accepted connection. Strings are copied. Applies to connections accepted afterwards.
 * A [count] of 0 clears the list.
 *
 * @return 0, UV_EINVAL (closed, negative [count], NULL [protocols] with a [count] above 0, or a NULL entry; the
 *         current list is kept), or UV_ENOMEM
 */
int tlsuv_listener_set_protocols(tlsuv_listener_t *l, int count, const char *protocols[]);

/**
 * bind to [addr] (v4 or v6). [flags]: TLSUV_LISTENER_IPV6ONLY.
 *
 * @return 0, UV_EALREADY (already bound), UV_EINVAL (closed, or [addr] is NULL or neither AF_INET nor AF_INET6),
 *         or a socket error
 */
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

/**
 * close the listener; use this instead of `uv_close()`. Accepted streams are independent and unaffected.
 * [close_cb] gets the listener as a `uv_handle_t *` (the same address as the `tlsuv_listener_t *`, so cast it back
 * to reach the listener). The socket is already closed when it runs. It is deferred to the loop in every state,
 * including a listener that was never bound.
 */
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
