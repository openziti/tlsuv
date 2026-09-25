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


#ifndef TLSUV_TLS_LINK_H
#define TLSUV_TLS_LINK_H

typedef struct tls_link_s tls_link_t;
typedef void (*tls_handshake_cb)(tls_link_t *l, int status);
typedef struct ssl_buf_s ssl_buf_t;
struct tls_link_s {
    UV_LINK_FIELDS

    tlsuv_engine_t engine;
    tls_handshake_cb hs_cb;

    ssl_buf_t *ssl_in;  // buffer holding inbound ssl bytes
    ssl_buf_t *ssl_out; // buffer holding outbound ssl_bytes

    // wakes the link when an async engine (see tlsuv_engine_s.setup_async) has
    // handshake output, ciphertext to send, or decrypted data ready
    uv_async_t *async;
    // hs_cb has been told the handshake completed (an async engine can complete
    // it on its own, outside of a handshake() call)
    bool hs_reported;
};


/**
 * @param loop used to receive wakeups from async engines; may be NULL for engines
 *        that do all their work inside handshake/read/write calls
 *
 * If the engine is freed before the link, clear tls->engine first:
 * tlsuv_tls_link_free() detaches itself from the engine it still references.
 */
int tlsuv_tls_link_init(tls_link_t *tls, uv_loop_t *loop, tlsuv_engine_t engine, tls_handshake_cb cb);
void tlsuv_tls_link_free(tls_link_t *tls);

#endif//TLSUV_TLS_LINK_H
