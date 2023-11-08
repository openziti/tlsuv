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
};


int tlsuv_tls_link_init(tls_link_t *tls, tlsuv_engine_t engine, tls_handshake_cb cb);
void tlsuv_tls_link_free(tls_link_t *tls);

#endif//TLSUV_TLS_LINK_H
