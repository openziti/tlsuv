// Copyright (c) 2024. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef TLSUV_CONNECTOR_H
#define TLSUV_CONNECTOR_H

#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum tlsuv_proxy_type {
    tlsuv_PROXY_HTTP,
    // maybe other kinds in the future
} tlsuv_proxy_t;

// connector creates connected sockets
typedef const void* tlsuv_connector_req;
typedef struct tlsuv_connector_s tlsuv_connector_t;
typedef void (*tlsuv_connect_cb)(uv_os_sock_t sock, int status, void *ctx);
typedef tlsuv_connector_req (*tlsuv_connect)(uv_loop_t *loop, const tlsuv_connector_t *connector,
                                             const char *host, const char *port,
                                             tlsuv_connect_cb cb, void *ctx);

extern void tlsuv_set_global_connector(const tlsuv_connector_t* connector);
const tlsuv_connector_t *tlsuv_global_connector();

// proxy connector connects to proxy and does proxy negotiation
tlsuv_connector_t *tlsuv_new_proxy_connector(tlsuv_proxy_t type, const char* host, const char *port);

struct tlsuv_connector_s {
    tlsuv_connect connect;
    void (*cancel)(tlsuv_connector_req);
    void (*free)(void *self);
};


#ifdef __cplusplus
}
#endif

#endif //TLSUV_CONNECTOR_H
