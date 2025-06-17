// Copyright (c) 2025. NetFoundry Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
//         https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//

#ifndef ENGINE_H
#define ENGINE_H

#include <tlsuv/tls_engine.h>

#include <schannel.h>
#include <sspi.h>

struct win32crypto_engine_s {
    struct tlsuv_engine_s api;
    char *hostname;

    // requested protocols
    char *protocols;
    size_t protocols_len;
    // negotiated protocol
    char *alpn;

    int (*cert_verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx);
    void *verify_ctx;
    HCERTSTORE ca;
    CredHandle cred_handle;
    CtxtHandle ctxt_handle;
    SecPkgContext_StreamSizes sizes;

    SECURITY_STATUS status;
    tls_handshake_state handshake_st;
    io_ctx io;
    io_read read_fn;
    io_write write_fn;
    char outbound[32 * 1024];
    size_t outbound_len;
    char inbound[32 * 1024];
    size_t inbound_len;
    char decoded[32 * 1024];
    size_t decoded_len;
};

extern struct win32crypto_engine_s *new_win32engine(
    const char *hostname, HCERTSTORE ca, PCCERT_CONTEXT own_cert,
    int (*cert_verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx),
    void *verify_ctx);

#endif //ENGINE_H
