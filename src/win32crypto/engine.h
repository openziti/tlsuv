//
// Created by eugen on 6/11/2025.
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

extern struct win32crypto_engine_s *new_win32engine(const char *hostname, HCERTSTORE ca, PCCERT_CONTEXT own_cert);

#endif //ENGINE_H
