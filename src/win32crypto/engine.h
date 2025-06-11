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

    SCHANNEL_CRED cred;
    CredHandle cred_handle;
    CtxtHandle ctxt_handle;

    tls_handshake_state handshake_st;
    io_ctx io;
    io_read read_fn;
    io_write write_fn;
};

extern struct win32crypto_engine_s* new_win32engine(const char* hostname);

#endif //ENGINE_H
