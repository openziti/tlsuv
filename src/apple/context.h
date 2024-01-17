//
// Created by Eugene Kobyakov on 1/12/24.
//

#ifndef TLSUV_CONTEXT_H
#define TLSUV_CONTEXT_H

#include "tlsuv/tls_engine.h"
#include <Security/Security.h>

struct sectransport_ctx {
    tls_context api;

    CFArrayRef ca_bundle;
};

struct sectransport_priv_key {
    struct tlsuv_private_key_s api;
    SecKeyRef key;
    CFStringRef key_type;
    CFDataRef pem;
};

struct sectransport_pub_key {
    struct tlsuv_public_key_s api;
    SecKeyRef key;
    CFStringRef key_type;
};

extern const char* applesec_error(OSStatus code);
extern tlsuv_engine_t new_engine(tls_context *ctx, const char *hostname);

#endif //TLSUV_CONTEXT_H
