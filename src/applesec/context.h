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


#ifndef TLSUV_CONTEXT_H
#define TLSUV_CONTEXT_H

#include "tlsuv/tls_engine.h"
#include <Security/Security.h>

// resolved once, at key load/generate time. The kSecAttrKeyType value from
// SecKeyCopyAttributes() is only borrowed from the attribute dictionary, so it
// must not be retained past that dictionary's lifetime.
enum applesec_key_type {
    APPLESEC_KEY_UNKNOWN = 0,
    APPLESEC_KEY_EC,
    APPLESEC_KEY_RSA,
};

struct sectransport_ctx {
    tls_context api;

    // anchors for SecTrustSetAnchorCertificates()
    CFArrayRef ca_bundle;

    // [SecIdentityRef, SecCertificateRef...] as SSLSetCertificate() wants it
    CFArrayRef ssl_chain;
    // file keychain backing ssl_chain[0]; deleted with the context
    SecKeychainRef tmp_keychain;
    char *tmp_keychain_path;

    int (*cert_verify_f)(const struct tlsuv_certificate_s *cert, void *v_ctx);
    void *verify_ctx;
};

struct sectransport_priv_key {
    struct tlsuv_private_key_s api;
    SecKeyRef key;
    enum applesec_key_type key_type;
    // PEM as it was handed to load_key(); kept so to_pem() round-trips
    // byte-for-byte and so the key can be re-imported into a keychain.
    CFDataRef pem;
};

struct sectransport_pub_key {
    struct tlsuv_public_key_s api;
    SecKeyRef key;
    enum applesec_key_type key_type;
};

struct sectransport_cert {
    struct tlsuv_certificate_s api;

    CFArrayRef chain;
};

extern const char *applesec_error(OSStatus code);

// engine.c
extern tlsuv_engine_t applesec_new_engine(tls_context *ctx, const char *hostname);

// context.c, used by the engine to hand the peer chain to a verify callback.
// takes ownership of `chain`.
extern tlsuv_certificate_t applesec_cert_new(CFArrayRef chain);

#endif //TLSUV_CONTEXT_H
