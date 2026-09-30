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
#include <TargetConditionals.h>

// Where the client identity's key and certificate live: a temporary file keychain
// on macOS, unless built with TLSUV_APPLESEC_APP_KEYCHAIN; the app's (data
// protection) keychain otherwise, and always on iOS and the other Apple platforms.
#if TARGET_OS_OSX && !defined(APPLESEC_APP_KEYCHAIN)
#define APPLESEC_FILE_KEYCHAIN 1
#else
#define APPLESEC_FILE_KEYCHAIN 0
#endif

// resolved once, at key load/generate time. The kSecAttrKeyType value from
// SecKeyCopyAttributes() is only borrowed from the attribute dictionary, so it
// must not be retained past that dictionary's lifetime.
enum applesec_key_type {
    APPLESEC_KEY_UNKNOWN = 0,
    APPLESEC_KEY_EC,
    APPLESEC_KEY_RSA,
};

struct applesec_ctx {
    tls_context api;

    // anchors for SecTrustSetAnchorCertificates()
    CFArrayRef ca_bundle;

    // [SecIdentityRef, intermediate SecCertificateRef...]; engine.c turns it into a sec_identity_t
    CFArrayRef ssl_chain;
#if APPLESEC_FILE_KEYCHAIN
    // file keychain backing ssl_chain[0]; deleted with the context
    SecKeychainRef tmp_keychain;
    char *tmp_keychain_path;
    // random passphrase of tmp_keychain, kept to unlock it before each import
    char tmp_keychain_pw[65];
#else
    // persistent refs of the keys and certificates this context added to the
    // app's keychain for ssl_chain[0]; deleted with the context
    CFMutableArrayRef kc_items;
#endif

    int (*cert_verify_f)(const struct tlsuv_certificate_s *cert, void *v_ctx);
    void *verify_ctx;
};

struct applesec_priv_key {
    struct tlsuv_private_key_s api;
    SecKeyRef key;
    enum applesec_key_type key_type;
    // PEM as it was handed to load_key(); kept so the key can be re-imported
    // into the macOS temporary keychain as it was loaded.
    CFDataRef pem;
    // held by the platform keychain (generate/load_keychain_key): not extractable,
    // so the TLS identity pairs the certificate with it where it is
    bool in_keychain;
};

struct applesec_pub_key {
    struct tlsuv_public_key_s api;
    SecKeyRef key;
    enum applesec_key_type key_type;
};

struct applesec_cert {
    struct tlsuv_certificate_s api;

    CFArrayRef chain;
};

extern const char *applesec_error(OSStatus code);

// engine.c
extern tlsuv_engine_t applesec_new_engine(tls_context *ctx, const char *host);
extern tlsuv_engine_t applesec_new_server_engine(tls_context *ctx);

// context.c, used by the engine to hand the peer chain to a verify callback.
// takes ownership of `chain`.
extern tlsuv_certificate_t applesec_cert_new(CFArrayRef chain);

// context.c: make sure the key behind ssl_chain[0] is usable (see context.c)
extern void applesec_unlock_identity(struct applesec_ctx *c);

#endif //TLSUV_CONTEXT_H
