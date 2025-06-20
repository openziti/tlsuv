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

#ifndef TLSUV_KEYS_H
#define TLSUV_KEYS_H

#include <tlsuv/tls_engine.h>
#include <ncrypt.h>

#include "cert.h"

struct win32crypto_private_key_s {
    struct tlsuv_private_key_s api;
    NCRYPT_PROV_HANDLE provider;
    NCRYPT_KEY_HANDLE key;
};

struct win32crypto_public_key_s {
    struct tlsuv_public_key_s api;
    BCRYPT_KEY_HANDLE key;
    CERT_PUBLIC_KEY_INFO *info;
};

extern int win32crypto_generate_key(tlsuv_private_key_t *key);
extern int win32crypto_load_key(tlsuv_private_key_t *key, const char *data, size_t datalen);

extern int win32crypto_gen_keychain_key(tlsuv_private_key_t *pk, const char *id);
extern int win32crypto_load_keychain_key(tlsuv_private_key_t *pk, const char *name);
extern int win32crypto_remove_keychain_key(const char *name);

#endif //TLSUV_KEYS_H
