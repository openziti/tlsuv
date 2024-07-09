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

#ifndef TLSUV_KEYCHAIN_H
#define TLSUV_KEYCHAIN_H

#if __APPLE__
#define TLSUV_KEYCHAIN_SUPPORT
#endif

#if defined(TLSUV_KEYCHAIN_SUPPORT)
enum keychain_key_type {
    keychain_key_invalid,
    keychain_key_ec,
    keychain_key_rsa,
};

typedef void* keychain_key_t;

int keychain_gen_key(keychain_key_t *pk, enum keychain_key_type type, const char *name);
int keychain_load_key(keychain_key_t*, const char *name);
int keychain_rem_key(const char *name);

enum keychain_key_type keychain_key_type(keychain_key_t k);
int keychain_key_public(keychain_key_t k, char *buf, size_t *len);
int keychain_key_sign(keychain_key_t k, const uint8_t * data, size_t datalen,
                      uint8_t *sig, size_t *siglen, int p);

void keychain_free_key(keychain_key_t k);

#endif // defined(TLSUV_KEYCHAIN_SUPPORT)
#endif //TLSUV_KEYCHAIN_H
