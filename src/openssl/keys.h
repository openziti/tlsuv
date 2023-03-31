
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

#ifndef TLSUV_OPENSSL_KEYS_H
#define TLSUV_OPENSSL_KEYS_H

#include <tlsuv/tlsuv.h>

struct pub_key_s {
    TLSUV_PUBKEY_API
    EVP_PKEY *pkey;
};

struct priv_key_s {
    TLSUV_PRIVKEY_API
    EVP_PKEY *pkey;
};

const char *tls_error(int code);

void pub_key_init(struct pub_key_s *pubkey);
void priv_key_init(struct priv_key_s *privkey);

int gen_key(tlsuv_private_key_t *key);
int load_key(tlsuv_private_key_t *key, const char* keydata, size_t keydatalen);
int load_pkcs11_key(tlsuv_private_key_t *k, const char *lib, const char *slot, const char *pin, const char *id, const char *label);


int verify_signature (EVP_PKEY *pk, enum hash_algo md, const char* data, size_t datalen, const char* sig, size_t siglen);


#endif//TLSUV_OPENSSL_KEYS_H
