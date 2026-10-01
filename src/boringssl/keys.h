
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

#ifndef TLSUV_BORINGSSL_KEYS_H
#define TLSUV_BORINGSSL_KEYS_H

#include <tlsuv/keychain.h>
#include <tlsuv/tls_engine.h>

struct cert_s {
    TLSUV_CERT_API
    X509_STORE* cert;
    char* text;
};

struct pub_key_s {
    TLSUV_PUBKEY_API
    EVP_PKEY* pkey;
};

struct priv_key_s {
    TLSUV_PRIVKEY_API
    EVP_PKEY* pkey;
};

const char* tls_error(unsigned long code);

void pub_key_init(struct pub_key_s* pubkey);

void cert_init(struct cert_s* c);

int gen_key(tlsuv_private_key_t * key);
int load_key(tlsuv_private_key_t* key, const char* keydata, size_t keydatalen);

// wraps `pkey` (takes ownership) in a private key object
tlsuv_private_key_t new_private_key(EVP_PKEY* pkey);

// Keychain keys (keychain.c): the EVP_PKEY of these keys holds the public key
// only. The keychain handle hangs off the EC_KEY/RSA ex_data, so it lives as
// long as any reference to the EVP_PKEY (private key object, TLS context, TLS engine).
int load_keychain_key(tlsuv_private_key_t* key, const char* name);
int gen_keychain_key(tlsuv_private_key_t* key, const char* name);
int remove_keychain_key(const char* name);

// returns the keychain handle behind `pkey`, or NULL if it is not a keychain key
keychain_key_t pkey_keychain_key(EVP_PKEY* pkey);

// Signs an already computed `digest` with a keychain key.
// EC keys produce a DER ECDSA signature, RSA keys PKCS#1 v1.5.
// `*siglen` is the capacity of `sig` on input (at least EVP_PKEY_size()) and the
// signature length on output.
int keychain_sign_digest(EVP_PKEY* pkey, const EVP_MD* md, const uint8_t* digest, size_t digestlen,
                         uint8_t* sig, size_t* siglen);

// Signs (SHA-256) and completes a certificate request made for a keychain key.
int keychain_sign_csr(X509_REQ* req, EVP_PKEY* pkey);

int verify_signature(EVP_PKEY* pk, enum hash_algo md, const char* data, size_t datalen, const char* sig, size_t siglen);


#endif//TLSUV_BORINGSSL_KEYS_H
