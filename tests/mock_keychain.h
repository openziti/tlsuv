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

// In-memory keychain_t backed by software keys. It lets the keychain code paths
// run on platforms without a native keychain, and exercises variations real
// keychains have: the Android one returns SubjectPublicKeyInfo and has no
// key_bits(), Apple's returns the raw EC point.
//
// A keychain can be registered with tlsuv only once per process and only if the
// platform did not register its own, see mock_keychain_register().

#ifndef TLSUV_TESTS_MOCK_KEYCHAIN_H
#define TLSUV_TESTS_MOCK_KEYCHAIN_H

#include "openssl_fixtures.h"

#ifdef TEST_HAVE_OPENSSL_API

#include <tlsuv/keychain.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>

#include <cstring>
#include <map>
#include <string>
#include <vector>

// how key_public() reports keys
enum class MockFormat {
    SPKI,      // DER SubjectPublicKeyInfo, no key_bits() (Android)
    Raw,       // EC point / PKCS#1 RSAPublicKey, key_bits() present (Apple)
    RawNoBits, // as Raw, but no key_bits(): EC keys cannot be loaded
};

class MockKeychain {
public:
    keychain_t api{};
    std::map<std::string, EVP_PKEY *> keys;

    MockKeychain() {
        api.gen_key = gen_key;
        api.load_key = load_key;
        api.rem_key = rem_key;
        api.key_type = key_type;
        api.key_public = key_public;
        api.key_sign = key_sign;
        api.free_key = free_key;
        set_format(MockFormat::SPKI);
    }

    void set_format(MockFormat f) {
        format = f;
        api.key_bits = (f == MockFormat::Raw) ? key_bits : nullptr;
    }

    // creates a key of the given type under `name`
    bool add(const std::string &name, enum keychain_key_type type) {
        EVP_PKEY *pkey = EVP_PKEY_new();
        if (type == keychain_key_ec) {
            EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            if (!ec || EC_KEY_generate_key(ec) != 1 || EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
                EC_KEY_free(ec);
                EVP_PKEY_free(pkey);
                return false;
            }
        } else {
            RSA *rsa = RSA_new();
            BIGNUM *e = BN_new();
            BN_set_word(e, RSA_F4);
            bool ok = RSA_generate_key_ex(rsa, 2048, e, nullptr) == 1 && EVP_PKEY_assign_RSA(pkey, rsa) == 1;
            BN_free(e);
            if (!ok) {
                RSA_free(rsa);
                EVP_PKEY_free(pkey);
                return false;
            }
        }
        remove(name);
        keys[name] = pkey;
        return true;
    }

    void remove(const std::string &name) {
        auto it = keys.find(name);
        if (it != keys.end()) {
            EVP_PKEY_free(it->second);
            keys.erase(it);
        }
    }

private:
    MockFormat format = MockFormat::SPKI;

    static MockKeychain &self();
    friend MockKeychain &mock_keychain();

    // key handles are references to the stored EVP_PKEY
    static EVP_PKEY *ref(EVP_PKEY *k) {
        EVP_PKEY_up_ref(k);
        return k;
    }

    static int gen_key(keychain_key_t *pk, enum keychain_key_type type, const char *name) {
        auto &m = self();
        if (!m.add(name, type)) return -1;
        *pk = ref(m.keys[name]);
        return 0;
    }

    static int load_key(keychain_key_t *pk, const char *name) {
        auto &m = self();
        auto it = m.keys.find(name);
        if (it == m.keys.end()) return -1;
        *pk = ref(it->second);
        return 0;
    }

    static int rem_key(const char *name) {
        auto &m = self();
        if (m.keys.find(name) == m.keys.end()) return -1;
        m.remove(name);
        return 0;
    }

    static enum keychain_key_type key_type(keychain_key_t k) {
        switch (EVP_PKEY_id((EVP_PKEY *)k)) {
        case EVP_PKEY_EC: return keychain_key_ec;
        case EVP_PKEY_RSA: return keychain_key_rsa;
        default: return keychain_key_invalid;
        }
    }

    static int key_bits(keychain_key_t k) {
        return EVP_PKEY_bits((EVP_PKEY *)k);
    }

    static int key_public(keychain_key_t k, char *buf, size_t *len) {
        auto pkey = (EVP_PKEY *)k;
        std::vector<uint8_t> der;

        if (self().format == MockFormat::SPKI) {
            int n = i2d_PUBKEY(pkey, nullptr);
            if (n <= 0) return -1;
            der.resize(n);
            uint8_t *p = der.data();
            i2d_PUBKEY(pkey, &p);
        } else if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
            const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
            der.resize(256);
            size_t n = EC_POINT_point2oct(EC_KEY_get0_group(ec), EC_KEY_get0_public_key(ec),
                                          POINT_CONVERSION_UNCOMPRESSED, der.data(), der.size(), nullptr);
            if (n == 0) return -1;
            der.resize(n);
        } else {
            const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
            int n = i2d_RSAPublicKey(rsa, nullptr);
            if (n <= 0) return -1;
            der.resize(n);
            uint8_t *p = der.data();
            i2d_RSAPublicKey(rsa, &p);
        }

        if (der.size() > *len) return -1;
        memcpy(buf, der.data(), der.size());
        *len = der.size();
        return 0;
    }

    // same contract as the real keychains: EC signs a digest and returns DER;
    // RSA signs a DigestInfo with PKCS#1 v1.5 padding
    static int key_sign(keychain_key_t k, const uint8_t *data, size_t datalen,
                        uint8_t *sig, size_t *siglen, int padding) {
        auto pkey = (EVP_PKEY *)k;
        if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
            unsigned int l = 0;
            if (ECDSA_sign(0, data, datalen, sig, &l, (EC_KEY *)EVP_PKEY_get0_EC_KEY(pkey)) != 1) return -1;
            *siglen = l;
            return 0;
        }

        RSA *rsa = (RSA *)EVP_PKEY_get0_RSA(pkey);
        if (padding != RSA_PKCS1_PADDING) return -1;
#ifdef TEST_boringssl
        size_t l = 0;
        if (RSA_sign_raw(rsa, &l, sig, RSA_size(rsa), data, datalen, padding) != 1) return -1;
        *siglen = l;
#else
        int l = RSA_private_encrypt((int)datalen, data, sig, rsa, padding);
        if (l < 0) return -1;
        *siglen = l;
#endif
        return 0;
    }

    static void free_key(keychain_key_t k) {
        EVP_PKEY_free((EVP_PKEY *)k);
    }
};

inline MockKeychain &mock_keychain() {
    static MockKeychain mock;
    return mock;
}

inline MockKeychain &MockKeychain::self() {
    return mock_keychain();
}

// Registers the mock with tlsuv. Returns false when that is not possible: the
// platform has its own keychain (macOS, Windows), which tests use instead.
// Contexts created before registration do not have keychain support.
inline bool mock_keychain_register() {
    static bool registered = false;
    if (!registered) {
        if (tlsuv_keychain() != nullptr) return false;
        tlsuv_set_keychain(&mock_keychain().api);
        registered = true;
    }
    return true;
}

#endif // TEST_HAVE_OPENSSL_API
#endif // TLSUV_TESTS_MOCK_KEYCHAIN_H
