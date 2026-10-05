// Copyright (c) NetFoundry Inc.
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

// Keys that live in the platform keychain (tlsuv_keychain()).
//
// The EVP_PKEY of such a key holds the public key only; signing goes through
// the keychain, see keychain_sign_digest() and keychain_sign_csr().

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <uv.h>

#include "../alloc.h"
#include "../keychain.h"
#include "../um_debug.h"
#include "keys.h"

static int kc_ec_idx = -1;
static int kc_rsa_idx = -1;
static uv_once_t kc_once = UV_ONCE_INIT;

// the keychain handle is owned by the EC_KEY/RSA it is attached to
static void kc_ex_free(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int idx, long argl, void* argp) {
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;
    if (ptr != NULL) {
        keychain_free_key(ptr);
    }
}

static void kc_init(void) {
    kc_ec_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, kc_ex_free);
    kc_rsa_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, kc_ex_free);
}

keychain_key_t pkey_keychain_key(EVP_PKEY* pkey) {
    uv_once(&kc_once, kc_init);

    switch (EVP_PKEY_id(pkey)) {
    case EVP_PKEY_EC: {
        const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(pkey);
        return ec ? EC_KEY_get_ex_data(ec, kc_ec_idx) : NULL;
    }
    case EVP_PKEY_RSA: {
        const RSA* rsa = EVP_PKEY_get0_RSA(pkey);
        return rsa ? RSA_get_ex_data(rsa, kc_rsa_idx) : NULL;
    }
    default:
        return NULL;
    }
}

// builds the public EVP_PKEY for a keychain key
static EVP_PKEY* kc_public_pkey(keychain_key_t k) {
    const keychain_t* kc = tlsuv_keychain();
    enum keychain_key_type type = keychain_key_type(k);
    if (type == keychain_key_invalid) {
        UM_LOG(ERR, "unsupported keychain key type");
        return NULL;
    }

    uint8_t pub[8 * 1024];
    size_t publen = sizeof(pub);
    if (keychain_key_public(k, (char*)pub, &publen) != 0) {
        UM_LOG(WARN, "failed to load public key from keychain");
        return NULL;
    }

    // ASN.1 SubjectPublicKeyInfo
    const uint8_t* p = pub;
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &p, (long)publen);
    if (pkey != NULL) {
        int id = EVP_PKEY_id(pkey);
        if ((type == keychain_key_ec && id == EVP_PKEY_EC) || (type == keychain_key_rsa && id == EVP_PKEY_RSA)) {
            return pkey;
        }
        UM_LOG(ERR, "keychain public key does not match its type");
        EVP_PKEY_free(pkey);
        return NULL;
    }
    ERR_clear_error();

    // raw key material: EC point, or PKCS#1 RSAPublicKey
    if (type == keychain_key_ec) {
        // key_bits is optional in keychain_t
        int bits = kc->key_bits ? kc->key_bits(k) : -1;
        int nid;
        switch (bits) {
        case 256: nid = NID_X9_62_prime256v1; break;
        case 384: nid = NID_secp384r1; break;
        case 521: nid = NID_secp521r1; break;
        default:
            UM_LOG(ERR, "unsupported EC key size[%d]", bits);
            return NULL;
        }

        EC_KEY* ec = EC_KEY_new_by_curve_name(nid);
        pkey = EVP_PKEY_new();
        if (ec == NULL || pkey == NULL || EC_KEY_oct2key(ec, pub, publen, NULL) != 1 ||
            EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
            UM_LOG(ERR, "failed to set EC public key: %s", tls_error(ERR_get_error()));
            EC_KEY_free(ec);
            EVP_PKEY_free(pkey);
            return NULL;
        }
        return pkey;
    }

    RSA* rsa = RSA_public_key_from_bytes(pub, publen);
    pkey = EVP_PKEY_new();
    if (rsa == NULL || pkey == NULL || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        UM_LOG(ERR, "failed to set RSA public key: %s", tls_error(ERR_get_error()));
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    return pkey;
}

// takes ownership of `k` on success only
static int new_keychain_private_key(tlsuv_private_key_t* key, keychain_key_t k) {
    uv_once(&kc_once, kc_init);

    EVP_PKEY* pkey = kc_public_pkey(k);
    if (pkey == NULL) {
        return -1;
    }

    int rc;
    if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
        rc = EC_KEY_set_ex_data((EC_KEY*)EVP_PKEY_get0_EC_KEY(pkey), kc_ec_idx, k);
    } else {
        rc = RSA_set_ex_data((RSA*)EVP_PKEY_get0_RSA(pkey), kc_rsa_idx, k);
    }
    if (rc != 1) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    *key = new_private_key(pkey);
    return 0;
}

int load_keychain_key(tlsuv_private_key_t* key, const char* name) {
    keychain_key_t k = NULL;
    if (keychain_load_key(&k, name) != 0) {
        return -1;
    }

    if (new_keychain_private_key(key, k) != 0) {
        keychain_free_key(k);
        return -1;
    }
    return 0;
}

int gen_keychain_key(tlsuv_private_key_t* key, const char* name) {
    keychain_key_t k = NULL;
    if (keychain_gen_key(&k, keychain_key_ec, name) != 0) {
        return -1;
    }

    if (new_keychain_private_key(key, k) != 0) {
        keychain_free_key(k);
        keychain_rem_key(name);
        return -1;
    }
    return 0;
}

int remove_keychain_key(const char* name) {
    return keychain_rem_key(name);
}

int keychain_sign_digest(EVP_PKEY* pkey, const EVP_MD* md, const uint8_t* digest, size_t digestlen,
                         uint8_t* sig, size_t* siglen) {
    keychain_key_t k = pkey_keychain_key(pkey);
    if (k == NULL) {
        return -1;
    }

    // keychain implementations do not check the capacity of `sig`
    if (*siglen < (size_t)EVP_PKEY_size(pkey)) {
        UM_LOG(WARN, "signature buffer is too small: %zd < %d", *siglen, EVP_PKEY_size(pkey));
        return -1;
    }

    size_t len = *siglen;
    int rc;
    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
        uint8_t* msg = NULL;
        size_t msglen = 0;
        int allocated = 0;
        if (RSA_add_pkcs1_prefix(&msg, &msglen, &allocated, EVP_MD_type(md), digest, digestlen) != 1) {
            UM_LOG(WARN, "failed to build DigestInfo: %s", tls_error(ERR_get_error()));
            return -1;
        }
        rc = keychain_key_sign(k, msg, msglen, sig, &len, RSA_PKCS1_PADDING);
        if (allocated) {
            OPENSSL_free(msg);
        }
    } else {
        rc = keychain_key_sign(k, digest, digestlen, sig, &len, 0);
    }

    if (rc != 0) {
        UM_LOG(WARN, "keychain failed to sign: %d", rc);
        return -1;
    }
    *siglen = len;
    return 0;
}

int keychain_sign_digest_pss(EVP_PKEY* pkey, const EVP_MD* md, const uint8_t* digest, size_t digestlen,
                             uint8_t* sig, size_t* siglen) {
    keychain_key_t k = pkey_keychain_key(pkey);
    if (k == NULL || EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
        return -1;
    }

    // keychain implementations do not check the capacity of `sig`
    size_t size = (size_t)EVP_PKEY_size(pkey);
    if (*siglen < size) {
        UM_LOG(WARN, "signature buffer is too small: %zd < %zd", *siglen, size);
        return -1;
    }

    uint8_t* em = tlsuv__malloc(size);
    size_t len = *siglen;
    int rc = -1;
    // salt length -1: as long as the digest
    if (RSA_padding_add_PKCS1_PSS_mgf1(EVP_PKEY_get0_RSA(pkey), em, digest, md, md, -1) != 1) {
        UM_LOG(WARN, "failed to build PSS block: %s", tls_error(ERR_get_error()));
        goto done;
    }

    rc = keychain_key_sign(k, em, size, sig, &len, RSA_NO_PADDING);
    if (rc != 0) {
        UM_LOG(WARN, "keychain failed to sign: %d", rc);
        rc = -1;
        goto done;
    }
    *siglen = len;

done:
    tlsuv__free(em);
    return rc;
}

int keychain_sign_csr(X509_REQ* req, EVP_PKEY* pkey) {
    const EVP_MD* md = EVP_sha256();
    int rc = -1;

    X509_ALGOR* algo = X509_ALGOR_new();
    uint8_t* tbs = NULL;
    uint8_t* sig = NULL;
    int tbslen;
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digestlen = 0;
    size_t siglen = (size_t)EVP_PKEY_size(pkey);

    if (algo == NULL) {
        goto done;
    }

    // RFC 5758 (ECDSA: parameters absent), RFC 8017 (RSA: parameters NULL)
    if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
        if (X509_ALGOR_set0(algo, OBJ_nid2obj(NID_ecdsa_with_SHA256), V_ASN1_UNDEF, NULL) != 1) goto done;
    } else {
        if (X509_ALGOR_set0(algo, OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, NULL) != 1) goto done;
    }

    if (X509_REQ_set1_signature_algo(req, algo) != 1) goto done;

    tbslen = i2d_re_X509_REQ_tbs(req, &tbs);
    if (tbslen <= 0) goto done;

    if (EVP_Digest(tbs, (size_t)tbslen, digest, &digestlen, md, NULL) != 1) goto done;

    sig = tlsuv__calloc(1, siglen);
    if (keychain_sign_digest(pkey, md, digest, digestlen, sig, &siglen) != 0) goto done;

    if (X509_REQ_set1_signature_value(req, sig, siglen) != 1) goto done;
    rc = 0;

done:
    if (rc != 0) {
        UM_LOG(WARN, "failed to sign CSR with keychain key: %s", tls_error(ERR_get_error()));
    }
    X509_ALGOR_free(algo);
    OPENSSL_free(tbs);
    tlsuv__free(sig);
    return rc;
}
