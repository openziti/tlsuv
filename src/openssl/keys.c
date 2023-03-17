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

#define OPENSSL_API_LEVEL 101010

#include <openssl/types.h>
#include <openssl/evp.h>

#include <assert.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <tlsuv/tlsuv.h>

#include "../um_debug.h"
#include "keys.h"

static void pubkey_free(tlsuv_public_key_t k);
static int pubkey_verify(tlsuv_public_key_t pk, enum hash_algo md, const char *data, size_t datalen, const char *sig, size_t siglen);

static struct pub_key_s PUB_KEY_API = {
        .free = pubkey_free,
        .verify = pubkey_verify,
};


static void privkey_free(tlsuv_private_key_t k);
static tlsuv_public_key_t privkey_pubkey(tlsuv_private_key_t pk);
static int privkey_to_pem(tlsuv_private_key_t pk, char **pem, size_t *pemlen);
static int privkey_sign(tlsuv_private_key_t pk, enum hash_algo md,
                        const char *data, size_t datalen, char *sig, size_t *siglen);

static struct priv_key_s PRIV_KEY_API = {
        .free = privkey_free,
        .to_pem = privkey_to_pem,
        .pubkey = privkey_pubkey,
        .sign = privkey_sign,
};

void pub_key_init(struct pub_key_s *pubkey) {
    *pubkey = PUB_KEY_API;
}

void priv_key_init(struct priv_key_s *privkey) {
    *privkey = PRIV_KEY_API;
}

static void pubkey_free(tlsuv_public_key_t k) {
    struct pub_key_s *pub = (struct pub_key_s *) k;
    EVP_PKEY_free(pub->pkey);
    free(pub);
}


int verify_signature (EVP_PKEY *pk, enum hash_algo md, const char* data, size_t datalen, const char* sig, size_t siglen) {
    int rc = 0;
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *hash = NULL;
    switch (md) {
        case hash_SHA256: hash = EVP_sha256(); break;
        case hash_SHA384: hash = EVP_sha384(); break;
        case hash_SHA512: hash = EVP_sha512(); break;
        default:
            break;
    }
    EVP_DigestVerifyInit(digest, &pctx, hash, NULL, pk);

    int res = EVP_DigestVerify(digest, (const uint8_t *) sig, siglen, (const uint8_t *) data, datalen);
    if (res != 1) {
        rc = -1;
    }

    EVP_MD_CTX_free(digest);

    return rc;
}

static int pubkey_verify(tlsuv_public_key_t pk, enum hash_algo md, const char *data, size_t datalen, const char *sig, size_t siglen) {
    struct pub_key_s *pub = (struct pub_key_s *) pk;
    return verify_signature(pub->pkey, md, data, datalen, sig, siglen);
}

static void privkey_free(tlsuv_private_key_t k) {
    struct priv_key_s *priv = (struct priv_key_s *) k;
    EVP_PKEY_free(priv->pkey);
    free(priv);
}

static int privkey_sign(tlsuv_private_key_t pk, enum hash_algo md, const char *data, size_t datalen, char *sig, size_t *siglen) {
    struct priv_key_s *priv = (struct priv_key_s *) pk;
    int rc = 0;
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;

    const EVP_MD *hash = NULL;
    switch (md) {
        case hash_SHA256: hash = EVP_sha256(); break;
        case hash_SHA384: hash = EVP_sha384(); break;
        case hash_SHA512: hash = EVP_sha512(); break;
        default:
            break;
    }
    EVP_DigestSignInit(digest, &pctx, hash, NULL, priv->pkey);

    if (!EVP_DigestSign(digest, (uint8_t *)sig, siglen, (const uint8_t *) data, datalen)) {
        rc = -1;
    }
    EVP_MD_CTX_free(digest);
    return rc;
}


static tlsuv_public_key_t privkey_pubkey(tlsuv_private_key_t pk) {
    struct priv_key_s *priv = (struct priv_key_s *) pk;
    struct pub_key_s *pub = calloc(1, sizeof(*pub));
    *pub = PUB_KEY_API;

    // there is probably a more straight-forward way,
    // but I did not find it
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, priv->pkey);
    pub->pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    BIO_free_all(bio);
    return (tlsuv_public_key_t) pub;
}

static int privkey_to_pem(tlsuv_private_key_t pk, char **pem, size_t *pemlen) {
    BIO *b = BIO_new(BIO_s_mem());
    struct priv_key_s *privkey = (struct priv_key_s *) pk;
    PEM_write_bio_PKCS8PrivateKey(b, privkey->pkey, NULL, NULL, 0, NULL, NULL);
    size_t len = BIO_ctrl_pending(b);
    *pem = calloc(1, len + 1);
    BIO_read(b, *pem, (int)len);
    *pemlen = len;
    BIO_free(b);
    return 0;
}

int load_key(tlsuv_private_key_t *key, const char* keydata, size_t keydatalen) {
    // try file
    BIO *kb;
    int rc = 0;
    FILE *kf = fopen(keydata, "r");
    if (kf != NULL) {
        kb = BIO_new_fp(kf, 1);
    } else {
        kb = BIO_new_mem_buf(keydata, (int)keydatalen);
    }

    EVP_PKEY *pk = NULL;
    if (!PEM_read_bio_PrivateKey(kb, &pk, NULL, NULL)) {
        rc = -1;
    } else {
        struct priv_key_s *privkey = calloc(1, sizeof(struct priv_key_s));
        priv_key_init(privkey);
        privkey->pkey = pk;
        *key = (tlsuv_private_key_t) privkey;
    }
    BIO_free(kb);
    return rc;
}

int load_pkcs11_key(struct priv_key_s *k, const char *lib, const char *slot, const char *pin, const char *id, const char *label) {
    UM_LOG(ERR, "not implemented");
    return -1;
}


int gen_key(tlsuv_private_key_t *key) {
    int rc = 0;

    EVP_PKEY *pk = EVP_PKEY_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);

    if (!EVP_PKEY_keygen(pctx, &pk)) {
        uint32_t err = ERR_get_error();
        UM_LOG(ERR, "failed to generate key: %d(%s)", err, tls_error(err));
        rc = -1;
        EVP_PKEY_free(pk);
    }

    if (rc == 0) {
        struct priv_key_s *private_key = calloc(1, sizeof(struct priv_key_s));
        *private_key = PRIV_KEY_API;
        private_key->pkey = pk;
        *key = (tlsuv_private_key_t)private_key;
    }

    EVP_PKEY_CTX_free(pctx);
    return rc;
}