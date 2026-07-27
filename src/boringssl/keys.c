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

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <assert.h>
#include <stdbool.h>
#include <time.h>

#include "../um_debug.h"
#include "keys.h"
#include "../alloc.h"

static const char* cert_to_text(const struct tlsuv_certificate_s* cert);
static int cert_to_pem(const struct tlsuv_certificate_s* c, int full, char** pem, size_t* pemlen);
static void cert_free(tlsuv_certificate_t c);
static int cert_verify(const struct tlsuv_certificate_s* c, enum hash_algo md, const char* data, size_t datalen,
                       const char* sig, size_t siglen);
static int cert_exp(const struct tlsuv_certificate_s*, struct tm* time);

static X509* find_leaf_cert(X509_STORE * store);

static struct cert_s cert_API = {
    .free = cert_free,
    .verify = cert_verify,
    .to_pem = cert_to_pem,
    .get_text = cert_to_text,
    .get_expiration = cert_exp,
};


static int pubkey_to_pem(tlsuv_public_key_t pub, char** pem, size_t* pemlen);
static void pubkey_free(tlsuv_public_key_t k);
static int pubkey_verify(tlsuv_public_key_t pk, enum hash_algo md, const char* data, size_t datalen, const char* sig,
                         size_t siglen);

static struct pub_key_s PUB_KEY_API = {
    .free = pubkey_free,
    .verify = pubkey_verify,
    .to_pem = pubkey_to_pem,
};


static void privkey_free(tlsuv_private_key_t k);
static tlsuv_public_key_t privkey_pubkey(tlsuv_private_key_t pk);
static int privkey_to_pem(tlsuv_private_key_t pk, char** pem, size_t* pemlen);
static int privkey_sign(tlsuv_private_key_t pk, enum hash_algo md,
                        const char* data, size_t datalen, char* sig, size_t* siglen);

static struct priv_key_s PRIV_KEY_API = {
    .free = privkey_free,
    .to_pem = privkey_to_pem,
    .pubkey = privkey_pubkey,
    .sign = privkey_sign,
    // no PKCS11/keychain support in the BoringSSL backend, so no
    // get_certificate/store_certificate hook is provided (callers
    // already check these fields for NULL before use)
};

void pub_key_init(struct pub_key_s* pubkey) {
    *pubkey = PUB_KEY_API;
}

static tlsuv_private_key_t new_private_key(EVP_PKEY* pkey) {
    struct priv_key_s* private_key = tlsuv__calloc(1, sizeof(struct priv_key_s));
    *private_key = PRIV_KEY_API;
    private_key->pkey = pkey;
    return (tlsuv_private_key_t)private_key;
}

void cert_init(struct cert_s* c) {
    *c = cert_API;
}

static void pubkey_free(tlsuv_public_key_t k) {
    struct pub_key_s* pub = (struct pub_key_s*)k;
    EVP_PKEY_free(pub->pkey);
    tlsuv__free(pub);
}

static int verify_ecdsa_sig(EC_KEY* ec, const EVP_MD* hash, const char* data, size_t datalen, const char* sig,
                            size_t siglen) {
    int rc;
    ECDSA_SIG* ecdsa_sig = NULL;

    EVP_MD_CTX* digestor = EVP_MD_CTX_new();
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_DigestInit(digestor, hash);
    EVP_DigestUpdate(digestor, data, datalen);
    rc = EVP_DigestFinal(digestor, digest, &digest_len);

    if (rc == 1) {
        BIGNUM* r = BN_bin2bn((const uint8_t*)sig, (int)(siglen / 2), NULL);
        BIGNUM* s = BN_bin2bn((const uint8_t*)sig + siglen / 2, (int)siglen / 2, NULL);

        ecdsa_sig = ECDSA_SIG_new();
        ECDSA_SIG_set0(ecdsa_sig, r, s);
        rc = ECDSA_do_verify(digest, (int)digest_len, ecdsa_sig, ec);
    }

    ECDSA_SIG_free(ecdsa_sig);
    EVP_MD_CTX_free(digestor);

    return rc == 1 ? 0 : -1;
}

int verify_signature(EVP_PKEY* pk, enum hash_algo md, const char* data, size_t datalen, const char* sig,
                     size_t siglen) {
    const EVP_MD* hash = NULL;
    switch (md) {
    case hash_SHA256: hash = EVP_sha256();
        break;
    case hash_SHA384: hash = EVP_sha384();
        break;
    case hash_SHA512: hash = EVP_sha512();
        break;
    default:
        break;
    }

    EVP_MD_CTX* digestor = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(digestor, NULL, hash, NULL, pk) != 1 ||
        EVP_DigestVerifyUpdate(digestor, data, datalen) != 1) {
        UM_LOG(WARN, "failed to create digest: %s", tls_error(ERR_get_error()));
        return -1;
    }

    int rc = EVP_DigestVerifyFinal(digestor, (const uint8_t*)sig, siglen);
    EVP_MD_CTX_free(digestor);

    if (rc != 1 && EVP_PKEY_id(pk) == EVP_PKEY_EC) {
        const uint8_t* p = (const uint8_t*)sig;
        ECDSA_SIG* ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, (int)siglen);

        // if signature is not DER encoded try verifying it as raw ECDSA signature (EC-point)
        if (ecdsa_sig == NULL) {
            EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pk);
            int verified = verify_ecdsa_sig(ec, hash, data, datalen, sig, siglen);
            EC_KEY_free(ec);
            return verified;
        }

        ECDSA_SIG_free(ecdsa_sig);
    }
    return (rc == 1) ? 0 : -1;
}

static int pubkey_verify(tlsuv_public_key_t pk, enum hash_algo md, const char* data, size_t datalen, const char* sig,
                         size_t siglen) {
    struct pub_key_s* pub = (struct pub_key_s*)pk;
    return verify_signature(pub->pkey, md, data, datalen, sig, siglen);
}

static void privkey_free(tlsuv_private_key_t k) {
    struct priv_key_s* priv = (struct priv_key_s*)k;
    EVP_PKEY_free(priv->pkey);
    tlsuv__free(priv);
}

static int privkey_sign(tlsuv_private_key_t pk, enum hash_algo md, const char* data, size_t datalen, char* sig,
                        size_t* siglen) {
    struct priv_key_s* priv = (struct priv_key_s*)pk;
    int rc = 0;
    EVP_MD_CTX* digest = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = NULL;

    const EVP_MD* hash = NULL;
    switch (md) {
    case hash_SHA256: hash = EVP_sha256();
        break;
    case hash_SHA384: hash = EVP_sha384();
        break;
    case hash_SHA512: hash = EVP_sha512();
        break;
    default:
        break;
    }

    if ((EVP_DigestSignInit(digest, &pctx, hash, NULL, priv->pkey) != 1) ||
        (EVP_DigestSignUpdate(digest, data, datalen) != 1)) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to setup digest %ld/%s", err, ERR_lib_error_string(err));
        rc = -1;
    }

    if (EVP_DigestSignFinal(digest, (uint8_t*)sig, siglen) != 1) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to sign digest %ld/%s", err, ERR_lib_error_string(err));
        rc = -1;
    }

    EVP_MD_CTX_free(digest);
    return rc;
}


static tlsuv_public_key_t privkey_pubkey(tlsuv_private_key_t pk) {
    struct priv_key_s* priv = (struct priv_key_s*)pk;
    struct pub_key_s* pub = tlsuv__calloc(1, sizeof(*pub));
    pub_key_init(pub);

    // there is probably a more straight-forward way,
    // but I did not find it
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, priv->pkey);
    pub->pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    BIO_free_all(bio);
    return (tlsuv_public_key_t)pub;
}

static int privkey_to_pem(tlsuv_private_key_t pk, char** pem, size_t* pemlen) {
    BIO* b = BIO_new(BIO_s_mem());
    struct priv_key_s* privkey = (struct priv_key_s*)pk;

    *pem = NULL;
    *pemlen = 0;

    if (!PEM_write_bio_PKCS8PrivateKey(b, privkey->pkey, NULL, NULL, 0, NULL, NULL)) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to generate PEM for private key: %ld/%s", err, ERR_lib_error_string(err));
    } else {
        size_t len = BIO_ctrl_pending(b);
        *pem = tlsuv__calloc(1, len + 1);
        BIO_read(b, *pem, (int)len);
        *pemlen = len;
    }
    BIO_free(b);
    return *pem != NULL ? 0 : -1;
}


static int pubkey_to_pem(tlsuv_public_key_t pub, char** pem, size_t* pemlen) {
    BIO* b = BIO_new(BIO_s_mem());
    struct pub_key_s* pubkey = (struct pub_key_s*)pub;

    *pem = NULL;
    *pemlen = 0;

    if (!PEM_write_bio_PUBKEY(b, pubkey->pkey)) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to generate PEM for public key: %ld/%s", err, ERR_lib_error_string(err));
    } else {
        size_t len = BIO_ctrl_pending(b);
        *pem = tlsuv__calloc(1, len + 1);
        BIO_read(b, *pem, (int)len);
        *pemlen = len;
    }
    BIO_free(b);
    return *pem != NULL ? 0 : -1;
}

int load_key(tlsuv_private_key_t* key, const char* keydata, size_t keydatalen) {
    // try file
    BIO* kb;
    int rc = 0;
    FILE* kf = fopen(keydata, "r");
    if (kf != NULL) {
        kb = BIO_new_fp(kf, 1);
    } else {
        kb = BIO_new_mem_buf(keydata, (int)keydatalen);
    }

    EVP_PKEY* pk = NULL;
    if (!PEM_read_bio_PrivateKey(kb, &pk, NULL, NULL)) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to load key: %ld/%s", err, ERR_lib_error_string(err));
        rc = -1;
    } else {
        *key = new_private_key(pk);
    }
    BIO_free(kb);
    return rc;
}

int gen_key(tlsuv_private_key_t* key) {
    int rc = 0;

    EVP_PKEY* pk = EVP_PKEY_new();
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);

    if (!EVP_PKEY_keygen(pctx, &pk)) {
        uint32_t err = ERR_get_error();
        UM_LOG(ERR, "failed to generate key: %d(%s)", err, tls_error(err));
        rc = -1;
        EVP_PKEY_free(pk);
    }

    if (rc == 0) {
        *key = new_private_key(pk);
    }

    EVP_PKEY_CTX_free(pctx);
    return rc;
}

static const char* cert_to_text(const struct tlsuv_certificate_s* cert) {
    struct cert_s* c = (struct cert_s*)cert;

    if (c->text) return c->text;

    X509* x509 = find_leaf_cert(c->cert);
    if (x509 == NULL) {
        UM_LOG(WARN, "no leaf cert found in store");
        return NULL;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    X509_print_ex(bio, x509, 0,
                  X509_FLAG_NO_HEADER | X509_FLAG_NO_SIGDUMP |
                  X509_FLAG_NO_SIGNAME);

    int len = BIO_pending(bio);
    c->text = tlsuv__malloc(len + 1);
    BIO_read(bio, c->text, len);
    c->text[len] = '\0'; // ensure null-termination
    BIO_free(bio);

    return c->text;
}

static void cert_free(tlsuv_certificate_t cert) {
    struct cert_s* c = (struct cert_s*)cert;
    X509_STORE* s = c->cert;
    if (s != NULL) {
        X509_STORE_free(s);
    }
    tlsuv__free(c->text);
    tlsuv__free(c);
}

static X509* find_leaf_cert(X509_STORE* store) {
    STACK_OF(X509_OBJECT) * s = X509_STORE_get0_objects(store);
    for (int i = 0; i < sk_X509_OBJECT_num(s); i++) {
        X509* c = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(s, i));
        if (X509_check_ca(c) != 0) {
            continue;
        }

        uint32_t ku = X509_get_key_usage(c);
        uint32_t xku = X509_get_extended_key_usage(c);
        if ((ku & KU_DIGITAL_SIGNATURE) && (xku & (XKU_SSL_CLIENT | XKU_SSL_SERVER))) {
            return c;
        }
    }
    return NULL;
}

static int cert_to_pem(const struct tlsuv_certificate_s* cert, int full_chain, char** pem, size_t* pemlen) {
    X509_STORE* store = ((struct cert_s*)cert)->cert;
    STACK_OF(X509_OBJECT) * s = X509_STORE_get0_objects(store);
    if (sk_X509_OBJECT_num(s) == 0) {
        UM_LOG(WARN, "store is empty");
        return -1;
    }

    X509* leaf = find_leaf_cert(store);
    BIO* pembio = BIO_new(BIO_s_mem());
    if (!full_chain) {
        if (leaf == NULL) {
            leaf = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(s, 0));
        }
        if (leaf) {
            PEM_write_bio_X509(pembio, leaf);
        }
    } else {
        // write leaf cert first
        if (leaf) {
            PEM_write_bio_X509(pembio, leaf);
        }
        for (int i = 0; i < sk_X509_OBJECT_num(s); i++) {
            X509* c = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(s, i));
            if (c != leaf) {
                PEM_write_bio_X509(pembio, c);
            }
        }
    }

    *pemlen = BIO_ctrl_pending(pembio);
    *pem = tlsuv__calloc(1, *pemlen + 1);
    BIO_read(pembio, *pem, (int)*pemlen);

    BIO_free_all(pembio);
    return 0;
}

static int cert_verify(const struct tlsuv_certificate_s* cert, enum hash_algo md, const char* data, size_t datalen,
                       const char* sig, size_t siglen) {
    X509_STORE* store = ((struct cert_s*)cert)->cert;
    X509* c = find_leaf_cert(store);
    if (c == NULL) {
        UM_LOG(WARN, "no leaf cert");
        return -1;
    }
    EVP_PKEY* pk = X509_get_pubkey(c);
    if (pk == NULL) {
        unsigned long err = ERR_peek_error();
        UM_LOG(WARN, "no pub key: %ld/%s", err, ERR_lib_error_string(err));
        return -1;
    }
    int rc = verify_signature(pk, md, data, datalen, sig, siglen);
    EVP_PKEY_free(pk);
    return rc;
}

static int cert_exp(const struct tlsuv_certificate_s* cert, struct tm* time) {
    if (time == NULL || cert == NULL) {
        return -1;
    }

    X509_STORE* store = ((struct cert_s*)cert)->cert;
    X509* c = find_leaf_cert(store);
    if (c == NULL) {
        UM_LOG(WARN, "no leaf cert found");
        return -1;
    }
    const ASN1_TIME* notAfter = X509_get0_notAfter(c);
    int64_t posix_time;
    if (!ASN1_TIME_to_posix(notAfter, &posix_time)) {
        return -1;
    }
    time_t t = (time_t)posix_time;
    return gmtime_r(&t, time) != NULL ? 0 : -1;
}
