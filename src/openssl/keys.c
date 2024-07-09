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

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <tlsuv/tlsuv.h>
#include <assert.h>
#include <openssl/param_build.h>

#include "../p11.h"
#include "../um_debug.h"
#include "keys.h"
#include "../alloc.h"
#include "../keychain.h"

static int cert_to_pem(const struct tlsuv_certificate_s * c, int full, char **pem, size_t *pemlen);
static void cert_free(tlsuv_certificate_t c);
static int cert_verify(const struct tlsuv_certificate_s * c, enum hash_algo md, const char *data, size_t datalen, const char *sig, size_t siglen);
static int cert_exp(const struct tlsuv_certificate_s *, struct tm *time);

static struct cert_s cert_API = {
        .free = cert_free,
        .verify = cert_verify,
        .to_pem = cert_to_pem,
        .get_expiration = cert_exp,
};


static int pubkey_to_pem(tlsuv_public_key_t pub, char **pem, size_t *pemlen);
static void pubkey_free(tlsuv_public_key_t k);
static int pubkey_verify(tlsuv_public_key_t pk, enum hash_algo md, const char *data, size_t datalen, const char *sig, size_t siglen);

static struct pub_key_s PUB_KEY_API = {
        .free = pubkey_free,
        .verify = pubkey_verify,
        .to_pem = pubkey_to_pem,
};


static void privkey_free(tlsuv_private_key_t k);
static tlsuv_public_key_t privkey_pubkey(tlsuv_private_key_t pk);
static int privkey_to_pem(tlsuv_private_key_t pk, char **pem, size_t *pemlen);
static int privkey_sign(tlsuv_private_key_t pk, enum hash_algo md,
                        const char *data, size_t datalen, char *sig, size_t *siglen);

static int privkey_get_cert(tlsuv_private_key_t pk, tlsuv_certificate_t *cert);
static int privkey_store_cert(tlsuv_private_key_t pk, tlsuv_certificate_t cert);

// sign methods with pkcs11 token or native keychain
static ECDSA_SIG *privkey_ext_ecdsa(const unsigned char *digest, int len,
                                    const BIGNUM *n1, const BIGNUM *n2, EC_KEY *ec);
static int privkey_ext_sign(int,
                            const unsigned char *d, int dlen, unsigned char *s, unsigned int *slen,
                            const BIGNUM *n1, const BIGNUM *n2, EC_KEY *ec);

static int privkey_ext_rsa_enc(int msglen, const unsigned char *msg,
                               unsigned char *enc,
                               RSA *rsa, int padding);


static struct priv_key_s PRIV_KEY_API = {
        .free = privkey_free,
        .to_pem = privkey_to_pem,
        .pubkey = privkey_pubkey,
        .sign = privkey_sign,
        .get_certificate = privkey_get_cert,
        .store_certificate = privkey_store_cert,
};

static int (*orig_ec_sign)(int, const unsigned char *, int, unsigned char *, unsigned int *,
                           const BIGNUM *, const BIGNUM *, EC_KEY *);

static EC_KEY_METHOD *ext_ec_method;
static RSA_METHOD *p11_rsa_method;
static int p11_ec_idx = 0;
static int p11_rsa_idx = 0;
static int kc_ec_idx = 0;
static int kc_rsa_idx = 0;
static uv_once_t init_once;

static void key_ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                           int idx, long argl, void *argp) {
    (void)parent;
    (void)ad;
    (void)argl;
    (void)argp;

    if (ptr != NULL) {
        if (idx == p11_ec_idx || idx == p11_rsa_idx) {
            p11_key_free(ptr);
        } else if (idx == kc_ec_idx || idx == kc_rsa_idx) {
            keychain_free_key(ptr);
        }
    }
}

static void init() {
    p11_ec_idx = EC_KEY_get_ex_new_index(0, "tlsuv-ec-pkcs11", NULL, NULL, key_ex_free);
    p11_rsa_idx = RSA_get_ex_new_index(0, "tlsuv-rsa-pkcs11", NULL, NULL, key_ex_free);

    kc_ec_idx = EC_KEY_get_ex_new_index(0, "tlsuv-ec-keychain", NULL, NULL,key_ex_free);
    kc_rsa_idx = RSA_get_ex_new_index(0, "tlsuv-rsa-keychain", NULL, NULL, key_ex_free);

    // EC method used with native keychain or pkcs#11 keys
    ext_ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    EC_KEY_METHOD_get_sign(ext_ec_method, &orig_ec_sign, NULL, NULL);
    EC_KEY_METHOD_set_sign(ext_ec_method, privkey_ext_sign, NULL, privkey_ext_ecdsa);

    p11_rsa_method = RSA_meth_dup(RSA_get_default_method());
    RSA_meth_set_priv_enc(p11_rsa_method, privkey_ext_rsa_enc);
}

static void set_ec_ext_impl(EC_KEY *ec, int idx, void *ext_key) {
    uv_once(&init_once, init);

    EC_KEY_set_method(ec, ext_ec_method);
    EC_KEY_set_ex_data(ec, idx, ext_key);
}

static void set_rsa_p11_impl(RSA *rsa, p11_key_ctx *p11_key) {
    uv_once(&init_once, init);

    RSA_set_method(rsa, p11_rsa_method);
    RSA_set_ex_data(rsa, p11_rsa_idx, p11_key);
}

void pub_key_init(struct pub_key_s *pubkey) {
    *pubkey = PUB_KEY_API;
}

void priv_key_init(struct priv_key_s *privkey) {
    *privkey = PRIV_KEY_API;
}

void cert_init(struct cert_s *c) {
    *c = cert_API;
}

static void pubkey_free(tlsuv_public_key_t k) {
    struct pub_key_s *pub = (struct pub_key_s *) k;
    EVP_PKEY_free(pub->pkey);
    tlsuv__free(pub);
}

static int verify_ecdsa_sig(EC_KEY *ec, const EVP_MD *hash, const char* data, size_t datalen, const char* sig, size_t siglen) {
    int rc;
    ECDSA_SIG  *ecdsa_sig = NULL;
    
    EVP_MD_CTX *digestor = EVP_MD_CTX_new();
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_DigestInit(digestor, hash);
    EVP_DigestUpdate(digestor, data, datalen);
    rc = EVP_DigestFinal(digestor, digest, &digest_len);

    if (rc == 1) {
        BIGNUM *r = BN_bin2bn((const uint8_t *) sig, (int) (siglen / 2), NULL);
        BIGNUM *s = BN_bin2bn((const uint8_t *) sig + siglen / 2, (int) siglen / 2, NULL);

        ecdsa_sig = ECDSA_SIG_new();
        ECDSA_SIG_set0(ecdsa_sig, r, s);
        rc = ECDSA_do_verify(digest, (int) digest_len, ecdsa_sig, ec);
    }

    ECDSA_SIG_free(ecdsa_sig);
    EVP_MD_CTX_free(digestor);
    
    return rc == 1 ? 0 : -1;
}

int verify_signature (EVP_PKEY *pk, enum hash_algo md, const char* data, size_t datalen, const char* sig, size_t siglen) {
    const EVP_MD *hash = NULL;
    switch (md) {
        case hash_SHA256: hash = EVP_sha256(); break;
        case hash_SHA384: hash = EVP_sha384(); break;
        case hash_SHA512: hash = EVP_sha512(); break;
        default:
            break;
    }

    EVP_MD_CTX *digestor = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(digestor, NULL, hash, NULL, pk) != 1 ||
        EVP_DigestVerifyUpdate(digestor, data, datalen) != 1) {
        UM_LOG(WARN, "failed to create digest: %s", tls_error(ERR_get_error()));
        return -1;
    }

    int rc = EVP_DigestVerifyFinal(digestor, sig, siglen);
    EVP_MD_CTX_free(digestor);

    if (rc != 1 && EVP_PKEY_id(pk) == EVP_PKEY_EC) {
        const uint8_t *p = (const uint8_t*)sig;
        ECDSA_SIG *ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, (int) siglen);

        // if signature is not DER encoded try verifying it as raw ECDSA signature (EC-point)
        if (ecdsa_sig == NULL) {
            EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pk);
            int verified = verify_ecdsa_sig(ec, hash, data, datalen, sig, siglen);
            EC_KEY_free(ec);
            return verified;
        }

        ECDSA_SIG_free(ecdsa_sig);
    }
    return (rc == 1) ? 0 : -1;
}

static int pubkey_verify(tlsuv_public_key_t pk, enum hash_algo md, const char *data, size_t datalen, const char *sig, size_t siglen) {
    struct pub_key_s *pub = (struct pub_key_s *) pk;
    return verify_signature(pub->pkey, md, data, datalen, sig, siglen);
}

static void privkey_free(tlsuv_private_key_t k) {
    struct priv_key_s *priv = (struct priv_key_s *) k;
    EVP_PKEY_free(priv->pkey);
    tlsuv__free(priv);
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

    if ((EVP_DigestSignInit(digest, &pctx, hash, NULL, priv->pkey) != 1) ||
        (EVP_DigestSignUpdate(digest, data, datalen) != 1)) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to setup digest %ld/%s", err, ERR_lib_error_string(err));
        rc = -1;
    }

    if (EVP_DigestSignFinal(digest, sig, siglen) != 1) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to sign digest %ld/%s", err, ERR_lib_error_string(err));
        rc = -1;
    }

    EVP_MD_CTX_free(digest);
    return rc;
}


static tlsuv_public_key_t privkey_pubkey(tlsuv_private_key_t pk) {
    struct priv_key_s *priv = (struct priv_key_s *) pk;
    struct pub_key_s *pub = tlsuv__calloc(1, sizeof(*pub));
    pub_key_init(pub);

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

    *pem = NULL;
    *pemlen = 0;

    if (!PEM_write_bio_PKCS8PrivateKey(b, privkey->pkey, NULL, NULL, 0, NULL, NULL)) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to generate PEM for private key: %ld/%s", err, ERR_lib_error_string(err));
    } else {
        size_t len = BIO_ctrl_pending(b);
        *pem = tlsuv__calloc(1, len + 1);
        BIO_read(b, *pem, (int) len);
        *pemlen = len;
    }
    BIO_free(b);
    return *pem != NULL ? 0 : -1;
}


static int pubkey_to_pem(tlsuv_public_key_t pub, char **pem, size_t *pemlen) {
    BIO *b = BIO_new(BIO_s_mem());
    struct pub_key_s *pubkey = (struct pub_key_s *) pub;

    *pem = NULL;
    *pemlen = 0;

    if (!PEM_write_bio_PUBKEY(b, pubkey->pkey)) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to generate PEM for public key: %ld/%s", err, ERR_lib_error_string(err));
    } else {
        size_t len = BIO_ctrl_pending(b);
        *pem = tlsuv__calloc(1, len + 1);
        BIO_read(b, *pem, (int) len);
        *pemlen = len;
    }
    BIO_free(b);
    return *pem != NULL ? 0 : -1;
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
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to load key: %ld/%s", err, ERR_lib_error_string(err));
        rc = -1;
    } else {
        struct priv_key_s *privkey = tlsuv__calloc(1, sizeof(struct priv_key_s));
        priv_key_init(privkey);
        privkey->pkey = pk;
        *key = (tlsuv_private_key_t) privkey;
    }
    BIO_free(kb);
    return rc;
}

static int load_pkcs11_ec(EVP_PKEY *pkey, p11_key_ctx *p11_key, const char *id, const char *label) {
    size_t len;
    char *value = NULL;
    const unsigned char *a;
    ASN1_OCTET_STRING *os = NULL;

    EC_KEY *ec = EC_KEY_new();
    int rc = p11_get_key_attr(p11_key, CKA_EC_PARAMS, &value, &len);
    if (rc != 0) {
        UM_LOG(WARN, "failed to load EC parameters for key id[%s] label[%s]: %d/%s", id, label, rc, p11_strerror(rc));
        goto error;
    } else {
        a = (const unsigned char*)value;
        if (d2i_ECParameters(&ec, &a, (long) len) == NULL) {
            unsigned long err = ERR_get_error();
            UM_LOG(WARN, "failed to set EC parameters for key id[%s] label[%s]: %ld/%s", id, label, err, ERR_lib_error_string(err));
            goto error;
        }

        tlsuv__free(value);
        value = NULL;
    }

    rc = p11_get_key_attr(p11_key, CKA_EC_POINT, &value, &len);
    if (rc != 0) {
        UM_LOG(WARN, "failed to load EC point for key id[%s] label[%s]: %d/%s", id, label, rc, p11_strerror(rc));
        goto error;
    } else {
        a = (const unsigned char*)value;
        os = d2i_ASN1_OCTET_STRING(NULL, &a, (long)len);
        if (os) {
            a = os->data;
            if (o2i_ECPublicKey(&ec, &a, os->length) == NULL) {
                unsigned long err = ERR_get_error();
                UM_LOG(WARN, "failed to set EC pubkey for key id[%s] label[%s]: %ld/%s", id, label, err, ERR_lib_error_string(err));
                goto error;
            }
            ASN1_STRING_free(os);
            os = NULL;
        } else {
            if(o2i_ECPublicKey(&ec, &a, (int) len) == NULL) {
                unsigned long err = ERR_get_error();
                UM_LOG(WARN, "failed to set EC pubkey for key id[%s] label[%s]: %ld/%s", id, label, err, ERR_lib_error_string(err));
                goto error;
            }
        }
        tlsuv__free(value);
        value = NULL;
    }

    set_ec_ext_impl(ec, p11_ec_idx, p11_key);

    if (!EVP_PKEY_set1_EC_KEY(pkey, ec)) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to set EC pubkey for key id[%s] label[%s]: %ld/%s", id, label, err, ERR_lib_error_string(err));
        goto error;
    }
    EC_KEY_free(ec); // decrease refcount

    return 0;

    error:
    if (os) ASN1_STRING_free(os);
    if (ec) EC_KEY_free(ec);
    tlsuv__free(value);

    return -1;
}

static int load_pkcs11_rsa(EVP_PKEY *pkey, p11_key_ctx *p11_key, const char *id, const char *label) {
    RSA *rsa = RSA_new();

    size_t len;
    uint8_t *value = NULL;
    int rc;

    BIGNUM *n = NULL, *e = NULL;

    if (p11_get_key_attr(p11_key, CKA_PUBLIC_EXPONENT, (char**)&value, &len) != 0) {
        goto error;
    }
    e = BN_bin2bn(value, (int)len, NULL);
    tlsuv__free(value);
    value = NULL;

    if (p11_get_key_attr(p11_key, CKA_MODULUS, (char**)&value, &len) != 0) {
        goto error;
    }
    n = BN_bin2bn(value, (int)len, NULL);
    tlsuv__free(value);
    value = NULL;

    RSA_set0_key(rsa, n, e, NULL);
    set_rsa_p11_impl(rsa, p11_key);
    EVP_PKEY_set1_RSA(pkey, rsa);
    RSA_free(rsa); // dec refcount
    return 0;

error:
    BN_free(e);
    BN_free(n);
    tlsuv__free(value);
    return -1;
}


int gen_pkcs11_key(tlsuv_private_key_t *key, const char *pkcs11driver, const char *slot, const char *pin, const char *label) {
    uv_once(&init_once, init);

    p11_context *p11 = tlsuv__calloc(1, sizeof(*p11));
    p11_key_ctx *p11_key = NULL;
    EVP_PKEY *pkey = NULL;

    int rc = p11_init(p11, pkcs11driver, slot, pin);
    if (rc != 0) {
        UM_LOG(WARN, "failed to init pkcs#11 token driver[%s] slot[%s]: %d/%s", pkcs11driver, slot, rc, p11_strerror(rc));
        tlsuv__free(p11);
        return rc;
    }

    p11_key = tlsuv__calloc(1, sizeof(*p11_key));
    if (p11_gen_key(p11, p11_key, label) != 0) {
        goto error;
    }


    pkey = EVP_PKEY_new();
    switch (p11_key->key_type) {
        case CKK_EC: load_pkcs11_ec(pkey, p11_key, NULL, label); break;
        case CKK_RSA:
            load_pkcs11_rsa(pkey, p11_key, NULL, label);
            break;
        default:
            UM_LOG(WARN, "unsupported pkcs11 key type: %lu", p11_key->key_type);
            goto error;
    }

    struct priv_key_s *private_key = tlsuv__calloc(1, sizeof(struct priv_key_s));
    *private_key = PRIV_KEY_API;
    private_key->pkey = pkey;
    *key = (tlsuv_private_key_t)private_key;

    return 0;

    error:
    tlsuv__free(p11_key);
    tlsuv__free(p11);
    if(pkey) EVP_PKEY_free(pkey);
    return -1;
}

int load_kc_key(EVP_PKEY **pkey, keychain_key_t k) {
    uv_once(&init_once, init);

    int rc = 0;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    if (keychain_key_type(k) == keychain_key_ec) {
        char pub[1024];
        size_t publen = sizeof(pub);
        if (keychain_key_public(k, pub, &publen) != 0) {
            UM_LOG(WARN, "failed to load public key from keychain");
            rc = -1;
            goto error;
        }

        const char *group = NULL;
        size_t keysize = (publen/2) * 8;
        if (keysize == 256) {
            group = "prime256v1";
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_X9_62_prime256v1);
        EVP_PKEY_fromdata_init(pkey_ctx);
        rc = EVP_PKEY_fromdata(pkey_ctx, pkey, EVP_PKEY_PRIVATE_KEY, (OSSL_PARAM[]){
                OSSL_PARAM_octet_string("pub", pub, publen),
                OSSL_PARAM_utf8_string("group",  group, 0),
                OSSL_PARAM_END
        });

        if(rc != 1) {
            unsigned long err = ERR_get_error();
            UM_LOG(WARN, "failed to set EC pubkey for key id[%s] label[%s]: %ld/%s", "id", "label", err, ERR_lib_error_string(err));
            goto error;
        }

        EC_KEY *key = EVP_PKEY_get1_EC_KEY(*pkey);
        EC_KEY_set_ex_data(key, kc_ec_idx, k);
        EC_KEY_set_method(key, ext_ec_method);
        EVP_PKEY_set1_EC_KEY(*pkey, key);
        EC_KEY_free(key); // decrease refcount
    } else if (keychain_key_type(k) == keychain_key_rsa) {

    }

    error:
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    return rc;
}

int gen_keychain_key(tlsuv_private_key_t *key, const char *name) {
    uv_once(&init_once, init);

    EVP_PKEY *pkey = NULL;

    keychain_key_t k = NULL;
    long err = keychain_gen_key(&k, keychain_key_ec, name);
    if (err != 0) {
        goto error;
    }

    load_kc_key(&pkey, k);

    struct priv_key_s *private_key = tlsuv__calloc(1, sizeof(struct priv_key_s));
    *private_key = PRIV_KEY_API;
    private_key->pkey = pkey;
    *key = (tlsuv_private_key_t)private_key;

    return 0;

    error:
    if (k) {
        keychain_free_key(k);
    }

    return -1;

}

int load_keychain_key(tlsuv_private_key_t *key, const char *name) {
    uv_once(&init_once, init);

    EVP_PKEY *pkey = NULL;

    keychain_key_t k = NULL;
    long err = keychain_load_key(&k, name);
    if (err != 0) {
        goto error;
    }

    if (load_kc_key(&pkey, k) != 0) {
        goto error;
    }

    struct priv_key_s *private_key = tlsuv__calloc(1, sizeof(struct priv_key_s));
    *private_key = PRIV_KEY_API;
    private_key->pkey = pkey;
    *key = (tlsuv_private_key_t)private_key;

    return 0;

    error:
    if (k) {
        keychain_free_key(k);
    }

    return -1;
}

int load_pkcs11_key(tlsuv_private_key_t *key, const char *lib, const char *slot, const char *pin, const char *id, const char *label) {
    uv_once(&init_once, init);

    p11_context *p11 = tlsuv__calloc(1, sizeof(*p11));
    p11_key_ctx *p11_key = NULL;
    EVP_PKEY *pkey = NULL;

    int rc = p11_init(p11, lib, slot, pin);
    if (rc != 0) {
        UM_LOG(WARN, "failed to init pkcs#11 token driver[%s] slot[%s]: %d/%s", lib, slot, rc, p11_strerror(rc));
        tlsuv__free(p11);
        return rc;
    }

    p11_key = tlsuv__calloc(1, sizeof(*p11_key));
    rc = p11_load_key(p11, p11_key, id, label);
    if (rc != 0) {
        UM_LOG(WARN, "failed to load pkcs#11 key id[%s] label[%s]: %d/%s", id, label, rc, p11_strerror(rc));
        goto error;
    }

    pkey = EVP_PKEY_new();
    switch (p11_key->key_type) {
        case CKK_EC: load_pkcs11_ec(pkey, p11_key, id, label); break;
        case CKK_RSA: load_pkcs11_rsa(pkey, p11_key, id, label); break;
        default:
            UM_LOG(WARN, "unsupported pkcs11 key type: %lu", p11_key->key_type);
            goto error;
    }

    struct priv_key_s *private_key = tlsuv__calloc(1, sizeof(struct priv_key_s));
    *private_key = PRIV_KEY_API;
    private_key->pkey = pkey;
    *key = (tlsuv_private_key_t)private_key;

    return 0;

error:
    tlsuv__free(p11_key);
    tlsuv__free(p11);
    if(pkey) EVP_PKEY_free(pkey);
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
        struct priv_key_s *private_key = tlsuv__calloc(1, sizeof(struct priv_key_s));
        *private_key = PRIV_KEY_API;
        private_key->pkey = pk;
        *key = (tlsuv_private_key_t)private_key;
    }

    EVP_PKEY_CTX_free(pctx);
    return rc;
}

static ECDSA_SIG *privkey_ext_ecdsa(const unsigned char *digest, int len,
                                    const BIGNUM *n1, const BIGNUM *n2,
                                    EC_KEY *ec) {
    p11_key_ctx *p11_key = EC_KEY_get_ex_data(ec, p11_ec_idx);

    ECDSA_SIG *ecdsa_sig = NULL;
    uint8_t sig[512];
    size_t siglen = sizeof(sig);

    if (p11_key) {
        int rc = p11_key_sign(p11_key, digest, len, sig, &siglen, 0);
        if (rc != 0) {
            return NULL;
        }
        BIGNUM *r = BN_bin2bn(sig, (int)siglen/2, NULL);
        BIGNUM *s = BN_bin2bn(sig + siglen/2, (int)siglen/2, NULL);
        ecdsa_sig = ECDSA_SIG_new();
        ECDSA_SIG_set0(ecdsa_sig, r, s);
    }
    return ecdsa_sig;
}

// OpenSSL using encrypt method for signing)
static int privkey_ext_rsa_enc(int msglen, const unsigned char *msg,
                               unsigned char *enc,
                               RSA *rsa, int padding) {
    p11_key_ctx *p11_key = RSA_get_ex_data(rsa, p11_rsa_idx);

    CK_MECHANISM_TYPE mech = 0;
    size_t siglen = RSA_size(rsa);
    if (padding == RSA_PKCS1_PADDING) {
        mech = CKM_RSA_PKCS;
    } else if (padding == RSA_NO_PADDING) {
        mech = CKM_RSA_X_509;
    } else if (padding == RSA_X931_PADDING) {
        mech = CKM_RSA_X9_31;
    }
    int rc = p11_key_sign(p11_key, msg, msglen, enc, &siglen, mech);

    return rc != 0 ? rc : (int)siglen;
}

static int privkey_get_cert(tlsuv_private_key_t pk, tlsuv_certificate_t *cert) {
    struct priv_key_s *key = (struct priv_key_s *) pk;

    p11_key_ctx *p11_key = NULL;
    switch (EVP_PKEY_id(key->pkey)) {
        case EVP_PKEY_EC:
            p11_key = EC_KEY_get_ex_data(EVP_PKEY_get0_EC_KEY(key->pkey), p11_ec_idx);
            break;
        case EVP_PKEY_RSA:
            p11_key = RSA_get_ex_data(EVP_PKEY_get0_RSA(key->pkey), p11_rsa_idx);
            break;
    }

    if (p11_key == NULL) {
        return -1;
    }

    char *der;
    size_t derlen;

    if (p11_get_key_cert(p11_key, &der, &derlen) == 0) {
        const uint8_t *a = (const uint8_t *)der;
        X509 *c = d2i_X509(NULL, &a, (long)derlen);

        struct cert_s *crt = tlsuv__calloc(1, sizeof(*crt));
        cert_init(crt);
        X509_STORE *store = X509_STORE_new();
        X509_STORE_add_cert(store, c);
        X509_free(c);
        crt->cert = store;
        *cert = (tlsuv_certificate_t) crt;
        tlsuv__free(der);
        return 0;
    }

    return -1;
}

static int privkey_store_cert(tlsuv_private_key_t pk, tlsuv_certificate_t cert) {
    struct priv_key_s *key = (struct priv_key_s *) pk;

    p11_key_ctx *p11_key = NULL;
    switch (EVP_PKEY_id(key->pkey)) {
        case EVP_PKEY_EC:
            p11_key = EC_KEY_get_ex_data(EVP_PKEY_get0_EC_KEY(key->pkey), p11_ec_idx);
            break;
        case EVP_PKEY_RSA:
            p11_key = RSA_get_ex_data(EVP_PKEY_get0_RSA(key->pkey), p11_rsa_idx);
            break;
    }

    if (p11_key == NULL) {
        return -1;
    }
    X509_STORE *store = ((struct cert_s*)cert)->cert;

    STACK_OF(X509_OBJECT) *objects = X509_STORE_get0_objects(store);

    X509_OBJECT *obj = sk_X509_OBJECT_value(objects, 0);
    X509 *c = X509_OBJECT_get0_X509(obj);

    X509_NAME *subj_name = X509_get_subject_name(c);
    unsigned char *subj_der = NULL;
    int subjlen = i2d_X509_NAME(subj_name, &subj_der);

    char *der = NULL;
    int derlen = i2d_X509(c, (unsigned char **) &der);

    int rc = p11_store_key_cert(p11_key, der, derlen, (char*)subj_der, subjlen);

    OPENSSL_free(der);
    OPENSSL_free(subj_der);
    return rc;
}

static void cert_free(tlsuv_certificate_t cert) {
    struct cert_s *c = (struct cert_s *) cert;
    X509_STORE *s = c->cert;
    if (s != NULL) {
        X509_STORE_free(s);
    }
    tlsuv__free(c);
}

static int cert_to_pem(const struct tlsuv_certificate_s * cert, int full_chain, char **pem, size_t *pemlen) {
    X509_STORE *store = ((struct cert_s*)cert)->cert;

    BIO *pembio = BIO_new(BIO_s_mem());
    X509 *c;
    STACK_OF(X509_OBJECT) *s = X509_STORE_get0_objects(store);
    for (int i = 0; i < sk_X509_OBJECT_num(s); i++) {
        c = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(s, i));
        PEM_write_bio_X509(pembio, c);
        if (!full_chain) {
            break;
        }
    }

    *pemlen = BIO_ctrl_pending(pembio);
    *pem = tlsuv__calloc(1, *pemlen + 1);
    BIO_read(pembio, *pem, (int)*pemlen);

    BIO_free_all(pembio);
    return 0;
}

static int cert_verify(const struct tlsuv_certificate_s * cert, enum hash_algo md, const char* data, size_t datalen, const char* sig, size_t siglen) {
    X509_STORE *store = ((struct cert_s*)cert)->cert;
    STACK_OF(X509_OBJECT ) *s = X509_STORE_get0_objects(store);
    X509 *c = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(s, 0));
    EVP_PKEY *pk = X509_get_pubkey(c);
    if (pk == NULL) {
        unsigned long err = ERR_peek_error();
        UM_LOG(WARN, "no pub key: %ld/%s", err, ERR_lib_error_string(err));
    }
    int rc = verify_signature(pk, md, data, datalen, sig, siglen);
    EVP_PKEY_free(pk);
    return rc;
}

static int cert_exp(const struct tlsuv_certificate_s * cert, struct tm *time) {
    if (time == NULL || cert == NULL) {
        return UV_EINVAL;
    }
    
    X509_STORE *store = ((struct cert_s*)cert)->cert;
    STACK_OF(X509_OBJECT ) *s = X509_STORE_get0_objects(store);
    X509 *c = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(s, 0));
    const ASN1_TIME *notAfter = X509_get0_notAfter(c);
    return ASN1_TIME_to_tm(notAfter, time) == 1 ? 0 : -1;
}


int privkey_ext_sign(int type,
                     const unsigned char *d, int dlen, unsigned char *s, unsigned int *slen,
                     const BIGNUM *n1, const BIGNUM *n2, EC_KEY *ec) {
    keychain_key_t kc_key = EC_KEY_get_ex_data(ec, kc_ec_idx);
    if (kc_key == NULL) {
        return orig_ec_sign(type, d, dlen, s, slen, n1, n2, ec);
    }

    if (keychain_key_sign(kc_key, d, dlen, s, slen, 0) != 0) {
        return 0;
    }

    return 1;
}

int remove_keychain_key(const char *name) {
    return keychain_rem_key(name);
}