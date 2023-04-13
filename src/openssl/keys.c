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
#include <openssl/types.h>

#include <tlsuv/tlsuv.h>

#include "../p11.h"
#include "../um_debug.h"
#include "keys.h"

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

static int privkey_get_cert(tlsuv_private_key_t pk, tls_cert *cert);
static int privkey_store_cert(tlsuv_private_key_t pk, tls_cert cert);

static ECDSA_SIG *privkey_p11_sign_sig(const unsigned char *digest, int len, const BIGNUM *pSt, const BIGNUM *pBignumSt, EC_KEY *ec);
static int privkey_p11_rsa_enc(int msglen, const unsigned char *msg,
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

static EC_KEY_METHOD *p11_ec_method;
static RSA_METHOD *p11_rsa_method;
static int p11_ec_idx = 0;
static int p11_rsa_idx = 0;
static uv_once_t init_once;

static void p11_ec_ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                           int idx, long argl, void *argp)
{
    if (ptr != NULL && idx == p11_ec_idx) {
        p11_key_free(ptr);
    }
}

static void init() {
    p11_ec_idx = EC_KEY_get_ex_new_index(0, "tlsuv-ec-pkcs11", NULL, NULL, p11_ec_ex_free);
    p11_rsa_idx = RSA_get_ex_new_index(0, "tlsuv-rsa-pkcs11", NULL, NULL, p11_ec_ex_free);

    p11_ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    int (*orig_sign)(int, const unsigned char *, int, unsigned char *, unsigned int *, const BIGNUM *, const BIGNUM *, EC_KEY *);
    EC_KEY_METHOD_get_sign(p11_ec_method, &orig_sign, NULL, NULL);
    EC_KEY_METHOD_set_sign(p11_ec_method, orig_sign, NULL, privkey_p11_sign_sig);

    p11_rsa_method = RSA_meth_dup(RSA_get_default_method());
    RSA_meth_set_priv_enc(p11_rsa_method, privkey_p11_rsa_enc);
}

static void set_ec_p11_impl(EC_KEY *ec, p11_key_ctx *p11_key) {
    uv_once(&init_once, init);

    EC_KEY_set_method(ec, p11_ec_method);
    EC_KEY_set_ex_data(ec, p11_ec_idx, p11_key);
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

static void pubkey_free(tlsuv_public_key_t k) {
    struct pub_key_s *pub = (struct pub_key_s *) k;
    EVP_PKEY_free(pub->pkey);
    free(pub);
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
    
    BIGNUM *r = BN_bin2bn((const uint8_t*)sig, (int)(siglen / 2), NULL);
    BIGNUM *s = BN_bin2bn((const uint8_t*)sig + siglen/2, (int)siglen/2, NULL);

    ecdsa_sig = ECDSA_SIG_new();
    rc = ECDSA_SIG_set0(ecdsa_sig, r, s);
    rc = ECDSA_do_verify(digest, (int)digest_len, ecdsa_sig, ec);

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
    
    if (EVP_PKEY_id(pk) == EVP_PKEY_EC) {
        const uint8_t *p = sig;
        ECDSA_SIG *ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, (int) siglen);

        // if signature is not DER encoded try verifying it as raw ECDSA signature (EC-point)
        if (ecdsa_sig == NULL) {
            return verify_ecdsa_sig(EVP_PKEY_get1_EC_KEY(pk), hash, data, datalen, sig, siglen);
        }

        ECDSA_SIG_free(ecdsa_sig);
    }

    int rc = 0;
    EVP_MD_CTX *digestor = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;

    if (!EVP_DigestVerifyInit(digestor, &pctx, hash, NULL, pk)) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to setup digest %ld/%s", err, ERR_lib_error_string(err));
        rc = -1;
    } else if (EVP_DigestVerify(digestor, (const uint8_t *) sig, siglen, (const uint8_t *) data, datalen) != 1) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to verify digest %ld/%s", err, ERR_lib_error_string(err));
        rc = -1;
    }
    EVP_MD_CTX_free(digestor);

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
    if (!EVP_DigestSignInit(digest, &pctx, hash, NULL, priv->pkey)) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to setup digest %ld/%s", err, ERR_lib_error_string(err));
        rc = -1;
    } else {
        if (EVP_DigestSign(digest, (uint8_t *)sig, siglen, (const uint8_t *) data, datalen) != 1) {
            unsigned long err = ERR_get_error();
            UM_LOG(WARN, "failed to sign digest %ld/%s", err, ERR_lib_error_string(err));
            rc = -1;
        }
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

    *pem = NULL;
    *pemlen = 0;

    if (!PEM_write_bio_PKCS8PrivateKey(b, privkey->pkey, NULL, NULL, 0, NULL, NULL)) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to generate PEM for private key: %d/%s", err, ERR_lib_error_string(err));
    } else {
        size_t len = BIO_ctrl_pending(b);
        *pem = calloc(1, len + 1);
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
        UM_LOG(WARN, "failed to generate PEM for public key: %d/%s", err, ERR_lib_error_string(err));
    } else {
        size_t len = BIO_ctrl_pending(b);
        *pem = calloc(1, len + 1);
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
            UM_LOG(WARN, "failed to set EC parameters for key id[%s] label[%s]: %d/%s", id, label, err, ERR_lib_error_string(err));
            goto error;
        }

        free(value);
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
                UM_LOG(WARN, "failed to set EC pubkey for key id[%s] label[%s]: %d/%s", id, label, err, ERR_lib_error_string(err));
                goto error;
            }
            ASN1_STRING_free(os);
            os = NULL;
        } else {
            if(o2i_ECPublicKey(&ec, &a, (int) len) == NULL) {
                unsigned long err = ERR_get_error();
                UM_LOG(WARN, "failed to set EC pubkey for key id[%s] label[%s]: %d/%s", id, label, err, ERR_lib_error_string(err));
                goto error;
            }
        }
        free(value);
        value = NULL;
    }

    set_ec_p11_impl(ec, p11_key);

    if (!EVP_PKEY_set1_EC_KEY(pkey, ec)) {
        unsigned long err = ERR_get_error();
        UM_LOG(WARN, "failed to set EC pubkey for key id[%s] label[%s]: %d/%s", id, label, err, ERR_lib_error_string(err));
        goto error;
    }
    EC_KEY_free(ec); // decrease refcount

    return 0;

    error:
    if (os) ASN1_STRING_free(os);
    if (ec) EC_KEY_free(ec);
    free(value);

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
    free(value);
    value = NULL;

    if (p11_get_key_attr(p11_key, CKA_MODULUS, (char**)&value, &len) != 0) {
        goto error;
    }
    n = BN_bin2bn(value, (int)len, NULL);
    free(value);
    value = NULL;

    RSA_set0_key(rsa, n, e, NULL);
    set_rsa_p11_impl(rsa, p11_key);
    EVP_PKEY_set1_RSA(pkey, rsa);
    RSA_free(rsa); // dec refcount
    return 0;

error:
    BN_free(e);
    BN_free(n);
    free(value);
    return -1;
}

int load_pkcs11_key(tlsuv_private_key_t *key, const char *lib, const char *slot, const char *pin, const char *id, const char *label) {
    p11_context *p11 = calloc(1, sizeof(*p11));
    p11_key_ctx *p11_key = NULL;
    EVP_PKEY *pkey = NULL;

    int rc = p11_init(p11, lib, slot, pin);
    if (rc != 0) {
        UM_LOG(WARN, "failed to init pkcs#11 token driver[%s] slot[%s]: %d/%s", lib, slot, rc, p11_strerror(rc));
        free(p11);
        return rc;
    }

    p11_key = calloc(1, sizeof(*p11_key));
    rc = p11_load_key(p11, p11_key, id, label);
    if (rc != 0) {
        UM_LOG(WARN, "failed to load pkcs#11 key id[%s] label[%s]: %d/%s", id, label, rc, p11_strerror(rc));
        goto error;
    }

    pkey = EVP_PKEY_new();
    switch (p11_key->key_type) {
        case CKK_EC: load_pkcs11_ec(pkey, p11_key, id, label); break;
        case CKK_RSA:
            load_pkcs11_rsa(pkey, p11_key, id, label);
            break;
        default:
            UM_LOG(WARN, "unsupported pkcs11 key type: %d", p11_key->key_type);
            goto error;
    }

    struct priv_key_s *private_key = calloc(1, sizeof(struct priv_key_s));
    *private_key = PRIV_KEY_API;
    private_key->pkey = pkey;
    *key = (tlsuv_private_key_t)private_key;

    return 0;

error:
    free(p11_key);
    free(p11);
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
        struct priv_key_s *private_key = calloc(1, sizeof(struct priv_key_s));
        *private_key = PRIV_KEY_API;
        private_key->pkey = pk;
        *key = (tlsuv_private_key_t)private_key;
    }

    EVP_PKEY_CTX_free(pctx);
    return rc;
}

static ECDSA_SIG *privkey_p11_sign_sig(const unsigned char *digest, int len, const BIGNUM *pSt, const BIGNUM *pBignumSt, EC_KEY *ec) {
    p11_key_ctx *p11_key = EC_KEY_get_ex_data(ec, p11_ec_idx);

    uint8_t sig[512];
    size_t siglen = sizeof(sig);
    int rc = p11_key_sign(p11_key, digest, len, sig, &siglen, 0);

    BIGNUM *r = BN_bin2bn(sig, (int)siglen/2, NULL);
	BIGNUM *s = BN_bin2bn(sig + siglen/2, (int)siglen/2, NULL);
	ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
	rc = ECDSA_SIG_set0(ecdsa_sig, r, s);

    return ecdsa_sig;
}

// OpenSSL using encrypt method for signing)
static int privkey_p11_rsa_enc(int msglen, const unsigned char *msg,
                                unsigned char *enc,
                                RSA *rsa, int padding) {
    p11_key_ctx *p11_key = RSA_get_ex_data(rsa, p11_rsa_idx);

    CK_MECHANISM_TYPE mech;
    size_t siglen = RSA_size(rsa);
    if (padding == RSA_PKCS1_PADDING) {
        mech = CKM_RSA_PKCS;
    } else if (padding == RSA_NO_PADDING) {
        mech = CKM_RSA_X_509;
    } else if (padding == RSA_X931_PADDING) {
        mech = CKM_RSA_X9_31;
    }
    int rc = p11_key_sign(p11_key, msg, msglen, enc, &siglen, mech);

    return (int)siglen;
}

static int privkey_get_cert(tlsuv_private_key_t pk, tls_cert *cert) {
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
        X509_STORE_CTX *store = X509_STORE_CTX_new();
        X509_STORE_CTX_set_cert(store, c);
        *cert = store;
        free(der);
        return 0;
    }

    return -1;
}

static int privkey_store_cert(tlsuv_private_key_t pk, tls_cert cert) {
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
    X509_STORE_CTX *store = cert;
    X509 *c = X509_STORE_CTX_get0_cert(store);

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