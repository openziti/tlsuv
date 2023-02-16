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

#include <mbedtls/pk.h>
#include <string.h>
#include <tlsuv/tlsuv.h>

#include "../um_debug.h"
#include "keys.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

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
    mbedtls_pk_free(pub->pkey);
    free(pub->pkey);
    free(pub);
}


int verify_signature (mbedtls_pk_context *pk, enum hash_algo md, const char* data, size_t datalen, const char* sig, size_t siglen) {

    int type;
    const mbedtls_md_info_t *md_info = NULL;
    switch (md) {
        case hash_SHA256:
            type = MBEDTLS_MD_SHA256;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;
        case hash_SHA384:
            type = MBEDTLS_MD_SHA384;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            break;
        case hash_SHA512:
            type = MBEDTLS_MD_SHA512;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            break;
        default:
            return -1;
    }

    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    if (mbedtls_md(md_info, (uint8_t *)data, datalen, hash) != 0) {
        return -1;
    }

    if (mbedtls_pk_verify(pk, type, hash, mbedtls_md_get_size(md_info), (uint8_t *)sig, siglen) != 0) {
        return -1;
    }

    return 0;
}

static int pubkey_verify(tlsuv_public_key_t pk, enum hash_algo md, const char *data, size_t datalen, const char *sig, size_t siglen) {
    struct pub_key_s *pub = (struct pub_key_s *) pk;
    return verify_signature(pub->pkey, md, data, datalen, sig, siglen);
}

static void privkey_free(tlsuv_private_key_t k) {
    struct priv_key_s *priv = (struct priv_key_s *) k;
    mbedtls_pk_free(priv->pkey);
    free(priv->pkey);
    free(priv);
}

static int privkey_sign(tlsuv_private_key_t pk, enum hash_algo md, const char *data, size_t datalen, char *sig, size_t *siglen) {
    struct priv_key_s *priv = (struct priv_key_s *) pk;

    int type;
    const mbedtls_md_info_t *md_info = NULL;
    switch (md) {
        case hash_SHA256:
            type = MBEDTLS_MD_SHA256;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;
        case hash_SHA384:
            type = MBEDTLS_MD_SHA384;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            break;
        case hash_SHA512:
            type = MBEDTLS_MD_SHA512;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            break;
        default:
            return -1;
    }

    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    memset(hash, 0, sizeof(hash));
    if (mbedtls_md(md_info, (uint8_t *)data, datalen, hash) != 0) {
        return -1;
    }
    int size = mbedtls_md_get_size(md_info);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    if (mbedtls_pk_sign(priv->pkey, type, hash, mbedtls_md_get_size(md_info), (uint8_t *)sig, *siglen, siglen, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        return -1;
    }
    return 0;
}


static tlsuv_public_key_t privkey_pubkey(tlsuv_private_key_t pk) {
    struct priv_key_s *priv = (struct priv_key_s *) pk;
    struct pub_key_s *pub = calloc(1, sizeof(*pub));
    pub_key_init(pub);

    // there is probably a more straight-forward way,
    // but I did not find it
    uint8_t buf[4096];
    mbedtls_pk_write_pubkey_pem(priv->pkey, buf, sizeof(buf));
    mbedtls_pk_context *pubkey = calloc(1, sizeof(*pubkey));
    mbedtls_pk_parse_public_key(pubkey, buf, strlen(buf) + 1);
    pub->pkey = pubkey;

    return (tlsuv_public_key_t) pub;
}

static int privkey_to_pem(tlsuv_private_key_t pk, char **pem, size_t *pemlen) {
    struct priv_key_s *privkey = (struct priv_key_s *) pk;
    uint8_t keybuf[4096];
    int ret;
    if ((ret = mbedtls_pk_write_key_pem(privkey->pkey, keybuf, sizeof(keybuf))) != 0) {
        UM_LOG(ERR, "mbedtls_pk_write_key_pem returned -0x%04x: %s", -ret, mbedtls_error(ret));
        return ret;
    }

    *pemlen = strlen(keybuf) + 1;
    *pem = strdup(keybuf);
    return 0;
}

int load_key(tlsuv_private_key_t *key, const char* keydata, size_t keydatalen) {
    mbedtls_pk_context *pk = calloc(1, sizeof(mbedtls_pk_context));
    mbedtls_pk_init(pk);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    // todo move this into engine init?
    int rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (rc != 0) {
        mbedtls_pk_free(pk);
        free(pk);
        *key = NULL;
        return rc;
    }
    size_t keylen = keydata[keydatalen - 1] == 0 ? keydatalen : keydatalen + 1;
    rc = mbedtls_pk_parse_key(pk, (const unsigned char *) keydata, keylen, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (rc < 0) {
        rc = mbedtls_pk_parse_keyfile(pk, keydata, NULL, mbedtls_ctr_drbg_random, &ctr_drbg);
        if (rc < 0) {
            mbedtls_pk_free(pk);
            free(pk);
            *key = NULL;
            return rc;
        }
    }
    struct priv_key_s *privkey = calloc(1, sizeof(struct priv_key_s));
    priv_key_init(privkey);
    privkey->pkey = pk;
    *key = (tlsuv_private_key_t) privkey;
    return rc;
}


int gen_key(tlsuv_private_key_t *key) {
    int ret;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";
    mbedtls_ecp_group_id ec_curve = MBEDTLS_ECP_DP_SECP256R1;
    mbedtls_pk_type_t pk_type = MBEDTLS_PK_ECKEY;

    mbedtls_pk_context *pk = malloc(sizeof(mbedtls_pk_context));
    mbedtls_pk_init(pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        UM_LOG(ERR, "mbedtls_ctr_drbg_seed returned -0x%04x: %s", -ret, mbedtls_error(ret));
        goto on_error;
    }

    // Generate the key
    if ((ret = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(pk_type))) != 0) {
        UM_LOG(ERR, "mbedtls_pk_setup returned -0x%04x: %s", -ret, mbedtls_error(ret));
        goto on_error;
    }

    if ((ret = mbedtls_ecp_gen_key(ec_curve, mbedtls_pk_ec(*pk), mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        UM_LOG(ERR, "mbedtls_ecp_gen_key returned -0x%04x: %s", -ret, mbedtls_error(ret));
        goto on_error;
    }

    on_error:
    if (ret != 0) {
        mbedtls_pk_free(pk);
        free(pk);
    }
    else {
        struct priv_key_s *private_key = calloc(1, sizeof(struct priv_key_s));
        *private_key = PRIV_KEY_API;
        private_key->pkey = pk;
        *key = (tlsuv_private_key_t)private_key;
    }

    return ret;
}