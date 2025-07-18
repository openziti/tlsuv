// Copyright (c) 2025. NetFoundry Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
//         https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//

#include "keys.h"
#include "cert.h"
#include "../alloc.h"
#include "../um_debug.h"

#include <tlsuv/tls_engine.h>
#include <ncrypt.h>

#define PK_HEADER  "-----BEGIN PRIVATE KEY-----\n"
#define PK_FOOTER "-----END PRIVATE KEY-----\n"

#define EC_PK_HEADER  "-----BEGIN EC PRIVATE KEY-----\n"

#define RSA_PK_HEADER  "-----BEGIN RSA PRIVATE KEY-----\n"

#define PUB_HEADER  "-----BEGIN PUBLIC KEY-----\n"
#define PUB_FOOTER "-----END PUBLIC KEY-----\n"

static struct win32crypto_private_key_s* new_private_key(NCRYPT_PROV_HANDLE ph, NCRYPT_KEY_HANDLE kh);

extern int win32crypto_generate_key(tlsuv_private_key_t *key) {
    NCRYPT_PROV_HANDLE ph = 0;
    NCRYPT_KEY_HANDLE kh = 0;
    *key = NULL;

    DWORD export_flags = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    SECURITY_STATUS rc;
    if (
        (rc = NCryptOpenStorageProvider(&ph, MS_KEY_STORAGE_PROVIDER, 0)) == ERROR_SUCCESS &&
        (rc = NCryptCreatePersistedKey(ph, &kh, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0, 0)) == ERROR_SUCCESS &&
        (rc = NCryptSetProperty(kh, NCRYPT_EXPORT_POLICY_PROPERTY, (BYTE*)&export_flags, sizeof(export_flags), 0)) == ERROR_SUCCESS &&
        (rc = NCryptFinalizeKey(kh, 0)) == ERROR_SUCCESS
    ) {
        *key = (tlsuv_private_key_t) new_private_key(ph, kh);
    } else {
        LOG_ERROR(WARN, rc, "failed to generate key");
        NCryptDeleteKey(kh, 0);
        NCryptFreeObject(ph);
    }

    return *key ? 0 : -1;
}

static SECURITY_STATUS load_rsa_key(NCRYPT_PROV_HANDLE prov, NCRYPT_KEY_HANDLE *kh, const BYTE *der, size_t der_len) {
    NTSTATUS r;
    BCRYPT_RSAKEY_BLOB *key_blob = 0;
    DWORD len;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            CNG_RSA_PRIVATE_KEY_BLOB, der, (DWORD)der_len,
                            CRYPT_DECODE_NOCOPY_FLAG, NULL,
                            NULL, &len)) {
        r = (SECURITY_STATUS)GetLastError();
        LOG_ERROR(ERR, r, "failed to parse RSA KEY info");
        return r;
    }

    key_blob = tlsuv__malloc(len);
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            CNG_RSA_PRIVATE_KEY_BLOB, der, (DWORD)der_len,
                            CRYPT_DECODE_NOCOPY_FLAG, NULL,
                            key_blob, &len)) {
        r = (SECURITY_STATUS)GetLastError();
        LOG_ERROR(ERR, r, "failed to parse RSA KEY info");
        tlsuv__free(key_blob);
        return r;
    }

    r = NCryptImportKey(prov, 0, BCRYPT_RSAPRIVATE_BLOB, NULL,
                        kh, (void*)key_blob, len, NCRYPT_DO_NOT_FINALIZE_FLAG);
    tlsuv__free(key_blob);

    if (!BCRYPT_SUCCESS(r)) {
        LOG_ERROR(ERR, r, "failed to import RSA key");
    }
    return r;
}

static SECURITY_STATUS load_ecc_key(NCRYPT_PROV_HANDLE prov, NCRYPT_KEY_HANDLE *kh, const BYTE *der, size_t der_len) {
    NCRYPT_KEY_HANDLE keyH = 0;
    SECURITY_STATUS rc = 0;

    ULONG len = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                             X509_ECC_PRIVATE_KEY, der, (DWORD)der_len,
                             CRYPT_DECODE_NOCOPY_FLAG, NULL, NULL, &len)) {
        rc = (SECURITY_STATUS)GetLastError();
        LOG_ERROR(ERR, rc, "failed to parse EC KEY info");
        return rc;
    }

    CRYPT_ECC_PRIVATE_KEY_INFO *eck = tlsuv__malloc(len);
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                             X509_ECC_PRIVATE_KEY, der, (DWORD)der_len,
                             CRYPT_DECODE_NOCOPY_FLAG, NULL, eck, &len)) {
        rc = (SECURITY_STATUS)GetLastError();
        LOG_ERROR(ERR, rc, "failed to parse EC KEY info");
        tlsuv__free(eck);
        return rc;
    }

    struct {
        BCRYPT_ECCKEY_BLOB ec_blob;
        char key_data[256]; // variable length: should be enough for P521 (66 * 3)
    } ecc_blob = {};
    memset(&ecc_blob, 0, sizeof(ecc_blob));

    if ((eck->szCurveOid && strcmp(eck->szCurveOid, szOID_ECC_CURVE_P256) == 0) ||
        eck->PrivateKey.cbData == 32) {
        ecc_blob.ec_blob.dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
    } else if (strcmp(eck->szCurveOid, szOID_ECC_CURVE_P384) == 0) {
        ecc_blob.ec_blob.dwMagic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
    } else if (strcmp(eck->szCurveOid, szOID_ECC_CURVE_P521) == 0) {
        ecc_blob.ec_blob.dwMagic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
    } else {
        UM_LOG(ERR, "Unsupported ECC curve: %s", eck->szCurveOid);
        tlsuv__free(eck);
        return 0;
    }

    ecc_blob.ec_blob.cbKey = eck->PrivateKey.cbData;
    // construct ECC import blob X[cbData]|Y[cbData]|d[cbData]
    memcpy(ecc_blob.key_data, eck->PublicKey.pbData + 1, eck->PrivateKey.cbData * 2);
    memcpy(ecc_blob.key_data + 2 * eck->PrivateKey.cbData,
        eck->PrivateKey.pbData, eck->PrivateKey.cbData);

    tlsuv__free(eck);

    rc = NCryptImportKey(
        prov, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, &keyH,
        (PBYTE) &ecc_blob, sizeof(ecc_blob.ec_blob) + 3 * ecc_blob.ec_blob.cbKey, NCRYPT_DO_NOT_FINALIZE_FLAG);

    if (rc != ERROR_SUCCESS) {
        LOG_ERROR(ERR, rc, "failed to import ecc key pair");
    } else {
        *kh = keyH;
    }
    return rc;
}

extern int win32crypto_load_key(tlsuv_private_key_t *key, const char *data, size_t data_len) {
    ULONG der_len;
    DWORD skip;
    BYTE *der = NULL;

    if (CryptStringToBinaryA(data, (DWORD)data_len,
                             CRYPT_STRING_BASE64HEADER, NULL, &der_len,
                             &skip, NULL)) {
        der = tlsuv__malloc(der_len);
        CryptStringToBinaryA(data, (DWORD)data_len,
                                  CRYPT_STRING_BASE64HEADER, der, &der_len,
                                  &skip, NULL);
    } else {
        LOG_LAST_ERROR(ERR, "failed to decode PEM data");
        return -1;
    }

    NCRYPT_PROV_HANDLE ph = 0;
    NCRYPT_KEY_HANDLE kh = 0;
    SECURITY_STATUS status = ERROR_SUCCESS;
    NCryptOpenStorageProvider(&ph, MS_KEY_STORAGE_PROVIDER, 0);

    const char *header = data + skip;
    if (strncmp(header, PK_HEADER, sizeof(PK_HEADER) -1) == 0) {
        status = NCryptImportKey(
            ph, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL,
            &kh, der, der_len,
            NCRYPT_SILENT_FLAG | NCRYPT_DO_NOT_FINALIZE_FLAG);
        if (status == 0) {
            goto finish;
        }
        UM_LOG(ERR, "failed to parse private key info: %s", win32_error(status));
    } else if (strncmp(header, EC_PK_HEADER, sizeof(EC_PK_HEADER) - 1) == 0) {
        status = load_ecc_key(ph, &kh, der, der_len);
    } else if (strncmp(header, RSA_PK_HEADER, sizeof(RSA_PK_HEADER) - 1) == 0 ) {
        status = load_rsa_key(ph, &kh, der, der_len);
    } else {
        status = SEC_E_INVALID_PARAMETER;
    }

finish:
    tlsuv__free(der);
    if (status != ERROR_SUCCESS) {
        UM_LOG(ERR, "failed to parse private key info: %s", win32_error(status));
    }
    if (kh != 0) {
        // make key exportable in case we need to re-import it for mutual auth
        DWORD export_policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        NCryptSetProperty(kh, NCRYPT_EXPORT_POLICY_PROPERTY,
                          (PVOID)&export_policy, sizeof(export_policy),
                          NCRYPT_PERSIST_FLAG);
        NCryptFinalizeKey(kh, NCRYPT_SILENT_FLAG);
        *key = (tlsuv_private_key_t)new_private_key(ph, kh);
        return 0;
    }

    NCryptFreeObject(ph);
    return -1;
}

static int priv_key_pem(struct tlsuv_private_key_s *key, char **pem, size_t *pem_len) {
    struct win32crypto_private_key_s *priv_key = (struct win32crypto_private_key_s *) key;
    if (priv_key->key == 0) {
        return -1; // Key not initialized
    }

    ULONG len = 0;
    LPCWSTR type = NCRYPT_PKCS8_PRIVATE_KEY_BLOB;
    DWORD rc = NCryptExportKey(priv_key->key, 0, type, NULL, NULL, 0, &len, 0);
    if (rc != ERROR_SUCCESS) {
        LOG_ERROR(ERR, rc, "Failed to export key");
        return -1;
    }
    BYTE *der = tlsuv__malloc(len);
    ULONG der_len;
    ULONG der64_len;
    NCryptExportKey(priv_key->key, 0, type, NULL, der, len, &der_len, 0);

    CryptBinaryToStringA(der, der_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, NULL, &der64_len);
    char *p = (char *) tlsuv__calloc(strlen(PK_HEADER) + strlen(PK_FOOTER) + der64_len + 1, 1);
    strcpy_s(p, strlen(PK_HEADER) + 1, PK_HEADER);
    CryptBinaryToStringA(der, der_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, p + strlen(PK_HEADER),
                         &der64_len);
    strcpy_s(p + strlen(PK_HEADER) + der64_len, strlen(PK_FOOTER) + 1, PK_FOOTER);

    tlsuv__free(der);
    if (pem_len) {
        *pem_len = strlen(p);
    }
    *pem = p;
    return 0;
}

static void pub_free(tlsuv_public_key_t k) {
    struct win32crypto_public_key_s *pub = (struct win32crypto_public_key_s*)k;
    if (pub) {
        BCryptDestroyKey(pub->key);
        tlsuv__free(pub->info);
        tlsuv__free(pub);
    }
}

static int pub_pem(tlsuv_public_key_t k, char **pem, size_t *pem_len) {
    struct win32crypto_public_key_s *pub = (struct win32crypto_public_key_s*)k;

    DWORD der_len;
    CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pub->info, 0, NULL, NULL, &der_len);
    BYTE *der = tlsuv__malloc(der_len);
    CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pub->info, 0, NULL, der, &der_len);

    DWORD der64_len;
    CryptBinaryToStringA(der, der_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, NULL, &der64_len);
    char *p = (char *) tlsuv__calloc(strlen(PUB_HEADER) + strlen(PUB_FOOTER) + der64_len + 1, 1);
    strcpy_s(p, strlen(PUB_HEADER) + 1, PUB_HEADER);
    CryptBinaryToStringA(der, der_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, p + strlen(PUB_HEADER),
                         &der64_len);
    strcpy_s(p + strlen(PUB_HEADER) + der64_len, strlen(PUB_FOOTER) + 1, PUB_FOOTER);
    tlsuv__free(der);

    if (pem_len) *pem_len = strlen(p);
    *pem = p;
    return 0;
}

static int pub_verify(struct tlsuv_public_key_s * pubkey, enum hash_algo md,
    const char *data, size_t datalen, const char *sig, size_t siglen) {
    struct win32crypto_public_key_s *pub = (struct win32crypto_public_key_s*)pubkey;
    int rc = 0;
    LPCWSTR hash_algo_id = NULL;
    BCRYPT_ALG_HANDLE hash_algo = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE hash_bin[64] = {0}; // SHA-512 is the largest hash size we support
    ULONG hash_bin_len = 0;

    switch(md) {
        case hash_SHA256:
            hash_algo_id = BCRYPT_SHA256_ALGORITHM;
            break;
        case hash_SHA384:
            hash_algo_id = BCRYPT_SHA384_ALGORITHM;
            break;
        case hash_SHA512:
            hash_algo_id = BCRYPT_SHA512_ALGORITHM;
            break;
        default:
            UM_LOG(ERR, "Unsupported hash algorithm");
            return -1;
    }

#define CHECK(op) do { \
NTSTATUS res = op;                       \
if (!BCRYPT_SUCCESS(res)) {  \
        UM_LOG(ERR, "BCrypt operation{" #op "} failed: 0x%x", res); \
        rc = -1; \
        goto done; \
    }} while(0)

    CHECK(BCryptOpenAlgorithmProvider(&hash_algo, hash_algo_id, NULL, 0));
    ULONG count;
    CHECK(BCryptGetProperty(hash_algo, BCRYPT_HASH_LENGTH, (PUCHAR) &hash_bin_len, sizeof(hash_bin_len), &count, 0));
    CHECK(BCryptCreateHash(hash_algo, &hash, NULL, 0, NULL, 0, 0));
    CHECK(BCryptHashData(hash, (PUCHAR)data, (ULONG)datalen, 0));
    CHECK(BCryptFinishHash(hash, hash_bin, hash_bin_len, 0));

    BCRYPT_PKCS1_PADDING_INFO pad = {
        .pszAlgId = hash_algo_id
    };
    DWORD flags = strcmp(pub->info->Algorithm.pszObjId, szOID_RSA_RSA) == 0 ? NCRYPT_PAD_PKCS1_FLAG : 0;

    NTSTATUS verified = BCryptVerifySignature(pub->key, flags ? &pad : NULL,
                                              hash_bin, hash_bin_len,
                                              (PUCHAR) sig, (ULONG)siglen, flags);
    if (!BCRYPT_SUCCESS(verified)) {
        UM_LOG(ERR, "Signature verification failed: 0x%X", verified);
        rc = -1;
    }

    done:

    if (hash_algo) BCryptCloseAlgorithmProvider(hash_algo, 0);
    if (hash) BCryptDestroyHash(hash);

    return rc;

}

static struct tlsuv_public_key_s pub_key_api = {
    .to_pem = pub_pem,
    .free = pub_free,
    .verify = pub_verify, // Not implemented for win32crypto
};

struct tlsuv_public_key_s* priv_key_pub(struct tlsuv_private_key_s * priv) {
    struct win32crypto_private_key_s *pk = (struct win32crypto_private_key_s *) priv;

    DWORD blob_len = 0;
    CryptExportPublicKeyInfo(pk->key, 0, X509_ASN_ENCODING, NULL, &blob_len);
    BYTE *blob = tlsuv__malloc(blob_len);
    CryptExportPublicKeyInfo(pk->key, 0, X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)blob, &blob_len);

    CERT_PUBLIC_KEY_INFO *pub_info = (PCERT_PUBLIC_KEY_INFO)blob;
    BCRYPT_KEY_HANDLE kh = 0;
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                     pub_info, 0, NULL, &kh)) {
        LOG_LAST_ERROR(ERR, "Failed to import public key");
    }
    if (kh == 0) {
        tlsuv__free(blob);
        return NULL;
    }

    struct win32crypto_public_key_s* pub = tlsuv__malloc(sizeof(*pub));
    pub->api = pub_key_api;
    pub->key = kh;
    pub->info = pub_info;
    return (tlsuv_public_key_t)pub;
}

static int priv_key_sign(tlsuv_private_key_t privkey, enum hash_algo md,
                         const char *data, size_t datalen, char *sig, size_t *siglen) {
    struct win32crypto_private_key_s *pk = (struct win32crypto_private_key_s*)privkey;
    int rc = 0;
    LPCWSTR hash_algo_id = NULL;
    BCRYPT_ALG_HANDLE hash_algo = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE hash_bin[64] = {0}; // SHA-512 is the largest hash size we support
    ULONG hash_bin_len = 0;

    switch(md) {
    case hash_SHA256: hash_algo_id = BCRYPT_SHA256_ALGORITHM; break;
    case hash_SHA384: hash_algo_id = BCRYPT_SHA384_ALGORITHM; break;
    case hash_SHA512: hash_algo_id = BCRYPT_SHA512_ALGORITHM; break;
    default:
        UM_LOG(ERR, "Unsupported hash algorithm");
        return -1;
    }

#define CHECK(op) do { \
NTSTATUS res = op;                       \
if (!BCRYPT_SUCCESS(res)) {  \
UM_LOG(ERR, "BCrypt operation{" #op "} failed: 0x%x", res); \
rc = -1; \
goto done; \
}} while(0)

    CHECK(BCryptOpenAlgorithmProvider(&hash_algo, hash_algo_id, NULL, 0));
    ULONG count;
    CHECK(BCryptGetProperty(hash_algo, BCRYPT_HASH_LENGTH, (PUCHAR) &hash_bin_len, sizeof(hash_bin_len), &count, 0));
    CHECK(BCryptCreateHash(hash_algo, &hash, NULL, 0, NULL, 0, 0));
    CHECK(BCryptHashData(hash, (PUCHAR)data, (ULONG)datalen, 0));
    CHECK(BCryptFinishHash(hash, hash_bin, hash_bin_len, 0));

    wchar_t key_type[16] = {};
    DWORD kt_len;
    NCryptGetProperty(pk->key, NCRYPT_ALGORITHM_GROUP_PROPERTY, (PVOID)key_type, sizeof(key_type), &kt_len, 0);
    DWORD len = (DWORD)(*siglen);
    BCRYPT_PKCS1_PADDING_INFO pad = {
        .pszAlgId = hash_algo_id
    };
    DWORD flags = lstrcmpW(key_type, L"RSA") == 0 ? NCRYPT_PAD_PKCS1_FLAG : 0;

    NTSTATUS err = NCryptSignHash(pk->key,
                                  flags ? &pad : NULL, hash_bin, hash_bin_len,
                                  (PBYTE)sig, len, &len, flags);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(ERR, err, "Signature failed");
        rc = -1;
    }
    *siglen = len;
done:

    if (hash_algo) BCryptCloseAlgorithmProvider(hash_algo, 0);
    if (hash) BCryptDestroyHash(hash);

    return rc;
}
static void free_priv_key(struct tlsuv_private_key_s *key) {
    struct win32crypto_private_key_s *priv_key = (struct win32crypto_private_key_s *) key;
    if (priv_key->key) {
        NCryptFreeObject(priv_key->key);
        priv_key->key = 0;
    }
    if (priv_key->provider) {
        NCryptFreeObject(priv_key->provider);
    }
    tlsuv__free(priv_key);
}

static struct tlsuv_private_key_s private_key_api = {
        .to_pem = priv_key_pem,
        .free = free_priv_key,
        .get_certificate = NULL,
        .pubkey = priv_key_pub,
        .sign = priv_key_sign,
        .store_certificate = NULL,
};

static struct win32crypto_private_key_s* new_private_key(NCRYPT_PROV_HANDLE ph, NCRYPT_KEY_HANDLE kh) {
    struct win32crypto_private_key_s *key = tlsuv__calloc(1, sizeof(*key));
    key->api = private_key_api;
    key->provider = ph;
    key->key = kh;
    return key;
}

static wchar_t *providers[] = {
    MS_PLATFORM_KEY_STORAGE_PROVIDER,
    MS_KEY_STORAGE_PROVIDER,
};

static wchar_t *key_algos[] = {
    NCRYPT_ECDSA_P384_ALGORITHM,
    NCRYPT_ECDSA_P256_ALGORITHM,
};

static NCRYPT_PROV_HANDLE get_provider() {
    NCRYPT_PROV_HANDLE prov = 0;
    SECURITY_STATUS rc = 0;
    for (int i = 0; i < sizeof(providers)/sizeof(providers[0]); i++) {
        rc = NCryptOpenStorageProvider(&prov, providers[i], 0);
        if (rc == ERROR_SUCCESS) return prov;
    }

    UM_LOG(ERR, "failed to open supported provider: %s", win32_error(rc));
    return 0;
}

static wchar_t* key_name(const char *id) {
    wchar_t *key_name = tlsuv__calloc(strlen(id) + 1, sizeof(wchar_t));
    swprintf(key_name, strlen(id) + 1, L"%hs", id);
    return key_name;
}

int win32crypto_gen_keychain_key(tlsuv_private_key_t *pk, const char *id) {
    NCRYPT_PROV_HANDLE prov = get_provider();

    if (prov == 0) {
        UM_LOG(ERR, "failed to open a supported key storage provider");
        return -1;
    }

    wchar_t *name = key_name(id);
    NCRYPT_KEY_HANDLE kh = 0;
    for (int i = 0; i < sizeof(key_algos)/sizeof(key_algos[0]); i++) {
        SECURITY_STATUS rc = NCryptCreatePersistedKey(prov, &kh, key_algos[i], name, 0, 0);
        if (rc != ERROR_SUCCESS) continue;

        rc = NCryptFinalizeKey(kh, 0);
        if (rc == ERROR_SUCCESS) break;

        NCryptDeleteKey(kh, NCRYPT_SILENT_FLAG);
        NCryptFreeObject(kh);
        kh = 0;
    }
    tlsuv__free(name);

    if (kh) {
        *pk = (tlsuv_private_key_t)new_private_key(prov, kh);
        return 0;
    }

    NCryptFreeObject(prov);
    return -1;
}

int win32crypto_load_keychain_key(tlsuv_private_key_t *pk, const char *id) {
    NCRYPT_PROV_HANDLE ph = 0;
    NCRYPT_KEY_HANDLE kh = 0;

    wchar_t* name = key_name(id);
    for (int i = 0; i < sizeof(providers)/sizeof(providers[0]); i++) {
        SECURITY_STATUS rc = NCryptOpenStorageProvider(&ph, providers[i], 0);
        if (rc != ERROR_SUCCESS) continue;

        rc = NCryptOpenKey(ph, &kh, name, 0, 0);
        if (rc == ERROR_SUCCESS) {
          UM_LOG(DEBG, "loaded key[%ls] from provider[%ls]", name, providers[i]);
          break;
        }

        kh = 0;
        NCryptFreeObject(ph);
    }

    tlsuv__free(name);
    if (kh) {
        *pk = (tlsuv_private_key_t)new_private_key(ph, kh);
        return 0;
    }

    UM_LOG(ERR, "failed to find key[%s] in any provider", id);
    return -1;
}

int win32crypto_remove_keychain_key(const char *id) {
    NCRYPT_PROV_HANDLE ph = 0;
    NCRYPT_KEY_HANDLE kh = 0;
    wchar_t* name = key_name(id);
    for (int i = 0; i < sizeof(providers)/sizeof(providers[0]); i++) {
        SECURITY_STATUS rc = NCryptOpenStorageProvider(&ph, providers[i], 0);
        if (rc != ERROR_SUCCESS) continue;

        rc = NCryptOpenKey(ph, &kh, name, 0, 0);
        if (rc != ERROR_SUCCESS) {
            NCryptFreeObject(ph);
            continue;
        }

        if (NCryptDeleteKey(kh, 0) != ERROR_SUCCESS) {
            NCryptFreeObject(kh);
        }
        NCryptFreeObject(ph);
        break;
    }
    tlsuv__free(name);
    return 0;
}



