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

#define _WIN32_WINNT 0x0a00 // Windows 7 or later
#include "keys.h"
#include "cert.h"
#include "../alloc.h"
#include "../um_debug.h"

#include <tlsuv/tls_engine.h>

#define PK_HEADER  "-----BEGIN PRIVATE KEY-----\n"
#define PK_FOOTER "-----END PRIVATE KEY-----\n"

#define PUB_HEADER  "-----BEGIN PUBLIC KEY-----\n"
#define PUB_FOOTER "-----END PUBLIC KEY-----\n"

static struct win32crypto_private_key_s* new_private_key(BCRYPT_KEY_HANDLE kh);

static CRYPT_DECODE_PARA DECODE_PARAMS = {
    .cbSize = sizeof(CRYPT_DECODE_PARA),
    .pfnAlloc = tlsuv__malloc,
    .pfnFree = tlsuv__free,
};

static CRYPT_ENCODE_PARA ENCODE_PARAMS = {
        .cbSize = sizeof(ENCODE_PARAMS),
        .pfnAlloc = tlsuv__malloc,
        .pfnFree = tlsuv__free,
};

extern int win32crypto_generate_key(tlsuv_private_key_t *key) {
    BCRYPT_ALG_HANDLE algo = NULL;
    BCRYPT_KEY_HANDLE kh = NULL;
    *key = NULL;

    if (
        BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algo, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0)) &&
        BCRYPT_SUCCESS(BCryptGenerateKeyPair(algo, &kh, 256, 0)) &&
        BCRYPT_SUCCESS(BCryptFinalizeKeyPair(kh, 0))
    ) {
        *key = (tlsuv_private_key_t) new_private_key(kh);
    } else {
        UM_LOG(WARN, "failed to generate key: %s", win32_error(GetLastError()));
    }

    if (algo) {
        BCryptCloseAlgorithmProvider(algo, 0);
    }

    return *key ? 0 : -1;
}

static BCRYPT_KEY_HANDLE load_ecc_key(const BYTE *der, size_t der_len) {
    BCRYPT_ALG_HANDLE algoH = NULL;
    BCRYPT_KEY_HANDLE keyH = INVALID_HANDLE_VALUE;
    NTSTATUS rc = 0;
    struct {
        CRYPT_ECC_PRIVATE_KEY_INFO eck;
        BYTE buf[1024];
    } ecc_info = {};
    ULONG len = sizeof(ecc_info);

    rc = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                             X509_ECC_PRIVATE_KEY, der, der_len,
                             0, &DECODE_PARAMS, &ecc_info, &len);
    if (!rc) {
        UM_LOG(ERR, "failed to parse EC KEY info: %s", win32_error(GetLastError()));
        return INVALID_HANDLE_VALUE;
    }

    struct {
        BCRYPT_ECCKEY_BLOB ec_blob;
        char key_data[256]; // variable length: should be enough for P521 (66 * 3)
    } ecc_blob = {};
    memset(&ecc_blob, 0, sizeof(ecc_blob));

    LPCWSTR algoId = NULL;
    if (strcmp(ecc_info.eck.szCurveOid, szOID_ECC_CURVE_P256) == 0) {
        ecc_blob.ec_blob.dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        algoId = BCRYPT_ECDSA_P256_ALGORITHM;
    } else if (strcmp(ecc_info.eck.szCurveOid, szOID_ECC_CURVE_P384) == 0) {
        ecc_blob.ec_blob.dwMagic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
        algoId = BCRYPT_ECDSA_P384_ALGORITHM;
    } else if (strcmp(ecc_info.eck.szCurveOid, szOID_ECC_CURVE_P521) == 0) {
        ecc_blob.ec_blob.dwMagic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
        algoId = BCRYPT_ECDSA_P521_ALGORITHM;
    } else {
        UM_LOG(ERR, "Unsupported ECC curve: %s", ecc_info.eck.szCurveOid);
        return INVALID_HANDLE_VALUE;
    }
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algoH, algoId, NULL, 0))) {
        UM_LOG(ERR, "failed to open EC algorithm[%ls]: %s", algoId, win32_error(GetLastError()));
    }

    ecc_blob.ec_blob.cbKey = ecc_info.eck.PrivateKey.cbData;
    // construct ECC import blob X[cbData]|Y[cbData]|d[cbData]
    memcpy(ecc_blob.key_data, ecc_info.eck.PublicKey.pbData + 1, ecc_info.eck.PrivateKey.cbData * 2);
    memcpy(ecc_blob.key_data + 2 * ecc_info.eck.PrivateKey.cbData,
        ecc_info.eck.PrivateKey.pbData, ecc_info.eck.PrivateKey.cbData);

    if (!BCRYPT_SUCCESS(BCryptImportKeyPair(
        algoH, NULL, BCRYPT_ECCPRIVATE_BLOB, &keyH,
        (PBYTE) &ecc_blob, sizeof(ecc_blob.ec_blob) + 3 * ecc_blob.ec_blob.cbKey, 0))) {
        UM_LOG(ERR, "failed to import ecc key pair: %s", win32_error(GetLastError()));
    }
    return keyH;
}

extern int win32crypto_load_key(tlsuv_private_key_t *key, const char *data, size_t data_len) {
    ULONG der_len;
    DWORD skip;
    BYTE *der = NULL;
    union {
        CRYPT_PRIVATE_KEY_INFO info;
        char buf[1024];
    } pk_info = {};

    if (CryptStringToBinaryA(data, data_len, CRYPT_STRING_BASE64HEADER, NULL,
                             &der_len, &skip, NULL)) {
        der = tlsuv__malloc(der_len);
        CryptStringToBinaryA(data, data_len,
                             CRYPT_STRING_BASE64HEADER, der, &der_len, &skip, NULL);
    } else {
        UM_LOG(ERR, "failed to decode PEM data");
        return -1;
    }

    const char *header = data + skip;
    if (strncmp(header, ""))

    DWORD str_info = sizeof(pk_info);
    WINBOOL rc = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                     PKCS_PRIVATE_KEY_INFO, der, der_len,
                                     0, &DECODE_PARAMS,
                                     &pk_info, &str_info);
    tlsuv__free(der);
    if (!rc) {
        UM_LOG(ERR, "failed to parse private key info: %s", win32_error(GetLastError()));
        return -1;
    }

    BCRYPT_KEY_HANDLE kh = INVALID_HANDLE_VALUE;
    if (strcmp(pk_info.info.Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY) == 0) {
        kh = load_ecc_key(pk_info.info.PrivateKey.pbData, pk_info.info.PrivateKey.cbData);
    } else if (strcmp(pk_info.info.Algorithm.pszObjId, szOID_RSA_RSA) == 0) {
        UM_LOG(WARN, "TODO: implement here");
    }

    if (kh != INVALID_HANDLE_VALUE) {
        *key = (tlsuv_private_key_t)new_private_key(kh);
        return 0;
    }
    return -1;
}

static int priv_key_pem(struct tlsuv_private_key_s *key, char **pem, size_t *pem_len) {
    struct win32crypto_private_key_s *priv_key = (struct win32crypto_private_key_s *) key;
    if (priv_key->key == NULL) {
        return -1; // Key not initialized
    }
    BCRYPT_KEY_HANDLE kh = priv_key->key;

    ULONG len = 0;
    CRYPT_PRIVATE_KEY_INFO pk_info = {};
    const char *param_oid = NULL;

    LPCWSTR type = BCRYPT_PRIVATE_KEY_BLOB;
    if (!BCRYPT_SUCCESS(BCryptExportKey(priv_key->key, NULL, type, NULL, 0, &len, 0))) {
        UM_LOG(ERR, "Failed to export key: %s", win32_error(GetLastError()));
        return -1;
    }

    BCRYPT_KEY_BLOB *key_blob = (BCRYPT_KEY_BLOB *) tlsuv__malloc(len);
    if (!BCRYPT_SUCCESS(BCryptExportKey(kh, NULL, type, (BYTE*)key_blob, len, &len, 0))) {
        UM_LOG(ERR, "Failed to export key: %s", win32_error(GetLastError()));
        tlsuv__free(key_blob);
        return -1;
    }

    switch (key_blob->Magic) {
        case BCRYPT_ECDSA_PRIVATE_P256_MAGIC:
            pk_info.Algorithm.pszObjId = szOID_ECC_PUBLIC_KEY;
            param_oid = szOID_ECC_CURVE_P256;
            break;
        case BCRYPT_ECDSA_PRIVATE_P384_MAGIC:
            pk_info.Algorithm.pszObjId = szOID_ECC_PUBLIC_KEY;
            param_oid = szOID_ECC_CURVE_P384;
            break;
        case BCRYPT_ECDSA_PRIVATE_P521_MAGIC: {
            pk_info.Algorithm.pszObjId = szOID_ECC_PUBLIC_KEY;
            param_oid = szOID_ECC_CURVE_P521;
            break;
        }
        case BCRYPT_RSAPRIVATE_MAGIC: {
            BCRYPT_RSAKEY_BLOB *rsa_blob = (BCRYPT_RSAKEY_BLOB *) key_blob;
            pk_info.Algorithm.pszObjId = szOID_RSA_RSA;
            pk_info.PrivateKey.pbData = (BYTE*)key_blob + sizeof(BCRYPT_RSAKEY_BLOB);
            pk_info.PrivateKey.cbData = len - sizeof(BCRYPT_RSAKEY_BLOB);
            break;
        }
        default:
            tlsuv__free(key_blob);
            return -1; // Unsupported key type
    }

    if (strcmp(pk_info.Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY) == 0) {
        BCRYPT_ECCKEY_BLOB *ecc_blob = (BCRYPT_ECCKEY_BLOB *) key_blob;
        // ECC key is exported in format X[cbKey]|Y[cbKey]|d[cbKey]:
        // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
        CRYPT_ECC_PRIVATE_KEY_INFO ecc_info = {
                .szCurveOid = (LPSTR)param_oid,
        };

        ecc_info.PrivateKey.cbData = ecc_blob->cbKey;
        ecc_info.PrivateKey.pbData = (BYTE *) ecc_blob + sizeof(BCRYPT_ECCKEY_BLOB) + 2 * ecc_blob->cbKey; // d is at the end of the blob
        ecc_info.PublicKey.cbData = ecc_blob->cbKey * 2 + 1; // uncompressed format: 0x04|X|Y
        ecc_info.PublicKey.pbData = (BYTE*)ecc_blob + sizeof(BCRYPT_ECCKEY_BLOB) - 1;
        ecc_info.PublicKey.pbData[0] = 0x04; // uncompressed point format

        CryptEncodeObjectEx(X509_ASN_ENCODING,
                            X509_OBJECT_IDENTIFIER, &param_oid,
                            CRYPT_ENCODE_ALLOC_FLAG, &ENCODE_PARAMS,
                            &pk_info.Algorithm.Parameters.pbData, &pk_info.Algorithm.Parameters.cbData);
        CryptEncodeObjectEx(X509_ASN_ENCODING,
                            X509_ECC_PRIVATE_KEY, &ecc_info,
                            CRYPT_ENCODE_ALLOC_FLAG, &ENCODE_PARAMS,
                            &pk_info.PrivateKey.pbData, &pk_info.PrivateKey.cbData);
    } else if (strcmp(pk_info.Algorithm.pszObjId, szOID_RSA_RSA) == 0) {
    } else {
        tlsuv__free(key_blob);
        return -1; // Unsupported key type

    }

    char *der = NULL;
    ULONG der_len;
    ULONG der64_len;

    CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
                        &pk_info, CRYPT_ENCODE_ALLOC_FLAG, &ENCODE_PARAMS,
                        &der, &der_len);

    CryptBinaryToStringA((BYTE *) der, der_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, NULL, &der64_len);
    char *p = (char *) tlsuv__calloc(strlen(PK_HEADER) + strlen(PK_FOOTER) + der64_len + 1, 1);
    strcpy_s(p, strlen(PK_HEADER) + 1, PK_HEADER);
    CryptBinaryToStringA((BYTE *) der, der_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, p + strlen(PK_HEADER),
                         &der64_len);
    strcpy_s(p + strlen(PK_HEADER) + der64_len, strlen(PK_FOOTER) + 1, PK_FOOTER);

    tlsuv__free(pk_info.Algorithm.Parameters.pbData);
    tlsuv__free(pk_info.PrivateKey.pbData);

    *pem = p;
    *pem_len = strlen(p);

    tlsuv__free(key_blob);
    return 0;
}

static void free_priv_key(struct tlsuv_private_key_s *key) {
    struct win32crypto_private_key_s *priv_key = (struct win32crypto_private_key_s *) key;
    if (priv_key->key) {
        BCryptDestroyKey(priv_key->key);
        priv_key->key = NULL;
    }
    tlsuv__free(priv_key);
}

static struct tlsuv_public_key_s pub_key_api = {
        .to_pem = NULL, // Not implemented for win32crypto
        .free = NULL, // Not implemented for win32crypto
        .verify = NULL, // Not implemented for win32crypto
};

static struct tlsuv_private_key_s private_key_api = {
        .to_pem = priv_key_pem,
        .free = free_priv_key,
        .get_certificate = NULL,
        .pubkey = NULL,
        .sign = NULL,
        .store_certificate = NULL,
};

static struct win32crypto_private_key_s* new_private_key(BCRYPT_KEY_HANDLE kh) {
    struct win32crypto_private_key_s *key = tlsuv__calloc(1, sizeof(*key));
    key->api = private_key_api;
    key->key = kh;
    return key;
}


