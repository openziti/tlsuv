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

#include <tlsuv/tls_engine.h>

#include "cert.h"
#include "../alloc.h"
#include "../um_debug.h"

#include <time.h>
#include <bcrypt.h>
#include <ncrypt.h>

static void free_cert(tlsuv_certificate_t cert) {
    win32_cert_t *c = (win32_cert_t *) cert;
    if (c->store) {
        CertCloseStore(c->store, CERT_CLOSE_STORE_FORCE_FLAG);
    }
    tlsuv__free(c);
}

static int cert_to_pem(const struct tlsuv_certificate_s *cert, int full, char **pem, size_t *pemlen) {
    win32_cert_t *c = (win32_cert_t *) cert;
    HCERTSTORE store = c->store;
    unsigned int flags = CRYPT_STRING_BASE64HEADER | CRYPT_STRING_NOCR;

    PCCERT_CONTEXT cert_ctx = CertEnumCertificatesInStore(store, NULL);
    if (!cert_ctx) {
        UM_LOG(ERR, "No certificates found in store");
        return -1;
    }
    size_t total_len = 0;
    while(cert_ctx != NULL) {
        DWORD len = 0;
        if (CryptBinaryToStringA(cert_ctx->pbCertEncoded, cert_ctx->cbCertEncoded,
                                 flags, NULL, &len)) {
            total_len += len;
        }
        cert_ctx = CertEnumCertificatesInStore(store, cert_ctx);
    }

    char *pem_buf = tlsuv__malloc(total_len + 1);
    char *p = pem_buf;
    cert_ctx = CertEnumCertificatesInStore(store, NULL);
    while(cert_ctx != NULL) {
        DWORD len = total_len - (p - pem_buf);
        if (CryptBinaryToStringA(cert_ctx->pbCertEncoded, cert_ctx->cbCertEncoded, flags, p, &len)) {
            p += len;
        } else {
            CertFreeCertificateContext(cert_ctx);
            LOG_LAST_ERROR(ERR, "Failed to convert certificate to PEM");
            tlsuv__free(pem_buf);
            return -1;
        }

        if (!full) {
            // If not full, we only need the first cert
            CertFreeCertificateContext(cert_ctx);
            break;
        }

        cert_ctx = CertEnumCertificatesInStore(store, cert_ctx);
    }

    *pem = pem_buf;
    *pemlen = total_len;
    return 0;
}

static int cert_verify(const struct tlsuv_certificate_s *cert, enum hash_algo md,
                        const char *data, size_t datalen, const char *sig, size_t siglen) {
    int rc = 0;
    LPCWSTR hash_algo_id = NULL;
    BCRYPT_ALG_HANDLE hash_algo = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE hash_bin[64] = {0}; // SHA-512 is the largest hash size we support
    ULONG hash_bin_len = 0;
    BCRYPT_KEY_HANDLE key = NULL;

    win32_cert_t *c = (win32_cert_t *) cert;

    PCCERT_CONTEXT cert_ctx = c->cert;
    if (!cert_ctx) {
        UM_LOG(ERR, "No certificates found in store");
        rc = -1;
        goto done;
    }
    CERT_PUBLIC_KEY_INFO *pk = &cert_ctx->pCertInfo->SubjectPublicKeyInfo;
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                     pk, 0, NULL, &key)) {
        LOG_LAST_ERROR(ERR, "Failed to import public key");
        rc = -1;
        goto done;
    }

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
            rc = -1;
            goto done;
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
    CHECK(BCryptHashData(hash, (PUCHAR)data, datalen, 0));
    CHECK(BCryptFinishHash(hash, hash_bin, hash_bin_len, 0));

    BCRYPT_PKCS1_PADDING_INFO pad = { hash_algo_id };
    DWORD flags = strcmp(pk->Algorithm.pszObjId, szOID_RSA_RSA) == 0 ? NCRYPT_PAD_PKCS1_FLAG : 0;

    NTSTATUS verified = BCryptVerifySignature(key, flags ? &pad : NULL,
        hash_bin, hash_bin_len, (PUCHAR) sig, siglen, flags);
    if (!BCRYPT_SUCCESS(verified)) {
        LOG_ERROR(ERR, verified, "Signature verification failed");
        rc = -1;
    }

    done:

    if (hash_algo) BCryptCloseAlgorithmProvider(hash_algo, 0);
    if (hash) BCryptDestroyHash(hash);
    if (key) BCryptDestroyKey(key);

    return rc;
}

static int get_expiration(const struct tlsuv_certificate_s *cert,  struct tm *tm) {
    win32_cert_t *c = (win32_cert_t *) cert;
    PCCERT_CONTEXT cert_ctx = c->cert;
    if (!cert_ctx) {
        UM_LOG(ERR, "No certificates found in store");
        return -1;
    }
    SYSTEMTIME sys_time = {};
    FileTimeToSystemTime(&cert_ctx->pCertInfo->NotAfter, &sys_time);

    memset(tm, 0, sizeof(*tm));
    tm->tm_year = sys_time.wYear - 1900;
    tm->tm_mon = sys_time.wMonth - 1; // tm_mon is 0-11
    tm->tm_mday = sys_time.wDay;
    tm->tm_hour = sys_time.wHour;
    tm->tm_min = sys_time.wMinute;
    tm->tm_sec = sys_time.wSecond;

    return 0;
}

static void fmt_time(const FILETIME *ft, char *out, size_t len) {
    SYSTEMTIME st;
    FileTimeToSystemTime(ft, &st);
    struct tm t = {
            .tm_sec = st.wSecond,
            .tm_min = st.wMinute,
            .tm_hour = st.wHour,
            .tm_mday = st.wDay,
            .tm_mon = st.wMonth - 1,
            .tm_year = st.wYear - 1900
    };

    // Jul 31 17:25:35 2024 GMT
    strftime(out, len, "%b %d %H:%M:%S %Y GMT", &t);
}

static char EC_PUB_FMT[] = "Public Key Algorithm: id-ecPublicKey\n"
                           "Public-Key: (%d bit)\n"
                           "ASN1 OID: %s\n";

static void fmt_pub_key_info(CERT_PUBLIC_KEY_INFO *keyInfo, char *buf, size_t len) {
    if (strcmp(keyInfo->Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY) == 0) {

        int key_size = 0;
        LPSTR *oid = NULL;
        const char *alg_id = NULL;
        DWORD l = 0;
        CryptDecodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER,
                            keyInfo->Algorithm.Parameters.pbData, keyInfo->Algorithm.Parameters.cbData,
                            CRYPT_DECODE_ALLOC_FLAG, 0,
                            &oid, &l
        );
        if (strcmp(*oid, szOID_ECC_CURVE_P256) == 0) {
            key_size = 256;
            alg_id = "prime256v1";
        } else if (strcmp(*oid, szOID_ECC_CURVE_P384) == 0) {
            key_size = 384;
            alg_id = "secp384r1";
        } else if (strcmp(*oid, szOID_ECC_CURVE_P521) == 0) {
            key_size = 521;
            alg_id = "secp521r1";
        } else {
            key_size = -1;
            alg_id = *oid;
        }
        snprintf(buf, len, EC_PUB_FMT, key_size, alg_id);
        LocalFree(oid);
        return;
    } else if(strcmp(keyInfo->Algorithm.pszObjId, szOID_RSA_RSA) == 0) {
        unsigned long bits = keyInfo->PublicKey.cbData * 8 - keyInfo->PublicKey.cUnusedBits;
        static char RSA_PUB_FMT[] = "Public Key Algorithm: rsaEncryption\n"
                                    "Public-Key: (%ld bit)\n";
        snprintf(buf, len, RSA_PUB_FMT, bits);
    } else {
        snprintf(buf, len, "<unsupported>\n");
    }
}

const char * get_text(const struct tlsuv_certificate_s * cert) {
    win32_cert_t *c = (win32_cert_t *) cert;
    
    if (c->text) return c->text;

    PCCERT_CONTEXT cert_ctx = c->cert;
    if (!cert_ctx) {
        UM_LOG(ERR, "No certificates found in store");
        return NULL;
    }
    

    // produce output similar OpenSSL/X509_print_ex, skipping more technical bits
    static char CERT_TEXT_FMT[] = "Version: %lu (0x%lx)\n"
                                  "Serial Number: %ld (0x%lX)\n"
                                  "Issuer: %s\n"
                                  "Validity\n"
                                  "Not Before: %s\n"
                                  "Not After : %s\n"
                                  "Subject: %s\n"
                                  "Subject Public Key Info:\n"
                                  "%s"
                                  "X509v3 extensions:\n"
                                  "X509v3 Authority Key Identifier:\n"
                                  "%s";

    unsigned long serial = 0;
    for (int i = 0; i < cert_ctx->pCertInfo->SerialNumber.cbData; i++) {
        serial += cert_ctx->pCertInfo->SerialNumber.pbData[i] << (8 * i);
    }

    char issuer[256] = {};
    char subject[256] = {};
    CertNameToStrA(X509_ASN_ENCODING, &cert_ctx->pCertInfo->Issuer, CERT_X500_NAME_STR, issuer, sizeof(issuer));
    CertNameToStrA(X509_ASN_ENCODING, &cert_ctx->pCertInfo->Subject, CERT_X500_NAME_STR, subject, sizeof(subject));

    struct tm aft;
    SYSTEMTIME before = {}, after = {};
    FileTimeToSystemTime(&cert_ctx->pCertInfo->NotBefore, &before);
    FileTimeToSystemTime(&cert_ctx->pCertInfo->NotAfter, &after);
    char not_before[64];
    char not_after[64];
    fmt_time(&cert_ctx->pCertInfo->NotBefore, not_before, sizeof(not_before));
    fmt_time(&cert_ctx->pCertInfo->NotAfter, not_after, sizeof(not_after));

    char key_info[256];
    fmt_pub_key_info(&cert_ctx->pCertInfo->SubjectPublicKeyInfo, key_info, sizeof(key_info));

    char key_id[128] = "<unknown>";
    for (int i = 0; i < cert_ctx->pCertInfo->cExtension; i++) {
        PCERT_EXTENSION ext = &cert_ctx->pCertInfo->rgExtension[i];
        if (strcmp(ext->pszObjId, szOID_AUTHORITY_KEY_IDENTIFIER2) == 0) {
            CERT_AUTHORITY_KEY_ID2_INFO *kid_info = NULL;
            DWORD kid_info_len = 0;
            if (CryptDecodeObject(X509_ASN_ENCODING, szOID_AUTHORITY_KEY_IDENTIFIER2, ext->Value.pbData, ext->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, &kid_info, &kid_info_len)) {
                BYTE *b = kid_info->KeyId.pbData;
                char *p = key_id;
                while (b - kid_info->KeyId.pbData < kid_info->KeyId.cbData) {
                    p += snprintf(p, 4, "%02X:", *b++);
                }
                *(p - 1) = (char)0;
                LocalFree(kid_info);
            }
        }
    }
    
    ssize_t len = snprintf(NULL, 0, CERT_TEXT_FMT,
                          cert_ctx->pCertInfo->dwVersion, cert_ctx->pCertInfo->dwVersion,
                          serial, serial,
                          issuer, // issuer
                          not_before,
                          not_after,
                          subject,
                          key_info,
                          key_id);

    c->text = tlsuv__malloc(len + 1);
    snprintf(c->text, len + 1, CERT_TEXT_FMT,
             cert_ctx->pCertInfo->dwVersion + 1, cert_ctx->pCertInfo->dwVersion,
             serial, serial,
             issuer, // issuer
             not_before,
             not_after,
             subject,
             key_info,
             key_id
    );
    return c->text;
}

static struct tlsuv_certificate_s cert_api = {
    .free = free_cert,
    .to_pem = cert_to_pem,
    .get_expiration = get_expiration,
    .get_text = get_text,
    .verify = cert_verify,
};

win32_cert_t *win32_new_cert(PCCERT_CONTEXT crt, HCERTSTORE store) {
    win32_cert_t *cert = tlsuv__calloc(1, sizeof(*cert));
    cert->api = cert_api;
    cert->store = store;
    cert->cert = crt;
    return cert;
}

