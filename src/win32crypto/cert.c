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

    PCCERT_CONTEXT cert_ctx = c->cert ? CertDuplicateCertificateContext(c->cert)
                                  : CertEnumCertificatesInStore(c->store, NULL);
    if (!cert_ctx) {
        UM_LOG(ERR, "No certificates found in store");
        rc = -1;
        goto done;
    }
    CERT_PUBLIC_KEY_INFO *pk = &cert_ctx->pCertInfo->SubjectPublicKeyInfo;
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            pk, 0, NULL, &key
            )) {
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
    CHECK(BCryptHashData(hash, (PUCHAR)data, datalen, 0));
    CHECK(BCryptFinishHash(hash, hash_bin, hash_bin_len, 0));

    NTSTATUS verified = BCryptVerifySignature(key, NULL, hash_bin, hash_bin_len, (PUCHAR) sig, siglen, 0);
    if (!BCRYPT_SUCCESS(verified)) {
        UM_LOG(ERR, "Signature verification failed: 0x%X", verified);
        rc = -1;
    }

    done:

    if (hash_algo) BCryptCloseAlgorithmProvider(hash_algo, 0);
    if (hash) BCryptDestroyHash(hash);
    if (cert_ctx) CertFreeCertificateContext(cert_ctx);
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

    CertFreeCertificateContext(cert_ctx);

    return 0;
}

static struct tlsuv_certificate_s cert_api = {
    .free = free_cert,
    .to_pem = cert_to_pem,
    .get_expiration = get_expiration,
    .verify = cert_verify,
};

win32_cert_t *win32_new_cert(PCCERT_CONTEXT crt, HCERTSTORE store) {
    win32_cert_t *cert = tlsuv__calloc(1, sizeof(*cert));
    cert->api = cert_api;
    cert->store = store;
    cert->cert = crt;
    return cert;
}

