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

#include "../alloc.h"
#include "../um_debug.h"
#include "cert.h"
#include "engine.h"
#include "keys.h"
#include <security.h>
#include <wincrypt.h>

#include <stdbool.h>

struct win32tls {
    tls_context api;
    int (*cert_verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx);
    void *verify_ctx;
    unsigned char *alpn_protocols;

    HCERTSTORE ca_bundle;
    const CERT_CONTEXT *own_cert;
    HCERTSTORE own_store;
};

static tls_context win32tls_context_api;

int configure_win32crypto() {
    return 0;
}

const char* win32_error(DWORD code) {
    static char msg[1024];

  FormatMessageA(
      FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                   NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   (LPSTR)msg, sizeof(msg), NULL);
    return msg;
}

tls_context * new_win32crypto_ctx(const char* ca, size_t ca_len) {
    struct win32tls *ctx = tlsuv__calloc(1, sizeof(*ctx));
    ctx->api = win32tls_context_api;
    if (ca && ca_len > 0) {
        ctx->api.set_ca_bundle((tls_context *) ctx, ca, ca_len);
    }
    return (tls_context*)ctx;
}

static void tls_free_ctx (tls_context *ctx) {
    struct win32tls *c = (struct win32tls*)ctx;
    if (c->alpn_protocols) {
        tlsuv__free(c->alpn_protocols);
    }

    tlsuv__free(c);
}

static const char* tls_lib_version() {
    static char version[256];
    if (*version == 0) {
        snprintf(version, sizeof(version), "win32 schannel: TODO");
    }
    return version;
}

static int parse_pkcs7_certs(tlsuv_certificate_t *ctx, const char *data, size_t len) {
    if (data == NULL || len == 0) {
        UM_LOG(ERR, "no data to parse");
        return -1;
    }

    BYTE *bin = NULL;
    DWORD bin_len = 0;
    if (!CryptStringToBinaryA(data, len, CRYPT_STRING_BASE64, bin, &bin_len, NULL, NULL)) {
        LOG_LAST_ERROR(ERR, "failed to get binary length");
        return -1;
    }

    bin = tlsuv__malloc(bin_len);
    if (!CryptStringToBinaryA(data, len, CRYPT_STRING_BASE64, bin, &bin_len, NULL, NULL)) {
        tlsuv__free(bin);
        return -1;
    }

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_PKCS7, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                                     (HCRYPTPROV_LEGACY) NULL, 0,
                                     &(CRYPT_DATA_BLOB) {
                                             .cbData = bin_len,
                                             .pbData = bin
                                     }
    );
    tlsuv__free(bin);
    if (!store) {
        DWORD err = GetLastError();
        UM_LOG(ERR, "failed to parse PKCS7 cert store: %s", win32_error(err));
        return -1;
    }

    *ctx = (tlsuv_certificate_t) win32_new_cert(NULL, store);
    return 0;
}

static int load_cert_internal(HCERTSTORE *storep, PCCERT_CONTEXT *crt, const char *buf, size_t buf_len) {
    if (buf == NULL || buf_len == 0) {
        UM_LOG(ERR, "no data to load certificate");
        return -1;
    }

    const char *pem = buf;
    WIN32_FIND_DATA file_data;
    HANDLE pem_file = FindFirstFileA(buf, &file_data);
    FindClose(pem_file);
    if (pem_file != INVALID_HANDLE_VALUE) {
        if (file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            UM_LOG(ERR, "file[%s] is a directory", buf);
            return -1;
        }

        pem = (const char*)tlsuv__malloc(file_data.nFileSizeLow);
        buf_len = file_data.nFileSizeLow;

        pem_file = CreateFileA(buf, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (!ReadFile(pem_file, (LPVOID)pem, file_data.nFileSizeLow, NULL, NULL)) {
            LOG_LAST_ERROR(ERR, "failed to read file[%s]", buf);
            tlsuv__free((void*)pem);
            return -1;
        }
        CloseHandle(pem_file);
    }

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY,
                                     PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                                     (HCRYPTPROV_LEGACY) NULL, 0, NULL);
    if (!store) {
        LOG_LAST_ERROR(ERR, "failed to open memory store");
        if (pem != buf) {
            tlsuv__free((void*)pem);
        }
        return -1;
    }

    const char *p = pem;
    DWORD cert_len = 0;
    bool first = true;
    while(CryptStringToBinaryA(p, buf_len - (p - pem), CRYPT_STRING_BASE64HEADER, NULL, &cert_len, NULL, NULL)) {
        BYTE *cert_bin = tlsuv__malloc(cert_len);
        CryptStringToBinaryA(p, buf_len - (p - pem), CRYPT_STRING_BASE64HEADER, cert_bin, &cert_len, NULL, NULL);
        p += cert_len;
        PCCERT_CONTEXT cert_ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert_bin, cert_len);
        if (cert_ctx == NULL || !CertAddCertificateContextToStore(store, cert_ctx, CERT_STORE_ADD_ALWAYS, NULL)) {
            LOG_LAST_ERROR(WARN, "failed to create certificate context");
            CertFreeCertificateContext(cert_ctx);
            cert_ctx = NULL;
        }

        if (first && crt != NULL) {
          *crt = cert_ctx;
        }
        first = false;
        tlsuv__free(cert_bin);
    }
    *storep = store;

    if (pem != buf) {
        tlsuv__free((void*)pem);
    }

    return 0;
}

static int load_cert(tlsuv_certificate_t *cert, const char *buf, size_t buf_len) {
    HCERTSTORE store;
    PCCERT_CONTEXT crt;
    if (load_cert_internal(&store, &crt, buf, buf_len) || store == INVALID_HANDLE_VALUE) {
        *cert = NULL;
        return -1;
    }
    *cert = (tlsuv_certificate_t) win32_new_cert(crt, store);
    return 0;
}

static int tls_set_cert_verify(
    tls_context *ctx,
    int (*verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx),
    void *v_ctx) {
    struct win32tls *c = (struct win32tls*)ctx;

    c->cert_verify_f = verify_f;
    c->verify_ctx = v_ctx;
    return 0;
}

static int set_ca_bundle(tls_context *ctx, const char *ca, size_t ca_len) {
    struct win32tls *c = (struct win32tls*)ctx;

    HCERTSTORE store;
    if (load_cert_internal(&store, NULL, ca, ca_len) || store == INVALID_HANDLE_VALUE) {
        return -1;
    }

    c->ca_bundle = store;
    return 0;
}

static int set_own_cert(tls_context *ctx, tlsuv_private_key_t key, tlsuv_certificate_t cert) {
    struct win32tls *c = (struct win32tls*)ctx;
    win32_cert_t *crt = (win32_cert_t*)cert;
    struct win32crypto_private_key_s *pk = (struct win32crypto_private_key_s*)key;

    if (c->own_cert) {
        CertFreeCertificateContext(c->own_cert);
        CertCloseStore(c->own_store, 0);
    }

    if (crt == NULL || pk == NULL) {
        return 0;
    }
    DWORD len;
    wchar_t prov_name[128] = {};
    NCryptGetProperty(pk->provider, NCRYPT_NAME_PROPERTY, (PVOID)prov_name, sizeof(prov_name), &len, 0);

    CryptExportPublicKeyInfo(pk->key, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, &len);
    CERT_PUBLIC_KEY_INFO *pub_info = tlsuv__malloc(len);
    CryptExportPublicKeyInfo(pk->key, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pub_info, &len);

    PCCERT_CONTEXT pcc = CertFindCertificateInStore(crt->store, X509_ASN_ENCODING, 0, CERT_FIND_PUBLIC_KEY, pub_info, NULL);
    tlsuv__free(pub_info);

    if (pcc == NULL) {
        UM_LOG(ERR, "cert/key mismatch");
        return -1;
    }

    wchar_t *key_name = NULL;
    SECURITY_STATUS rc = NCryptGetProperty(pk->key, NCRYPT_NAME_PROPERTY, (PVOID)NULL, 0, &len, 0);
    if (BCRYPT_SUCCESS(rc)) {
        key_name = tlsuv__malloc(len);
        NCryptGetProperty(pk->key, NCRYPT_NAME_PROPERTY, (PVOID)key_name, len, &len, 0);
    } else if (rc == NTE_NOT_SUPPORTED) {
        // this probably means that key is not persisted
        // we need to store it in order to use it for mutual auth
        // step 1: stable key name
        char kid[64] = {};
        DWORD kid_len = sizeof(kid);
        if (!CertGetCertificateContextProperty(pcc, CERT_KEY_IDENTIFIER_PROP_ID, kid, &kid_len)) {
            LOG_LAST_ERROR(ERR, "failed to get key id from the certificate");
            return -1;
        }

        CryptBinaryToStringW(kid, kid_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len);
        key_name = tlsuv__calloc(len + 1, sizeof(*key_name));
        if (!CryptBinaryToStringW(kid, kid_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, key_name, &len)) {
            LOG_LAST_ERROR(ERR,"key name error");
        }

        // step 2: export
        const wchar_t *exp_type = NCRYPT_PKCS8_PRIVATE_KEY_BLOB;
        DWORD key_blob_len = 0;
        rc = NCryptExportKey(pk->key, 0, exp_type, NULL, NULL, 0, &key_blob_len, 0);
        if (rc != 0) {
            LOG_ERROR(ERR, rc, "failed to export the key");
            tlsuv__free(key_name);
            return -1;
        }
        BYTE *key_blob = tlsuv__malloc(key_blob_len);
        NCryptExportKey(pk->key, 0, exp_type, NULL, key_blob, key_blob_len, &key_blob_len, 0);

        // step 3: import the key with the name to make it persistent
        NCRYPT_KEY_HANDLE imported = 0;
        NCryptBuffer name_buf ={
            .BufferType = NCRYPTBUFFER_PKCS_KEY_NAME,
            .pvBuffer = (PVOID)key_name,
            .cbBuffer = (len + 1) * sizeof(wchar_t),
        };
        NCryptBufferDesc name_desc = {
            .pBuffers = &name_buf,
            .cBuffers = 1,
        };
        rc = NCryptImportKey(pk->provider, 0, exp_type,
                             &name_desc,
                             &imported,
                             key_blob, key_blob_len, 0);
        tlsuv__free(key_blob);
        if (rc < 0) {
            LOG_ERROR(ERR, rc, "import key error");
        }

    } else {
        LOG_ERROR(ERR, rc, "unexpected key error");
        return -1;
    }

    c->own_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, (HCRYPTPROV)NULL, 0, NULL);
    CertAddCertificateContextToStore(c->own_store, pcc, CERT_STORE_ADD_ALWAYS, &c->own_cert);

    CRYPT_KEY_PROV_INFO key_info = {
        .pwszContainerName = key_name,
        .pwszProvName = prov_name,
    };
    if (!CertSetCertificateContextProperty(c->own_cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &key_info)) {
        LOG_LAST_ERROR(ERR, "failed to set cert key");
    }
    tlsuv__free(key_name);

    pcc = CertEnumCertificatesInStore(crt->store, NULL);
    while (pcc) {
        CertAddCertificateContextToStore(c->own_store, pcc, CERT_STORE_ADD_USE_EXISTING, NULL);
        pcc = CertEnumCertificatesInStore(crt->store, pcc);
    }

    return 0;
}

#define DN_MAX_ATTRS (8)
static const char* get_obj_id(const char *id) {
    if (strcmp(id, "C") == 0) return szOID_COUNTRY_NAME;
    if (strcmp(id, "ST") == 0) return szOID_STATE_OR_PROVINCE_NAME;
    if (strcmp(id, "L") == 0) return szOID_LOCALITY_NAME;
    if (strcmp(id, "O") == 0) return szOID_ORGANIZATION_NAME;
    if (strcmp(id, "OU") == 0) return szOID_ORGANIZATIONAL_UNIT_NAME;
    if (strcmp(id, "CN") == 0) return szOID_COMMON_NAME;
    if (strcmp(id, "DC") == 0) return szOID_DOMAIN_COMPONENT;
    return NULL;
}
static int win32crypto_generate_csr(tlsuv_private_key_t pk, char **pem, size_t *pemlen, ...) {
    struct win32crypto_private_key_s *key = (struct win32crypto_private_key_s*) pk;
    CERT_RDN_ATTR attrs[8] = {};
    int attr_idx = 0;

    va_list va;
    va_start(va, pemlen);
    while (attr_idx < DN_MAX_ATTRS) {
        char *id = va_arg(va, char*);
        if (id == NULL) { break; }

        const char *val = va_arg(va, char*);
        if (val == NULL) { break; }

        const char *objId = get_obj_id(id);
        if (objId == NULL) continue;
        attrs[attr_idx].pszObjId = (char*)objId;
        attrs[attr_idx].dwValueType = CERT_RDN_PRINTABLE_STRING;
        attrs[attr_idx].Value.pbData = (BYTE*)val;
        attrs[attr_idx].Value.cbData = strlen(val);
        attr_idx++;
    }
    va_end(va);
    CERT_REQUEST_INFO req = {
        .dwVersion = CERT_REQUEST_V1,
    };

    CERT_RDN cert_rdn = { .cRDNAttr = attr_idx, .rgRDNAttr = attrs };
    CERT_NAME_INFO cert_name = { 1, &cert_rdn };

    CryptEncodeObject(X509_ASN_ENCODING, X509_NAME, &cert_name, NULL, &req.Subject.cbData);
    req.Subject.pbData = tlsuv__malloc(req.Subject.cbData);
    CryptEncodeObject(X509_ASN_ENCODING, X509_NAME, &cert_name, req.Subject.pbData, &req.Subject.cbData);

    DWORD len = 0;
    CERT_PUBLIC_KEY_INFO *pub_info = NULL;
    CryptExportPublicKeyInfo(key->key, 0, X509_ASN_ENCODING, NULL, &len);
    pub_info = tlsuv__malloc(len);
    CryptExportPublicKeyInfo(key->key, 0, X509_ASN_ENCODING, pub_info, &len);
    req.SubjectPublicKeyInfo = *pub_info;

    CRYPT_ALGORITHM_IDENTIFIER signer = { szOID_ECDSA_SHA256 };
    BYTE *req_der = NULL;
    if (CryptSignAndEncodeCertificate(key->key, 0, X509_ASN_ENCODING,
        X509_CERT_REQUEST_TO_BE_SIGNED, &req, &signer, NULL, NULL, &len)) {
        req_der = tlsuv__malloc(len);
        CryptSignAndEncodeCertificate(key->key, 0, X509_ASN_ENCODING,
        X509_CERT_REQUEST_TO_BE_SIGNED, &req, &signer, NULL, req_der, &len);
    }

    DWORD pem_len;
    DWORD flags = CRYPT_STRING_BASE64REQUESTHEADER | CRYPT_STRING_NOCR;
    CryptBinaryToStringA(req_der, len, flags, NULL, &pem_len);
    char *p = tlsuv__malloc(pem_len);
    CryptBinaryToStringA(req_der, len, flags, p, &pem_len);

    *pem = p;
    if (pemlen) {
        *pemlen = pem_len;
    }

    tlsuv__free(req_der);
    tlsuv__free(pub_info);
    tlsuv__free(req.Subject.pbData);
    return 0;
}


static tlsuv_engine_t new_win32_engine(tls_context *ctx, const char *hostname) {
    struct win32tls *c = (struct win32tls*)ctx;

    return (tlsuv_engine_t) new_win32engine(
        hostname, c->ca_bundle, c->own_cert, c->cert_verify_f, c->verify_ctx);
}

static tls_context win32tls_context_api = {
        .version = tls_lib_version,
        .strerror = (const char *(*)(long)) win32_error,
        .new_engine = new_win32_engine,
        .free_ctx = tls_free_ctx,
        .set_ca_bundle = set_ca_bundle,
        .set_own_cert = set_own_cert,
//        .allow_partial_chain = tls_set_partial_vfy,
        .set_cert_verify = tls_set_cert_verify,
//        .verify_signature =  tls_verify_signature,
        .parse_pkcs7_certs = parse_pkcs7_certs,
        .generate_key = win32crypto_generate_key,
        .load_key = win32crypto_load_key,
//        .load_pkcs11_key = load_pkcs11_key,
//        .generate_pkcs11_key = gen_pkcs11_key,
        .generate_keychain_key = win32crypto_gen_keychain_key,
        .load_keychain_key = win32crypto_load_keychain_key,
        .remove_keychain_key = win32crypto_remove_keychain_key,
        .load_cert = load_cert,
        .generate_csr_to_pem = win32crypto_generate_csr,
};
