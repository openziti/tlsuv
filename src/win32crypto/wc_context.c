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

#include <wincrypt.h>
#include <security.h>
#include "../alloc.h"
#include "../um_debug.h"
#include "cert.h"
#include "engine.h"
#include "keys.h"

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

    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)msg, sizeof(msg), NULL);
    return msg;
}

tls_context * new_win32crypto_ctx(const char* ca, size_t ca_len) {
    struct win32tls *ctx = tlsuv__calloc(1, sizeof(*ctx));
    ctx->api = win32tls_context_api;
    if (ca && ca_len > 0) {
        ctx->api.set_ca_bundle((tls_context *) ctx, ca, ca_len);
    }
    return &ctx->api;
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
        UM_LOG(ERR, "failed to get binary length: %s", win32_error(GetLastError()));
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

    *ctx = (tlsuv_certificate_t) win32_new_cert(store);
    return 0;
}

static int load_cert_internal(HCERTSTORE *storep, const char *buf, size_t buf_len) {
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
            UM_LOG(ERR, "failed to read file[%s]: %s", buf, win32_error(GetLastError()));
            return -1;
        }
        CloseHandle(pem_file);
    }

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY,
                                     PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                                     (HCRYPTPROV_LEGACY) NULL, 0, NULL);
    if (!store) {
        UM_LOG(ERR, "failed to open memory store: %s", win32_error(GetLastError()));
        if (pem != buf) {
            tlsuv__free((void*)pem);
        }
        return -1;
    }

    const char *p = pem;
    DWORD cert_len = 0;
    while(CryptStringToBinaryA(p, buf_len - (p - pem), CRYPT_STRING_BASE64HEADER, NULL, &cert_len, NULL, NULL)) {
        BYTE *cert_bin = tlsuv__malloc(cert_len);
        CryptStringToBinaryA(p, buf_len - (p - pem), CRYPT_STRING_BASE64HEADER, cert_bin, &cert_len, NULL, NULL);
        p += cert_len;
        PCCERT_CONTEXT cert_ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert_bin, cert_len);
        if (cert_ctx == NULL || !CertAddCertificateContextToStore(store, cert_ctx, CERT_STORE_ADD_ALWAYS, NULL)) {
            UM_LOG(WARN, "failed to create certificate context: %s", win32_error(GetLastError()));
            CertFreeCertificateContext(cert_ctx);
        }
    }
    *storep = store;

    if (pem != buf) {
        tlsuv__free((void*)pem);
    }

    return 0;
}

static int load_cert(tlsuv_certificate_t *cert, const char *buf, size_t buf_len) {
    HCERTSTORE store;
    if (load_cert_internal(&store, buf, buf_len) || store == INVALID_HANDLE_VALUE) {
        *cert = NULL;
        return -1;
    }
    *cert = (tlsuv_certificate_t) win32_new_cert(store);
    return 0;
}

static int set_ca_bundle(tls_context *ctx, const char *ca, size_t ca_len) {
    struct win32tls *c = (struct win32tls*)ctx;

    HCERTSTORE store;
    if (load_cert_internal(&store, ca, ca_len) || store == INVALID_HANDLE_VALUE) {
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
    CERT_KEY_CONTEXT key_ctx = {
        .cbSize = sizeof(key_ctx),
        .hCryptProv = pk->provider,
        .dwKeySpec = CERT_NCRYPT_KEY_SPEC,
    };


    c->own_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, (HCRYPTPROV)NULL, 0, NULL);
    PCCERT_CONTEXT pcc = CertEnumCertificatesInStore(crt->store, NULL);
    CertAddCertificateContextToStore(c->own_store, pcc, CERT_STORE_ADD_ALWAYS, &c->own_cert);
    CertSetCertificateContextProperty(c->own_cert, CERT_KEY_PROV_INFO_PROP_ID, 0, (void*)&pk->key);

    pcc = CertEnumCertificatesInStore(crt->store, pcc);
    while (pcc) {
        CertAddCertificateContextToStore(c->own_store, pcc, CERT_STORE_ADD_ALWAYS, NULL);
        pcc = CertEnumCertificatesInStore(crt->store, pcc);
    }

    return 0;
}
static tlsuv_engine_t new_win32_engine(tls_context *ctx, const char *hostname) {
    struct win32tls *c = (struct win32tls*)ctx;

    return (tlsuv_engine_t) new_win32engine(hostname, c->ca_bundle, c->own_cert);
}

static tls_context win32tls_context_api = {
        .version = tls_lib_version,
        .strerror = (const char *(*)(long)) win32_error,
        .new_engine = new_win32_engine,
        .free_ctx = tls_free_ctx,
        .set_ca_bundle = set_ca_bundle,
        .set_own_cert = set_own_cert,
//        .allow_partial_chain = tls_set_partial_vfy,
//        .set_cert_verify = tls_set_cert_verify,
//        .verify_signature =  tls_verify_signature,
        .parse_pkcs7_certs = parse_pkcs7_certs,
        .generate_key = win32crypto_generate_key,
        .load_key = win32crypto_load_key,
//        .load_pkcs11_key = load_pkcs11_key,
//        .generate_pkcs11_key = gen_pkcs11_key,
//        .generate_keychain_key = gen_keychain_key,
//        .load_keychain_key = load_keychain_key,
//        .remove_keychain_key = remove_keychain_key,
        .load_cert = load_cert,
//        .generate_csr_to_pem = generate_csr,
};
