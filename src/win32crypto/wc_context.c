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

struct win32tls {
    tls_context api;
    int (*cert_verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx);
    void *verify_ctx;
    unsigned char *alpn_protocols;
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

static int load_cert(tlsuv_certificate_t *cert, const char *buf, size_t buflen) {
    if (buf == NULL || buflen == 0) {
        UM_LOG(ERR, "no data to load certificate");
        return -1;
    }

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY,
                                     PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                                     (HCRYPTPROV_LEGACY) NULL, 0, NULL);
    if (!store) {
        UM_LOG(ERR, "failed to open memory store: %s", win32_error(GetLastError()));
        return -1;
    }

    const char *p = buf;
    DWORD cert_len = 0;
    while(CryptStringToBinaryA(p, buflen - (p - buf), CRYPT_STRING_BASE64HEADER, NULL, &cert_len, NULL, NULL)) {
        BYTE *cert_bin = tlsuv__malloc(cert_len);
        CryptStringToBinaryA(p, buflen - (p - buf), CRYPT_STRING_BASE64HEADER, cert_bin, &cert_len, NULL, NULL);
        p += cert_len;
        PCCERT_CONTEXT cert_ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert_bin, cert_len);
        if (cert_ctx == NULL || !CertAddCertificateContextToStore(store, cert_ctx, CERT_STORE_ADD_ALWAYS, NULL)) {
            UM_LOG(WARN, "failed to create certificate context: %s", win32_error(GetLastError()));
            CertFreeCertificateContext(cert_ctx);
        }
    }

    *cert = (tlsuv_certificate_t) win32_new_cert(store);
    return 0;
}

static tls_context win32tls_context_api = {
        .version = tls_lib_version,
//        .strerror = (const char *(*)(long)) tls_error,
//        .new_engine = new_openssl_engine,
        .free_ctx = tls_free_ctx,
//        .set_ca_bundle = set_ca_bundle,
//        .set_own_cert = tls_set_own_cert,
//        .allow_partial_chain = tls_set_partial_vfy,
//        .set_cert_verify = tls_set_cert_verify,
//        .verify_signature =  tls_verify_signature,
        .parse_pkcs7_certs = parse_pkcs7_certs,
//        .write_cert_to_pem = write_cert_pem,
//        .generate_key = gen_key,
//        .load_key = load_key,
//        .load_pkcs11_key = load_pkcs11_key,
//        .generate_pkcs11_key = gen_pkcs11_key,
//        .generate_keychain_key = gen_keychain_key,
//        .load_keychain_key = load_keychain_key,
//        .remove_keychain_key = remove_keychain_key,
        .load_cert = load_cert,
//        .generate_csr_to_pem = generate_csr,
};
