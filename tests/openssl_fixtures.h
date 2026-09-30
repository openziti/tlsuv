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

// Helpers for tests that need to look inside what the OpenSSL-family backends
// produce (CSRs), or mint certificates for keys that live in a keychain.
// Works with both OpenSSL and BoringSSL headers.

#ifndef TLSUV_TESTS_OPENSSL_FIXTURES_H
#define TLSUV_TESTS_OPENSSL_FIXTURES_H

#if defined(TEST_openssl) || defined(TEST_boringssl)
#define TEST_HAVE_OPENSSL_API 1

// the helpers use the legacy EC/RSA APIs (OpenSSL 3 deprecates them, BoringSSL does not)
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <string>

// Parses `csr_pem`, checks its self-signature against its own public key and
// returns the subject as a one-line string ("CN=foo"); empty string on failure.
inline std::string verify_csr(const std::string &csr_pem) {
    BIO *bio = BIO_new_mem_buf(csr_pem.data(), (int)csr_pem.size());
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (req == nullptr) return {};

    std::string subject;
    EVP_PKEY *pub = X509_REQ_get_pubkey(req);
    if (pub != nullptr && X509_REQ_verify(req, pub) == 1) {
        char *s = X509_NAME_oneline(X509_REQ_get_subject_name(req), nullptr, 0);
        if (s) {
            subject = s;
            OPENSSL_free(s);
        }
    }
    EVP_PKEY_free(pub);
    X509_REQ_free(req);
    return subject;
}

// Issues a certificate for the public key in `csr_pem`, signed by a throwaway
// EC key (so it chains to nothing). Enough for a server that requests, but does
// not verify, a client certificate. Returns PEM; empty string on failure.
inline std::string cert_from_csr(const std::string &csr_pem) {
    std::string result;
    BIO *bio = BIO_new_mem_buf(csr_pem.data(), (int)csr_pem.size());
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (req == nullptr) return result;

    EVP_PKEY *pub = X509_REQ_get_pubkey(req);
    X509 *x = X509_new();
    EVP_PKEY *issuer_key = EVP_PKEY_new();
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    X509_NAME *issuer = X509_NAME_new();

    if (pub && x && issuer_key && ec && issuer &&
        EC_KEY_generate_key(ec) == 1 &&
        EVP_PKEY_assign_EC_KEY(issuer_key, ec) == 1) {
        ec = nullptr; // owned by issuer_key now
        X509_NAME_add_entry_by_txt(issuer, "CN", MBSTRING_ASC, (const unsigned char *)"keychain-test-issuer", -1, -1, 0);
        X509_set_version(x, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
        X509_gmtime_adj(X509_getm_notBefore(x), -60);
        X509_gmtime_adj(X509_getm_notAfter(x), 3600);
        X509_set_subject_name(x, X509_REQ_get_subject_name(req));
        X509_set_issuer_name(x, issuer);
        X509_set_pubkey(x, pub);
        if (X509_sign(x, issuer_key, EVP_sha256()) > 0) {
            BIO *out = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(out, x);
            char *data = nullptr;
            long len = BIO_get_mem_data(out, &data);
            result.assign(data, len);
            BIO_free(out);
        }
    }

    X509_NAME_free(issuer);
    EC_KEY_free(ec);
    EVP_PKEY_free(issuer_key);
    X509_free(x);
    EVP_PKEY_free(pub);
    X509_REQ_free(req);
    return result;
}

#endif // TEST_openssl || TEST_boringssl
#endif // TLSUV_TESTS_OPENSSL_FIXTURES_H
