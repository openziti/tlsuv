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

#ifndef TLSUV_FIPS_POLICY_H
#define TLSUV_FIPS_POLICY_H

// Algorithms a context may use after tls_context::require_fips().
// OpenSSL configuration-string syntax; see docs/superpowers/specs/2026-10-01-require-fips-design.md

// TLS 1.3 cipher suites (SSL_CTX_set_ciphersuites)
#define TLSUV_FIPS_TLS13_SUITES "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"

// TLS 1.2 cipher suites (SSL_CTX_set_cipher_list)
#define TLSUV_FIPS_TLS12_CIPHERS                                              \
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"             \
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"

// key agreement groups (SSL_CTX_set1_groups_list)
#define TLSUV_FIPS_GROUPS "P-256:P-384"

// signature algorithms (SSL_CTX_set1_sigalgs_list)
#define TLSUV_FIPS_SIGALGS                                                    \
    "ecdsa_secp384r1_sha384:ecdsa_secp256r1_sha256:"                          \
    "rsa_pss_rsae_sha512:rsa_pss_rsae_sha384:rsa_pss_rsae_sha256:"            \
    "rsa_pkcs1_sha384:rsa_pkcs1_sha256"

#endif // TLSUV_FIPS_POLICY_H
