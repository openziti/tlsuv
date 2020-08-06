/*
Copyright 2019 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <uv_mbed/tls_engine.h>
#include <cstring>
#include "catch.hpp"

TEST_CASE("key gen", "[engine]") {
    tls_context *ctx = default_tls_context(nullptr, 0);

    tls_private_key key;
    REQUIRE(ctx->api->generate_key(&key) == 0);

    char *pem;
    size_t pemlen;
    REQUIRE(ctx->api->write_key_to_pem(key, &pem, &pemlen) == 0);
    printf("priv key:\n%.*s\n", (int)pemlen, pem);

    tls_private_key k1;
    char *pem2;
    REQUIRE(ctx->api->load_key(&k1, pem, pemlen) == 0);
    REQUIRE(ctx->api->write_key_to_pem(key, &pem2, &pemlen) == 0);

    REQUIRE_THAT(pem2, Catch::Matchers::Equals(pem));

    ctx->api->free_ctx(ctx);
}

TEST_CASE("gen csr", "[engine]") {
    tls_context *ctx = default_tls_context(nullptr, 0);

    tls_private_key key;
    REQUIRE(ctx->api->generate_key(&key) == 0);

    char *pem;
    size_t pemlen;
    REQUIRE(ctx->api->generate_csr_to_pem(key, &pem, &pemlen,
                                          "C", "US",
                                          "O", "OpenZiti",
                                          "OU", "Developers",
                                          "CN", "CSR test",
                                          NULL) == 0);
    printf("CSR:\n%.*s\n", (int)pemlen, pem);

    ctx->api->free_key(&key);
    ctx->api->free_ctx(ctx);
    free(pem);
}

TEST_CASE("parse pkcs7", "[engine]") {
    const char *pkcs7 = R"(MIIL8QYJKoZIhvcNAQcCoIIL4jCCC94CAQExADALBgkqhkiG9w0BBwGgggvEMIIF
3zCCA8egAwIBAgIQBgjdXUgQ+nYu9WqjujdxCDANBgkqhkiG9w0BAQsFADB5MQsw
CQYDVQQGEwJVUzESMBAGA1UEBxMJQ2hhcmxvdHRlMRMwEQYDVQQKEwpOZXRmb3Vu
ZHJ5MRAwDgYDVQQLEwdBRFYtREVWMS8wLQYDVQQDEyZOZXRmb3VuZHJ5LCBJbmMu
IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xOTA5MDMxODMzNThaFw0yMDA5MDIx
ODM0NThaMHkxCzAJBgNVBAYTAlVTMRIwEAYDVQQHEwlDaGFybG90dGUxEzARBgNV
BAoTCk5ldGZvdW5kcnkxEDAOBgNVBAsTB0FEVi1ERVYxLzAtBgNVBAMTJk5ldGZv
dW5kcnksIEluYy4gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAsve8aW8cqZivN5kUtppI0kmNpImpS3Ypc/l48PTd
jH46Eetbdzl98NjdYXf/InYK0f7JO8/oKm+BhOssbkhr6TPdzywfl6RuQqpcX8p1
7Zs1gTuE4qc7+8VLCAPMGrO7qb6N03fh/baLUhMurGeu2Xho2OhdyiJVcQhEOB0K
oywKR7B/GqKc4GnKbHuvVog56b717ltkg7NQjmAiwmOPAng8+QcmJxeJsK5+7zNv
kppxSIzEE/Nk0n55VIc0CoQdx323eXQbyOH9Oo8SdVPiiurvs40pEmgUGo/pd/5y
ZU+ki67Y27CNuO32YdXro6zsIC3ueblyc7uIKc3OrnkEoMUJNsPN5ZLfMdW053kI
hiibJrFCG0NEze8yYakHBsZ3DfrmN+fzq5IHBI4K277/hOknJvHIHaXqt4oPJVps
IFtt8j8BlZUW29KZKLlzlQ1uGmD1Eixwk63bqaExHQ9aSXMQEbfHre79zUdPDoNM
5Ruj/OvwSxHB49R/oMkN0mDBuPU+tmM8AYkGsQrU+lT8PcWp45Cp04gvbIhuAWCP
bhbWDBmSoV68DO5lFe/PPveNmfrcqBudm9VllE/3hPGUMSDzs0rQMhgiHr9cj6pO
BroJAWInYRoKnSoKUpy6yY2od+5FQpI8Ykck7rQOl8/2bSVloSVgzJjCRgAGXqvp
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
)";

    tls_context *ctx = default_tls_context(nullptr, 0);
    tls_cert chain;
    REQUIRE(ctx->api->parse_pkcs7_certs(&chain, pkcs7, strlen(pkcs7)) == 0);

    char *pem;
    size_t pemlen;
    REQUIRE(ctx->api->write_cert_to_pem(chain, 1, &pem, &pemlen) == 0);

    printf("\n%.*s\n", (int)pemlen, pem);

    free(pem);
    ctx->api->free_cert(&chain);
    ctx->api->free_ctx(ctx);
}