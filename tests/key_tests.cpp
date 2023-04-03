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

#include "catch.hpp"

#include <cstring>
#include <tlsuv/tls_engine.h>

#define xstr(s) str__(s)
#define str__(s) #s




TEST_CASE("key gen", "[key]") {
    tls_context *ctx = default_tls_context(nullptr, 0);

    tlsuv_private_key_t key;
    REQUIRE(ctx->api->generate_key(&key) == 0);

    char *pem;
    size_t pemlen;
    REQUIRE(key->to_pem(key, &pem, &pemlen) == 0);
    printf("priv key:\n%.*s\n", (int)pemlen, pem);

    tlsuv_private_key_t k1;
    char *pem2;
    REQUIRE(ctx->api->load_key(&k1, pem, pemlen) == 0);
    REQUIRE(k1 != nullptr);
    REQUIRE(k1->to_pem(k1, &pem2, &pemlen) == 0);

    REQUIRE_THAT(pem2, Catch::Matchers::Equals(pem));
    free(pem);
    free(pem2);
    key->free(key);
    k1->free(k1);
    ctx->api->free_ctx(ctx);
}

static void check_key(tlsuv_private_key_t key) {
    auto pub = key->pubkey(key);
    REQUIRE(pub != nullptr);

    const char *data = "this is an important message";
    size_t datalen = strlen(data);

    char sig[256];
    memset(sig, 0, sizeof(sig));
    size_t siglen = sizeof(sig);

    CHECK(-1 == pub->verify(pub, hash_SHA256, data, datalen, sig, siglen));
    CHECK(0 == key->sign(key, hash_SHA256, data, datalen, sig, &siglen));
    CHECK(0 == pub->verify(pub, hash_SHA256, data, datalen, sig, siglen));
    sig[0] = (char)(sig[0] ^ 0xff);
    CHECK(-1 == pub->verify(pub, hash_SHA256, data, datalen, sig, siglen));

    pub->free(pub);
}


TEST_CASE("key-tests", "[key]") {
    tls_context *ctx = default_tls_context(nullptr, 0);

    tlsuv_private_key_t key = nullptr;
    WHEN("generated key") {
        REQUIRE(ctx->api->generate_key(&key) == 0);
        check_key(key);
    }

    WHEN("load RSA key") {
        const char *pem = R"(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCcmbdVp2gH+YHC
VIcl+pLwXNTKMZZGZRcmhLu+JtTdc4wwV3xiL57REHGr6rY4Vfo8Yr5eXbzHEmjA
4Cp7qJs5/1CN2Zqg0TZ8ayCoz223M+FghwQmz5cuHke98YLcQSV6DrLiqPlZ2vMx
Z5hXWzDpZAPrgLA3GrivCuPSbkW9Tr7wzUZgy2gZounU+Hm237fXz0SDyyMIsDKs
NHKoIEjhYuCnxhuWhgipteogVu+LOX45LsBK9TslN5AxOQEvGD8zj9PcN0DBfMTR
qL6vWBlkSohhmPPhYOJAegOqgTMHMm83o9DjN3/3sG+RLU6dzMp7s7REJlp2zVbN
kF/XqU6FAgMBAAECggEACGAMNw+B99M3Rl5g7/4Lt8EvPDUUtWUYrN2ycMQA5GsW
l0tGgrXLR6EagzhFUJQAkxQw3DklLHxmj9ItU3m7+4kVFNELfQhTYqoUEBMv6flj
V1dBOJYnnrbN3XG6Lu9pArMgjBC/bTfRg9XnhtyArCrGLuUuB3RtZict8gYlwq8K
/IE7T2c9nLW+WZmZh0/2ouZJw1nFPSeuynasPpKSFHzvlKTBLMnGZWjiKifmNciy
JtU0296BxPcj5fTtoAa5YPkp7qGe5blWRYPqjCAi0TE3edxcVaAYtaLwhXXzmpQt
yDcHcY9lpfSkkGM4Hz27YUegIcpjPGHrD1lBJieYwQKBgQDXDTzBvbFtyReiDLW3
v5+oRtgriqDqed/sZR/sdaFb5tiUffENFXA3kFyIVzP/Aem3yRtprHgX9viIDzIE
bOSAOgYZv1Ie++Dyk2GnCUIbpV03Y8lMxX9/RUFpLefgyvq2T6OXyjeWe9OgnnIf
MGg1acmfmAXdlatBhoaa8E/gcQKBgQC6a0EQ0x7eyF/Rb020PbJL+qhQSjLelHF5
d4s7rhcp0MLTBfIjpVDkOLw78ujrl8e1hvvE+YqHpau5GSEXtpBBlvgrC54ZkQD6
3Qy64wXtScVQxETK02UM9iJQsEaQWi3opQnQ5tV2IVi3gCZLqNte3+Hxgq0VxA10
NURPSCTZVQKBgQCAbTVVdlVZfPgSHIkA/Pz536UFC7rhjHr/j7yq1+zPF2NL+pJT
//OOGzZHbdxtc9UBnqYyS39EwIbXqktyfR1QvlYaVjlSq5VBCGcO++Zw4CZ1B7CV
mnRzqwZPK80IX++tpI3L/kWIJtbRWw5INf5lt5FjL8SA+frWHOKR8OWi4QKBgDrA
uOYDk/Qk9MX+LWBEHaCCpG+Boxyxbj4ZJiGuEZDVQcHeWt1PKfpzwyelvDEcSg31
N/5xo25zEXcp61sc58Q0P4zZgX+PSt7FslBoYqLRoEV/RisiivOV02TY2bR/J37u
HPTg+5/ajKpw0iEAW/s/1mcWh1SX0KGydBAErdBtAoGBAIdjLkZBr4vybsUh8lof
8SsycNXmqcoQEgRcQNp8HYJlv46K6bvtiNNtuo0/ZTYkDSFZi6Wn/ridpIWO8Zpj
/kqmvc7l6e9XlPvhj2/VAM+mGAf3vf7VGZD6sOCbnNtIRCP1PGv64IhdpHJBTp7n
iemZJfIkLzyuwra/o7WkK+hK
-----END PRIVATE KEY-----
)";
        REQUIRE(0 == ctx->api->load_key(&key, pem, strlen(pem)));
        check_key(key);
    }

    WHEN("load EC key") {
        const char *pem = R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDkQFm34yO6vjVPw71v+O8l4r7TelfL8jLnakR8IbARvoAoGCCqGSM49
AwEHoUQDQgAEozzayHZuK1VKSJdnSlQtMWF0iLIkqGxbxWCL6/QlGAATbNSkcW8b
lAkOwU8XOpspVUfYbwPSVSoS2NXn1rE7iA==
-----END EC PRIVATE KEY-----
)";
        REQUIRE(0 == ctx->api->load_key(&key, pem, strlen(pem)));
        check_key(key);
    }
    key->free(key);
    ctx->api->free_ctx(ctx);
}


TEST_CASE("gen csr", "[engine]") {
    tls_context *ctx = default_tls_context(nullptr, 0);

    tlsuv_private_key_t key;
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

    key->free(key);
    ctx->api->free_ctx(ctx);
    free(pem);
}

#if defined(HSM_CONFIG)
#define HSM_DRIVER xstr(HSM_LIB)

TEST_CASE("pkcs11 valid pkcs#11 key", "[key]") {
    tls_context *ctx = default_tls_context(nullptr, 0);
    REQUIRE(ctx->api->load_pkcs11_key != nullptr);

    std::string keyType = GENERATE("ec", "rsa");
    std::string keyLabel = "test-" + keyType;
    tlsuv_private_key_t key = nullptr;

    int rc = 0;
    rc = ctx->api->load_pkcs11_key(&key, HSM_DRIVER, nullptr, "2222", nullptr, keyLabel.c_str());
    CHECK(rc == 0);
    CHECK(key != nullptr);

    WHEN(keyType <<": private key PEM") {
        char *pem;
        size_t pemlen;
        rc = key->to_pem(key, &pem, &pemlen);
        THEN("should fail") {
            CHECK(rc == -1);
            CHECK(pem == nullptr);
            CHECK(pemlen == 0);
        }
    }

    WHEN(keyType << ": public key PEM") {
        char *pem = nullptr;
        size_t pemlen;
        auto pub = key->pubkey(key);
        REQUIRE(pub != nullptr);
        THEN("should work") {
            CHECK(pub->to_pem(pub, &pem, &pemlen) == 0);
            CHECK(pem != nullptr);
            CHECK(pemlen > 0);
            Catch::cout() << std::string(pem, pemlen);
        }
        pub->free(pub);
        free(pem);
    }

    WHEN(keyType << ": get key cert") {
        tls_cert cert;
        char *pem = nullptr;
        size_t pemlen;
        CHECK(key->get_certificate(key, &cert) == 0);

        THEN("should be able to write cert to PEM") {
            CHECK(ctx->api->write_cert_to_pem(cert, 1, &pem, &pemlen) == 0);
            CHECK(pemlen > 0);
            CHECK(pem != nullptr);
            Catch::cout() << std::string(pem, pemlen) << std::endl;
            free(pem);
        }
        AND_THEN("should be able to store cert back to key") {
            CHECK(key->store_certificate(key, cert) == 0);
        }
        AND_THEN("verify using cert") {
            char sig[512];
            const char *data = "I want to sign and verify this";
            size_t datalen = strlen(data);

            memset(sig, 0, sizeof(sig));
            size_t siglen = sizeof(sig);

            CHECK(0 == key->sign(key, hash_SHA256, data, datalen, sig, &siglen));
            CHECK(0 == ctx->api->verify_signature(cert, hash_SHA256, data, datalen, sig, siglen));
        }
        ctx->api->free_cert(&cert);
    }

    WHEN(keyType << ": sign and verify") {
        auto pub = key->pubkey(key);
        REQUIRE(pub != nullptr);
        THEN("should work") {

            const char *data = "this is an important message";
            size_t datalen = strlen(data);

            char sig[512];
            memset(sig, 0, sizeof(sig));
            size_t siglen = sizeof(sig);

            CHECK(-1 == pub->verify(pub, hash_SHA256, data, datalen, sig, siglen));
            CHECK(0 == key->sign(key, hash_SHA256, data, datalen, sig, &siglen));
            CHECK(0 == pub->verify(pub, hash_SHA256, data, datalen, sig, siglen));
        }
        pub->free(pub);
    }

    if (key) {
        key->free(key);
    }
    ctx->api->free_ctx(ctx);
}

#endif
