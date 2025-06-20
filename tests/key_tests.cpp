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

#include <catch2/catch_all.hpp>
#include "p11.h"
#include "util.h"

#include <cstring>
#include <iostream>
#include <tlsuv/tls_engine.h>

#define xstr(s) str__(s)
#define str__(s) #s


TEST_CASE("key gen", "[key]") {
    tls_context *ctx = default_tls_context(nullptr, 0);

    tlsuv_private_key_t key;
    REQUIRE(ctx->generate_key(&key) == 0);

    char *pem;
    size_t pemlen;
    REQUIRE(key->to_pem(key, &pem, &pemlen) == 0);
    printf("priv key:\n%.*s\n", (int) pemlen, pem);

    tlsuv_private_key_t k1;
    char *pem2;
    REQUIRE(ctx->load_key(&k1, pem, pemlen) == 0);
    REQUIRE(k1 != nullptr);
    REQUIRE(k1->to_pem(k1, &pem2, &pemlen) == 0);

    REQUIRE_THAT(pem2, Catch::Matchers::Equals(pem));
    free(pem);
    free(pem2);
    key->free(key);
    k1->free(k1);
    ctx->free_ctx(ctx);
}

static void check_key(tlsuv_private_key_t key) {
    auto pub = key->pubkey(key);
    REQUIRE(pub != nullptr);

    char *pem = nullptr;
    size_t pemlen;
    CHECK(key->to_pem(key, &pem, &pemlen) == 0);
    CHECK(pem != nullptr);
    CHECK(pemlen > 0);
    free(pem);

    pem = nullptr;
    CHECK(pub->to_pem(pub, &pem, &pemlen) == 0);
    CHECK(pem != nullptr);
    CHECK(pemlen > 0);
    free(pem);

    const char *data = "this is an important message";
    size_t datalen = strlen(data);

    char sig[256] = {};
    size_t siglen = sizeof(sig);

    CHECK(-1 == pub->verify(pub, hash_SHA256, data, datalen, sig, siglen));
    CHECK(0 == key->sign(key, hash_SHA256, data, datalen, sig, &siglen));
    CHECK(0 == pub->verify(pub, hash_SHA256, data, datalen, sig, siglen));
    sig[0] = (char) (sig[0] ^ 0xff);
    CHECK(-1 == pub->verify(pub, hash_SHA256, data, datalen, sig, siglen));

    pub->free(pub);
}


TEST_CASE("key-tests", "[key]") {
    tls_context *ctx = default_tls_context(nullptr, 0);

    tlsuv_private_key_t key = nullptr;
    WHEN("generated key") {
        REQUIRE(ctx->generate_key(&key) == 0);
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
        REQUIRE(0 == ctx->load_key(&key, pem, strlen(pem)));
        check_key(key);
    }

    WHEN("RSA traditional")
    {
        const char *rsa = R"(-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAr8ChivhwrUoqHK6ggyjug2RBKsIBu7y66spGNq5i6w0TeiC5
YP5THsWRdq+ji2Ypsamn8BjYwUnfY9Ni6ippVEQC8E6AzKp0ctY6vJS5xgGvLnXp
yf8badNBWtLg+QKWXvAWOF0JnzwKYWOec3moklEmz+TfYoCk9KBrrbTs13104VMM
zGGHr+TxOmTt+gRPV2wJ/fzD71ZSjaOeUfom8uMjvBnj36ZA2IP+4B4z6HR3gHGS
xmPwur0ooPH8t7bHaM1hjrsYGD8zwfRmFdXMscbNLMQvrixBAr2aGGxsc8/pnFbX
wTvALivogGP+8SsDL9QsCIkafRMO1f3/9nGhzQIDAQABAoIBAAflgAYwlbSkTFv7
DAFKNymZbGS8w3US38dGUAOYPLk7+ATPKeN95P0RALFKmjuPmy523xgf/N2PkXul
YJoBG1GBRJK7xQVmrP8IeV2fntdfnBmA8nOt5Fmrt5GnP85R8f2K5hJH7dnlCcAo
u9Kk4/CYOFLAmtMABC+6JUEwZWOXvDOky2YJeeNwFeHdFaBGt3gc0t3FUmiB8ltS
sSu8wQcKk2FeEFFNir7NdCAOpg0mWyUOCT2yriSozbtGAuoSltfx8u4qgvLAcmzc
dbwQjtAIDIvd3XLF8F2mwHc2zUAWATETPyPOyuPUl8Ep932n6ijv+nFeA5zKftgA
ErZt14kCgYEA3KXDhVFzLD1N+1ZfjrbaOp9inSoDhfISxerpk/yqk+29NWmlpNy8
vEsxjSyT48ikKS+kOQ7457XmBMORrzbrLOMF2fV5qbIP0YL7JTz/I0uuQ/Zmlnyz
73wwNAPZXgQVRTlRB2GI1qkTb0Xt1Z2Hvx+Bi7fQJSni2cBmm42J2RkCgYEAy+lr
eK4jAqicv71yzyCi/Tq8GRDeGwYSC1hU/7g5mDGGzESnH/jlVO5Uga4VLFpS6Hfv
hc9DlAHDUqY4zW/nC35/somC7A+9pE1xGdFA7khTlD1H3ctj4lRvH+nxFvmckA/a
MLvToMVH3+vwicSAzkOLbi1gVmXOTiQR32DAANUCgYEA17VejklwdUGBqUNprBXr
BwCm4csfIqXj4IWl0L1k7bWwEjW0cJY0FUjVqpR4CGowwusGe5m9kJltxB6FoGvq
Qjm3kLvBMzsW59ZLPL6DF7h3J44OAPTs3CXm4hMZQCZxvPkp1DNwGZu1mkUdHIcj
HJ/qf/M1k/98/TBxn4UhzJECgYEAmvgv3EyDgQ7B6hrBuVa1aDyOHYKrOeB4MDUW
jC3nX5osNuvqE6tmJxDmGpRBtS6EGfaki45EbqSUXCjFvKPR9PNTe010uZEQ8GCG
lzdn4HAJTPzxtEdSBv1iYt+5gVt8uCPEEAt/P40PHcfDTACSX7AHtFk6AQ9oJgzV
pG10Hm0CgYEAraf8UVhqcXRcFydoa3uWVesXWQtFv6SwxHOmdUZzvT4dsIqa/t4b
FzO5cyy4Kkl44BaMVOzq34wmoWmdFRkH+QTmBjZQTrOHOcF1Bg+1kZCoC6k7v+9k
xXZg4bmeG+pKDj27FtV550iez1viN5pqTWYvpyp06zdi2KiaxM7mUVo=
-----END RSA PRIVATE KEY-----)";
        REQUIRE(0 == ctx->load_key(&key, rsa, strlen(rsa)));
        check_key(key);
    }
    WHEN("load EC key") {
        const char *pem = R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMWGag/hK7RXuDol/9YckdFTlJlDDHCxUgBzNYx2QX7BoAoGCCqGSM49
AwEHoUQDQgAEM3anktl6pp67K2hi0h0eLsYSjJ32ySZUxQqPfj0Ww6g3hlYbfPfJ
wUCYxPvYv6zrPXOi81bMLKDK555IaxEjBQ==
-----END EC PRIVATE KEY-----
)";
        REQUIRE(0 == ctx->load_key(&key, pem, strlen(pem)));
        check_key(key);
    }

    WHEN("load EC[PKCS8] key") {
        const char *pem = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxYZqD+ErtFe4OiX/
1hyR0VOUmUMMcLFSAHM1jHZBfsGhRANCAAQzdqeS2XqmnrsraGLSHR4uxhKMnfbJ
JlTFCo9+PRbDqDeGVht898nBQJjE+9i/rOs9c6LzVswsoMrnnkhrESMF
-----END PRIVATE KEY-----
)";
        REQUIRE(0 == ctx->load_key(&key, pem, strlen(pem)));
        check_key(key);
    }
    key->free(key);
    ctx->free_ctx(ctx);
}


TEST_CASE("gen csr", "[engine]") {
    tls_context *ctx = default_tls_context(nullptr, 0);

    tlsuv_private_key_t key;
    REQUIRE(ctx->generate_key(&key) == 0);

    char *pem;
    size_t pemlen = 0;
    CHECK(ctx->generate_csr_to_pem(key, &pem, &pemlen,
                                   "C", "US",
                                   "O", "OpenZiti",
                                   "OU", "Developers",
                                   "CN", "CSR test",
                                   NULL) == 0);
    CHECK(pemlen == strlen(pem));
    printf("CSR:\n%.*s\n", (int) pemlen, pem);
    free(pem);
    pem = nullptr;

    CHECK(ctx->generate_csr_to_pem(key, &pem, nullptr,
                                   "C", "US",
                                   "O", "OpenZiti",
                                   "OU", "Developers",
                                   "CN", "CSR test",
                                   NULL) == 0);
    printf("CSR:\n%s\n", pem);

    key->free(key);
    ctx->free_ctx(ctx);
    free(pem);
}

#if defined(HSM_CONFIG)
#define HSM_DRIVER xstr(HSM_LIB)

TEST_CASE("pkcs11 valid pkcs#11 key", "[key]") {
    tls_context *ctx = default_tls_context(nullptr, 0);
    REQUIRE(ctx->load_pkcs11_key != nullptr);

    std::string keyType = GENERATE("ec", "rsa");
    std::string keyLabel = "test-" + keyType;
    tlsuv_private_key_t key = nullptr;

    int rc = 0;
    rc = ctx->load_pkcs11_key(&key, HSM_DRIVER, nullptr, "2222", nullptr, keyLabel.c_str());
    CHECK(rc == 0);
    REQUIRE(key != nullptr);

    WHEN(keyType << ": private key PEM") {
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
        tlsuv_certificate_t cert;
        char *pem = nullptr;
        size_t pemlen;
        CHECK(key->get_certificate(key, &cert) == 0);

        THEN("should be able to write cert to PEM") {
            CHECK(cert->to_pem(cert, 1, &pem, &pemlen) == 0);
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
            CHECK(0 == cert->verify(cert, hash_SHA256, data, datalen, sig, siglen));
        }
        cert->free(cert);
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
    ctx->free_ctx(ctx);
}

TEST_CASE("gen-pkcs11-key-internals", "[key]") {
    p11_context p11;
    p11_key_ctx key;
    REQUIRE(p11_init(&p11, HSM_DRIVER, nullptr, "2222") == 0);
    REQUIRE(p11_gen_key(&p11, &key, "test-key") == 0);
}

TEST_CASE("gen-pkcs11-key", "[key]") {
    auto tls = default_tls_context(nullptr, 0);
    tlsuv_private_key_t key = nullptr;
    REQUIRE(tls->generate_pkcs11_key(&key, HSM_DRIVER, nullptr, "2222", "gen-key-test") == 0);

    WHEN("public key PEM") {
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
    key->free(key);
    tls->free_ctx(tls);
}
#endif

TEST_CASE("keychain", "[key]") {
    auto tls = default_tls_context(nullptr, 0);
    if (tls->load_keychain_key == nullptr) {
        tls->free_ctx(tls);
        SKIP("keychain not supported");
    }

    uv_timeval64_t now;
    uv_gettimeofday(&now);
    auto name = "testkey-" + std::to_string(now.tv_usec);

    GIVEN("generated private key") {
        fprintf(stderr, "using name: %s\n", name.c_str());
        tlsuv_private_key_t pk{};
        REQUIRE(tls->load_keychain_key(&pk, name.c_str()) != 0);

        REQUIRE(tls->generate_keychain_key(&pk, name.c_str()) == 0);

        char data[1024];
        uv_random(nullptr, nullptr, data, sizeof(data), 0, nullptr);
        size_t datalen = sizeof(data);

        char sig[512] = {};
        size_t siglen = sizeof(sig);

        WHEN("it can sign data") {
            REQUIRE(0 == pk->sign(pk, hash_SHA256, data, datalen, sig, &siglen));

            THEN("verify with its public key") {
                auto pub = pk->pubkey(pk);
                REQUIRE(pub != nullptr);

                char *pem = nullptr;
                size_t pem_len = 0;
                CHECK(pub->to_pem(pub, &pem, &pem_len) == 0);
                CHECK(pem != nullptr);
                if (pem) {
                    CHECK_THAT(pem, Catch::Matchers::StartsWith("-----BEGIN PUBLIC KEY-----"));
                    std::cout << std::string(pem, pem_len) << std::endl;
                    free(pem);
                }
                CHECK(0 == pub->verify(pub, hash_SHA256, data, datalen, sig, siglen));
                pub->free(pub);
            }
        }

        WHEN("it can be loaded by name") {
            tlsuv_private_key_t pk2{};
            int rc2 = tls->load_keychain_key(&pk2, name.c_str());
            THEN("loaded successfully") {
                REQUIRE(rc2 == 0);
                pk2->free(pk2);
            }
        }

        pk->free(pk);
        REQUIRE(0 == tls->remove_keychain_key(name.c_str()));
    }

    tls->free_ctx(tls);
}

TEST_CASE("keychain-manual", "[.]") {
    auto test_name = getenv("TEST_KEYCHAIN_KEY");
    if (!test_name) {
        SKIP("keychain key not specified");
        return;
    }
    auto tls = default_tls_context(nullptr, 0);
    if (tls->load_keychain_key == nullptr) {
        tls->free_ctx(tls);
        SKIP("keychain not supported");
        return;
    }

    uv_timeval64_t now;
    uv_gettimeofday(&now);
    auto name = std::string(test_name);

    GIVEN("existing private key") {
        fprintf(stderr, "using name: %s\n", name.c_str());
        tlsuv_private_key_t pk{};
        REQUIRE(tls->load_keychain_key(&pk, name.c_str()) == 0);

        char data[1024];
        uv_random(nullptr, nullptr, data, sizeof(data), 0, nullptr);
        size_t datalen = sizeof(data);

        char sig[512];
        memset(sig, 0, sizeof(sig));
        size_t siglen = sizeof(sig);

        THEN("it can sign data") {
            REQUIRE(0 == pk->sign(pk, hash_SHA256, data, datalen, sig, &siglen));

            AND_THEN("verify with its public key") {
                auto pub = pk->pubkey(pk);
                REQUIRE(pub != nullptr);

                char *pem = nullptr;
                size_t pem_len = 0;
                CHECK(pub->to_pem(pub, &pem, &pem_len) == 0);
                CHECK(pem != nullptr);
                if (pem) {
                    CHECK_THAT(pem, Catch::Matchers::StartsWith("-----BEGIN PUBLIC KEY-----"));
                    std::cout << std::string(pem, pem_len) << std::endl;
                    free(pem);
                }
                CHECK(0 == pub->verify(pub, hash_SHA256, data, datalen, sig, siglen));
                pub->free(pub);
            }
            pk->free(pk);
        }
    }

    tls->free_ctx(tls);
}

TEST_CASE("wraparound buffer test", "[util]") {
    WRAPAROUND_BUFFER(,16) buf{};
    WAB_INIT(buf);

    char *p;
    size_t len;
    WAB_PUT_SPACE(buf, p, len);
    CHECK(p == buf.putp);
    CHECK(len == sizeof(buf.buf));

    WAB_GET_SPACE(buf, p, len);
    CHECK(p == buf.getp);
    CHECK(len == 0);

    WAB_UPDATE_PUT(buf, 10);
    CHECK(buf.putp == buf.buf + 10);
    WAB_PUT_SPACE(buf, p, len);
    CHECK(p == buf.putp);
    CHECK(len == sizeof(buf.buf) - 10);
    WAB_GET_SPACE(buf, p, len);
    CHECK(p == buf.getp);
    CHECK(len == 10);

    WAB_UPDATE_GET(buf, 6);
    CHECK(buf.getp == p + 6);
    WAB_GET_SPACE(buf, p, len);
    CHECK(p == buf.getp);
    CHECK(len == 4);

    // wrap around
    WAB_UPDATE_PUT(buf, 6);
    CHECK(buf.putp - buf.buf == 0);
    WAB_PUT_SPACE(buf, p, len);
    CHECK(p == buf.putp);
    CHECK(len == buf.getp - buf.putp - 1);

    WAB_GET_SPACE(buf, p, len);
    CHECK(p == buf.getp);
    CHECK(len == 10);

    WAB_UPDATE_GET(buf, len);
    CHECK(buf.getp == buf.buf);
}

TEST_CASE("cert-chain", "[key]") {
    auto pem = R"("
-----BEGIN CERTIFICATE-----
MIIDojCCAYqgAwIBAgIDBLfgMA0GCSqGSIb3DQEBCwUAMIGTMQswCQYDVQQGEwJVUzELMAkGA1UE
CBMCTkMxEjAQBgNVBAcTCUNoYXJsb3R0ZTETMBEGA1UEChMKTmV0Rm91bmRyeTEoMCYGA1UEAxMf
Wml0aSBDb250cm9sbGVyIEludGVybWVkaWF0ZSBDQTEkMCIGCSqGSIb3DQEJARYVc3VwcG9ydEBu
ZXRmb3VuZHJ5LmlvMB4XDTI0MDczMTE3MjUzNVoXDTI1MDczMTE3MjYzNVowFDESMBAGA1UEAxMJ
Q2FmU3ZwSHAwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE92VlMrJv9Ydw33aTCefJtwMHgDKv
mDqJJkH4STzM/+5UJDLtSF5z7TftVFZ2rZvLaDPD1rs4JpWdiscASYdk96NIMEYwDgYDVR0PAQH/
BAQDAgSwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFGt95MgE1uEQNJoDlUebyTJ/
7/UJMA0GCSqGSIb3DQEBCwUAA4ICAQByEisNy20/2GMaN1q7ILIMiuq1SeDHi9qsmzgOnb3mYGWU
uLuMc0Rs/N5W4+8TXq3ex+GHKWGAx+AB6oNTYtqLsGAEo9c7kCPWOrsFa3TPDG/u7jNBCvC5idIw
RanAfNMQGXWuqbTt9mi5hf115vC6QIRSUo6gPF5+IEMG1RcNMjTYChCFctBzPMqU4Ku9S2jFyYhM
7s1q6MGAQ7LEkXOVWn66dsnpaqkVjFOsjg66xkENFyF0PIwMvbCqUrlzxKij3INfc8Q0QtCLY0Wl
+9p1n27MRQBamiJHVdANJ62X2f3LH2izkV4Ria2sZjqYvs3Oh/1tWc171QKekZDwn+Nz01eXRTVM
ynVPu5CNlcGD4vMUkiXWr282MH51l02aZ0/PUXPdU7NZxJdt+AGsWNgTBjKA0uEhc51rXKmj1iN9
s1/1K4PDrgwt0ikHq5n6NpEk3OXfAVuLWJqPQ/+leouP5S8OCG6n2DrrypC2bT4EMej5VMo8OUbn
XNS8uqbsqU70gKlJdnOh9exoClo9yppNzRdmpyZTBPCrQ637wnhw4VjwsYzZccg8iT6mNn/tRHeR
qfvj87DcOjrqPPRUC9MLvO+1uyPG069mZAu2DJzYtFM7OOmqHEK58syMf4sAR09o7drfliKkz8Mx
9nGcqsXUMNZRl1aiDtplNxnRrEPaqw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIF6TCCA9GgAwIBAgIGAYekZkqtMA0GCSqGSIb3DQEBCwUAMHIxLTArBgNVBAMMJDUwYTQ5YTkw
LTQ4MDQtNGU0Ni1iMGM0LWU5M2ZjNmJjNTc4ZjETMBEGA1UECgwKTmV0Rm91bmRyeTESMBAGA1UE
BwwJQ2hhcmxvdHRlMQswCQYDVQQIDAJOQzELMAkGA1UEBhMCVVMwHhcNMjMwNDIxMTUxOTM5WhcN
MzMwNDE4MTUxOTM5WjCBkzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAk5DMRIwEAYDVQQHEwlDaGFy
bG90dGUxEzARBgNVBAoTCk5ldEZvdW5kcnkxKDAmBgNVBAMTH1ppdGkgQ29udHJvbGxlciBJbnRl
cm1lZGlhdGUgQ0ExJDAiBgkqhkiG9w0BCQEWFXN1cHBvcnRAbmV0Zm91bmRyeS5pbzCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJQvbAD2H5aI1fe1z2GbaSopVNx5izA0+QAWTXAKyXZm
aUxJpw10fC1fFPOx0OSi0a/cdDgXMl8TdEs9Qb2w/6qTTduQUGes4SsO02BUHvUDPK4HG6eHpxL6
VSudDDcH8mkGcv1RhsTTvB2400Gxdgp1i9zpfZkt4JYDeEJDhE//+GXZ2pMzX0ShUPzRoRyuzW+O
ha1TgcX8upA/8nDwREEp24/A3Hwk+uJ4Ym+1XOPICT2idgJcjs++3tb++UJitfFELTKUVlzs0kx+
2sEddhjYuEkv21x53eW727sG0cNIVr9SHqS3NgK5w4GE92f73D6IDHWchZHpSSs0atF6Ty7nIElx
CgtlhMbge3yLeLHJHX/jHibb38e7w+jpyyBNk/ty85r+DN5j24it8TOpKgARvywb5vRTIUUGv6wq
jRBSN76yUQxaKUUoSII13b0yJwZncMkNK4hex1W6sS+o4PB2pVQpOAb5dbrtsUtLr+mEfERdQH+y
SQaKjYTvyl9XbA9lw3551pyfJPLuc4otKx+uBVTMWmYIkuiRvUM/Xql29LqM0lrSrw64xqw1sdn7
piKqIBXetnF4KUhvs0mXzwSf+XuRNHTrFAKaQY373hDnVqgesjo87ilP7zhTftX5CBzeywx84e79
chQJ00uV/7V/tDoYYX1Auohf800XZ1UlAgMBAAGjYzBhMB0GA1UdDgQWBBRrfeTIBNbhEDSaA5VH
m8kyf+/1CTAfBgNVHSMEGDAWgBRrfeTIBNbhEDSaA5VHm8kyf+/1CTAPBgNVHRMBAf8EBTADAQH/
MA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAi8Nr09339b5Hu7S46ce8k4dNO+iT
VLW37Kxwy6ZCwgOHgjoMMR0JTzn1y+dJGv2+SWC8AOQwGsaAh8JBbK5F3I/dGyXLUmth3KsUr1Ex
2cLJM9usF+MRQrKarybW84yWyPXRUNh9z8n/gNsZVLhggLG0C73zfCijhFcOdMf/1s732tUlG3/X
mZb2Rftf94oquLp31499OJXsl554QRDDzST88hyUmBd6q/gfWPjhdESvM/60IIgnPNlXv7q/X1EF
4qqSts8doaMx2XGX5sZA6o7h2fCdgGUtxe1Pm1vohCzKeFZeC9wS18QxGxIWkBJY6RndcfC2CXNC
H9Ck1wlfpUH6snzKw+iyw6+1QaMNLjQU3ZsU5tJBjdFSKDF+auBVX1V3rY2arKfrYBtzq6v98WXW
BYPbtx6Hy30DmwBAQsWSh087O6Atj0ZupgFm58zYrIj4lL5sdeOeJ+yu4rKqI5IYj1ssEkL7ey8c
ddyoEdE1txGHUICkwIlzHbtBNp0vCoI6V5K4IYAEFwpDJxmIrMDxi7z6WBt7i0YZuLfwWV/5Gu26
ClE70UxGSsMjY8Evg0qSemyX/S63aziH1I9+m+3BUF+bg75zTmirgzIPt3B0mbD4Rx99DC6bE9n8
Z8AgrJehwuXYVyJrG5Tc1vnlSUhUrK2812JyXA7tkWj/qzc=
-----END CERTIFICATE-----
)";
    auto tls = default_tls_context(nullptr, 0);
    tlsuv_certificate_t cert = nullptr;
    CHECK(tls->load_cert(&cert, pem, strlen(pem)) == 0);
    cert->free(cert);
    tls->free_ctx(tls);
}

TEST_CASE("set-own-cert-leak", "[key]") {

    auto key = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgG7SzSKahcWLs89fv
aNizJUSiYsauVwa9FwxYXgEBoVehRANCAAQKQVwUR8o8rTd9jyUdhnF6YwoLliJj
Rq5+BgFEc0nNrjgYH4P/EiFMxA/Y4sBWD+U3psD7XA6Xk7e0fH1V2Iop
-----END PRIVATE KEY-----
)";
    auto cert = R"(-----BEGIN CERTIFICATE-----
MIIDtjCCAZ6gAwIBAgIDAIkPMA0GCSqGSIb3DQEBCwUAMIGTMQswCQYDVQQGEwJV
UzELMAkGA1UECBMCTkMxEjAQBgNVBAcTCUNoYXJsb3R0ZTETMBEGA1UEChMKTmV0
Rm91bmRyeTEoMCYGA1UEAxMfWml0aSBDb250cm9sbGVyIEludGVybWVkaWF0ZSBD
QTEkMCIGCSqGSIb3DQEJARYVc3VwcG9ydEBuZXRmb3VuZHJ5LmlvMB4XDTI0MTEy
NjE5MTcwNFoXDTI1MTEyNjE5MTgwNFowKDERMA8GA1UEChMIT3BlblppdGkxEzAR
BgNVBAMTCnNwLkVQeFdMeFUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQKQVwU
R8o8rTd9jyUdhnF6YwoLliJjRq5+BgFEc0nNrjgYH4P/EiFMxA/Y4sBWD+U3psD7
XA6Xk7e0fH1V2Iopo0gwRjAOBgNVHQ8BAf8EBAMCBLAwEwYDVR0lBAwwCgYIKwYB
BQUHAwIwHwYDVR0jBBgwFoAUa33kyATW4RA0mgOVR5vJMn/v9QkwDQYJKoZIhvcN
AQELBQADggIBAHF8wPRdC/85zPRqCKp0MOPTUU7198LOMhjhZVWkG2sPnNoc1CdD
NpshtjkARcMfRsY5M8jiS7v+5a5kpHGtLwLBv+cRgg+2JENKv5rhQLnrukLn9ekX
Df3tzNhyUFr9RBMT51sK5Rw9oBlkXggw9+cpldfCKYeMo/hzgOCoIboSyrA9zrEf
LTMN25eQ3YJ82ZSS66UPnPh7xMI1ikEA2n869chTx4XMbxOo2aMla1RFpZ5INB1A
wxtOMq1lle7D0GlwKFNPW6JoeNV3q2WxY8axPeDzKq15gGRkAhWMwjQ/IFSJQoJ3
tzf0MtGwE8LCtAaZMAc+zagcMNs4gcl7+LYV1AzpvuxsAc7h43545kRYkpSmfiT6
wKoTM5uLbxzAUVJQDELjR7QJQmVygH7L+NDK3RAACnZEGwvk6jSMM4N0zsMqhgO3
cKnsPn93ZEMIywmYHzClbj873xjWZYbxAXoF43QpBf3AHSyVH+s36Z4Ms/rMBBGK
438HlVWET6PyXIKWJwTnLuXrRk/BKqk/2+AAwtmofSyL92T2IWLBw29/ZBJk2deb
J8qzl2qqtGhE9wZQ4Bi9d+bUYmyCXT5mPS1xpdOuhG6sg4UcLCErppzBw6L1pz2l
MAnfMG/XPmdqXs7FFhQsXUAH7qnFePuMUUZnVuZ0WJ4ju9JFcp5UQoi8
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIF6TCCA9GgAwIBAgIGAYekZkqtMA0GCSqGSIb3DQEBCwUAMHIxLTArBgNVBAMM
JDUwYTQ5YTkwLTQ4MDQtNGU0Ni1iMGM0LWU5M2ZjNmJjNTc4ZjETMBEGA1UECgwK
TmV0Rm91bmRyeTESMBAGA1UEBwwJQ2hhcmxvdHRlMQswCQYDVQQIDAJOQzELMAkG
A1UEBhMCVVMwHhcNMjMwNDIxMTUxOTM5WhcNMzMwNDE4MTUxOTM5WjCBkzELMAkG
A1UEBhMCVVMxCzAJBgNVBAgTAk5DMRIwEAYDVQQHEwlDaGFybG90dGUxEzARBgNV
BAoTCk5ldEZvdW5kcnkxKDAmBgNVBAMTH1ppdGkgQ29udHJvbGxlciBJbnRlcm1l
ZGlhdGUgQ0ExJDAiBgkqhkiG9w0BCQEWFXN1cHBvcnRAbmV0Zm91bmRyeS5pbzCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJQvbAD2H5aI1fe1z2GbaSop
VNx5izA0+QAWTXAKyXZmaUxJpw10fC1fFPOx0OSi0a/cdDgXMl8TdEs9Qb2w/6qT
TduQUGes4SsO02BUHvUDPK4HG6eHpxL6VSudDDcH8mkGcv1RhsTTvB2400Gxdgp1
i9zpfZkt4JYDeEJDhE//+GXZ2pMzX0ShUPzRoRyuzW+Oha1TgcX8upA/8nDwREEp
24/A3Hwk+uJ4Ym+1XOPICT2idgJcjs++3tb++UJitfFELTKUVlzs0kx+2sEddhjY
uEkv21x53eW727sG0cNIVr9SHqS3NgK5w4GE92f73D6IDHWchZHpSSs0atF6Ty7n
IElxCgtlhMbge3yLeLHJHX/jHibb38e7w+jpyyBNk/ty85r+DN5j24it8TOpKgAR
vywb5vRTIUUGv6wqjRBSN76yUQxaKUUoSII13b0yJwZncMkNK4hex1W6sS+o4PB2
pVQpOAb5dbrtsUtLr+mEfERdQH+ySQaKjYTvyl9XbA9lw3551pyfJPLuc4otKx+u
BVTMWmYIkuiRvUM/Xql29LqM0lrSrw64xqw1sdn7piKqIBXetnF4KUhvs0mXzwSf
+XuRNHTrFAKaQY373hDnVqgesjo87ilP7zhTftX5CBzeywx84e79chQJ00uV/7V/
tDoYYX1Auohf800XZ1UlAgMBAAGjYzBhMB0GA1UdDgQWBBRrfeTIBNbhEDSaA5VH
m8kyf+/1CTAfBgNVHSMEGDAWgBRrfeTIBNbhEDSaA5VHm8kyf+/1CTAPBgNVHRMB
Af8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAi8Nr
09339b5Hu7S46ce8k4dNO+iTVLW37Kxwy6ZCwgOHgjoMMR0JTzn1y+dJGv2+SWC8
AOQwGsaAh8JBbK5F3I/dGyXLUmth3KsUr1Ex2cLJM9usF+MRQrKarybW84yWyPXR
UNh9z8n/gNsZVLhggLG0C73zfCijhFcOdMf/1s732tUlG3/XmZb2Rftf94oquLp3
1499OJXsl554QRDDzST88hyUmBd6q/gfWPjhdESvM/60IIgnPNlXv7q/X1EF4qqS
ts8doaMx2XGX5sZA6o7h2fCdgGUtxe1Pm1vohCzKeFZeC9wS18QxGxIWkBJY6Rnd
cfC2CXNCH9Ck1wlfpUH6snzKw+iyw6+1QaMNLjQU3ZsU5tJBjdFSKDF+auBVX1V3
rY2arKfrYBtzq6v98WXWBYPbtx6Hy30DmwBAQsWSh087O6Atj0ZupgFm58zYrIj4
lL5sdeOeJ+yu4rKqI5IYj1ssEkL7ey8cddyoEdE1txGHUICkwIlzHbtBNp0vCoI6
V5K4IYAEFwpDJxmIrMDxi7z6WBt7i0YZuLfwWV/5Gu26ClE70UxGSsMjY8Evg0qS
emyX/S63aziH1I9+m+3BUF+bg75zTmirgzIPt3B0mbD4Rx99DC6bE9n8Z8AgrJeh
wuXYVyJrG5Tc1vnlSUhUrK2812JyXA7tkWj/qzc=
-----END CERTIFICATE-----)";

    auto tls = default_tls_context(nullptr, 0);
    tlsuv_certificate_t c = nullptr;
    tlsuv_private_key_t k = nullptr;
    CHECK(tls->load_key(&k, key, strlen(key)) == 0);
    CHECK(tls->load_cert(&c, cert, strlen(cert)) == 0);

    CHECK(tls->set_own_cert(tls, k, c) == 0);

    k->free(k);
    c->free(c);
    tls->free_ctx(tls);
}
