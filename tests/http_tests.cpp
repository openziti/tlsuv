// Copyright (c) 2024. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "catch.hpp"
#include "fixtures.h"

#include <compression.h>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <tlsuv/http.h>
#include <tlsuv/tls_engine.h>
#include <tlsuv/tlsuv.h>

#include <parson.h>

extern tlsuv_log_func test_log;
using namespace std;
using namespace Catch::Matchers;

#define to_str_(x) #x
#define to_str(x) to_str_(x)
static const char *test_server_CA = to_str(TEST_SERVER_CA);

std::string testServerURL(const string& type) {
    if (type == "http") {
        return "http://localhost:8080";
    } else if (type == "https") {
        return "https://localhost:8443";
    } else if (type == "auth") {
        return "https://localhost:9443";
    }
    FAIL("unsupported scheme");
    return "";
}

class testServer {
public:
    tls_context* TLS() {
        return tls;
    }
    testServer() {
        tls = default_tls_context(test_server_CA, strlen(test_server_CA));
    }

    ~testServer() {
        tls->free_ctx(tls);
    }
private:
    tls_context* tls;
};

tls_context* testServerTLS() {
    static testServer srv;
    return srv.TLS();
}

static const tlsuv_connector_t *proxy = tlsuv_new_proxy_connector(tlsuv_PROXY_HTTP, "127.0.0.1", "13128");


class resp_capture {
public:
    tlsuv_http_body_cb body_cb;

    explicit resp_capture(tlsuv_http_body_cb cb) : body_cb(cb), status("not set"), code(-666) {}

    resp_capture() : resp_capture(nullptr) {}

    string http_version;
    ssize_t code;
    string status;
    map<string, string> headers;

    string body;
    string req_body;

    int resp_body_end_called{};
    int req_body_cb_called{};

    uv_timeval64_t resp_start{};
    uv_timeval64_t resp_endtime{};
};

void req_body_cb(tlsuv_http_req_t *req, char *chunk, ssize_t status) {
    auto rc = static_cast<resp_capture *>(req->data);
    rc->req_body.append(chunk);
    rc->req_body_cb_called = true;
}

void resp_body_cb(tlsuv_http_req_t *req, char *chunk, ssize_t len) {
    auto rc = static_cast<resp_capture *>(req->data);

    if (len > 0) {
        rc->body.append(chunk, len);
    }
    else if (len == UV_EOF) {
        rc->resp_body_end_called += 1;
    }
}

void resp_capture_cb(tlsuv_http_resp_t *resp, void *data) {
    auto rc = static_cast<resp_capture *>(data);
    rc->code = resp->code;
    rc->status = resp->status ? resp->status : "no status";
    rc->http_version = resp->http_version;

    tlsuv_http_hdr *h;
    LIST_FOREACH(h, &resp->headers, _next) {
        rc->headers[h->name] = h->value;
    }

    resp->body_cb = rc->body_cb;
}

void test_timeout(uv_timer_t *t) {
    printf("timeout stopping loop\n");
    uv_print_all_handles(t->loop, stderr);
    uv_stop(t->loop);
}

static const char* part2 = "this is part 2";
void send_part2(uv_timer_t *t) {
    auto req = static_cast<tlsuv_http_req_t *>(t->data);
    tlsuv_http_req_data(req, part2, strlen(part2), req_body_cb);
    tlsuv_http_req_end(req);

    uv_close((uv_handle_t *) (t), nullptr);
}

TEST_CASE("conn failures", "[http]") {
    auto scheme = GENERATE(as < std::string > {}, "http", "https");
    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);

    string url = scheme + "://localhost:1222";
    INFO(url);
    tlsuv_http_init(test.loop, &clt, url.c_str());
    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "POST", "/", resp_capture_cb, &resp);
    const char *msg = "this is a message";
    tlsuv_http_req_data(req, msg, strlen(msg), nullptr);

    test.run();

    REQUIRE(resp.code == UV_ECONNREFUSED);

    tlsuv_http_close(&clt, nullptr);
}


TEST_CASE("resolve failures", "[http]") {
    auto scheme = GENERATE(as < std::string > {}, "http", "https");

    UvLoopTest test;

    auto clt = t_alloc<tlsuv_http_t>();
    resp_capture resp(resp_body_cb);

    tlsuv_http_init(test.loop, clt, (scheme + "://not.a.real.host").c_str());
    tlsuv_http_req_t *req = tlsuv_http_req(clt, "GET", "/", resp_capture_cb, &resp);

    test.run();

    tlsuv_http_close(clt, (tlsuv_http_close_cb) free);
    INFO("resp.code = " << resp.code << "/" << uv_strerror(resp.code));
    CHECK((resp.code == UV_EAI_NONAME || resp.code == UV_EAI_AGAIN));
}

TEST_CASE("http_tests", "[http]") {

    auto connector = GENERATE((const tlsuv_connector_t *)nullptr, proxy);

    auto scheme = GENERATE(as < std::string > {}, "http", "https");

    UvLoopTest test;
    tlsuv_http_t clt;

    std::string testType = scheme + '(' + (connector ? "proxy" : "direct") + ")";
    tlsuv_set_global_connector(connector);

    resp_capture resp(resp_body_cb);

    WHEN(testType << " redirect") {
        tlsuv_http_init(test.loop, &clt, testServerURL(scheme).c_str());
        tlsuv_http_set_ssl(&clt, testServerTLS());
        tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/redirect/2", resp_capture_cb, &resp);

        test.run();

        REQUIRE(resp.code == HTTP_STATUS_FOUND);
        REQUIRE(resp.headers["Location"] == "/relative-redirect/1");
    }

    WHEN(testType << " body GET") {
        tlsuv_http_init(test.loop, &clt, testServerURL(scheme).c_str());
        tlsuv_http_set_ssl(&clt, testServerTLS());
        tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/get", resp_capture_cb, &resp);

        test.run();

        REQUIRE(resp.code == HTTP_STATUS_OK);
        REQUIRE(resp.resp_body_end_called);
        REQUIRE_THAT(resp.headers["Content-Type"], Catch::Matchers::StartsWith("application/json"));
        REQUIRE(resp.headers.find("Content-Length") != resp.headers.end());
        size_t body_len = resp.body.size();
        size_t content_len = strtol(resp.headers["Content-Length"].c_str(), nullptr, 10);
        REQUIRE(body_len == content_len);
    }

    WHEN(testType << " send headers") {
        tlsuv_http_init(test.loop, &clt, testServerURL(scheme).c_str());
        tlsuv_http_set_ssl(&clt, testServerTLS());
        tlsuv_http_header(&clt, "Client-Header", "This is client header");

        tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/get", resp_capture_cb, &resp);
        tlsuv_http_req_header(req, "Request-Header", "this is request header");

        resp_capture resp2(resp_body_cb);
        tlsuv_http_req_t *req2 = tlsuv_http_req(&clt, "GET", "/get", resp_capture_cb, &resp2);

        test.run();

        REQUIRE(resp.code == HTTP_STATUS_OK);
        REQUIRE(resp2.code == HTTP_STATUS_OK);
        REQUIRE_THAT(resp.body, Catch::Matchers::ContainsSubstring("Client-Header") && Catch::Matchers::ContainsSubstring("This is client header"));
        REQUIRE_THAT(resp2.body, Catch::Matchers::ContainsSubstring("Client-Header") && Catch::Matchers::ContainsSubstring("This is client header"));

        REQUIRE_THAT(resp.body, Catch::Matchers::ContainsSubstring("Request-Header") && Catch::Matchers::ContainsSubstring("this is request header"));
        REQUIRE_THAT(resp2.body, !Catch::Matchers::ContainsSubstring("Request-Header") && !Catch::Matchers::ContainsSubstring("this is request header"));
    }

    WHEN(testType << " POST body") {
        tlsuv_http_init(test.loop, &clt, testServerURL(scheme).c_str());
        tlsuv_http_set_ssl(&clt, testServerTLS());
        tlsuv_http_req_t *req = tlsuv_http_req(&clt, "POST", "/post", resp_capture_cb, &resp);
        string req_body("this is a test message");
        tlsuv_http_req_data(req, req_body.c_str(), req_body.length(), req_body_cb);

        test.run();

        THEN("request should complete") {
            REQUIRE(resp.code == HTTP_STATUS_OK);
            REQUIRE(resp.resp_body_end_called);
        }
        REQUIRE_THAT(resp.headers["Content-Type"], Catch::Matchers::StartsWith("application/json"));
        size_t body_len = resp.body.size();
        size_t content_len = strtol(resp.headers["Content-Length"].c_str(), nullptr, 10);
        REQUIRE(body_len == content_len);

        REQUIRE_THAT(resp.body, Catch::Matchers::ContainsSubstring(req_body));
        REQUIRE(resp.req_body_cb_called);
    }


    WHEN(testType << " posting chunked") {
        tlsuv_http_init(test.loop, &clt, testServerURL(scheme).c_str());
        tlsuv_http_set_ssl(&clt, testServerTLS());
        tlsuv_http_req_t *req = tlsuv_http_req(&clt, "POST", "/post", resp_capture_cb, &resp);
        tlsuv_http_req_header(req, "Transfer-Encoding", "chunked");

        string part1("this is part1");
        tlsuv_http_req_data(req, part1.c_str(), part1.length(), req_body_cb);

        uv_timer_t p2_timer;
        uv_timer_init(test.loop, &p2_timer);
        p2_timer.data = req;
        uv_timer_start(&p2_timer, send_part2, 1000, 0);

        test.run();

        THEN("request should complete") {
            REQUIRE(resp.code == HTTP_STATUS_OK);
            REQUIRE_THAT(resp.headers["Content-Type"], Catch::Matchers::StartsWith("application/json"));
            REQUIRE(resp.resp_body_end_called);
            REQUIRE(resp.headers.find("Content-Length") != resp.headers.end());
        }
        size_t body_len = resp.body.size();
        size_t content_len = strtol(resp.headers["Content-Length"].c_str(), nullptr, 10);

        THEN("response body size Catch::Matchers::ContainsSubstring") {
            REQUIRE(body_len == content_len);
        }

        THEN("request sent completely") {
            REQUIRE_THAT(resp.req_body, Equals(part1 + part2));
            REQUIRE(resp.req_body_cb_called);
        }
    }
    tlsuv_http_close(&clt, nullptr);
    tlsuv_set_global_connector(nullptr);
}

#if defined(HSM_LIB)

TEST_CASE("pkcs11_client_cert_test","[http]") {
    std::string keyType = GENERATE("rsa","ec");

    UvLoopTest test;
    tls_context *tls = default_tls_context(test_server_CA, strlen(test_server_CA));

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);

    WHEN(keyType << ": client cert set") {
        tlsuv_http_init(test.loop, &clt, testServerURL("auth").c_str());
        tlsuv_http_set_ssl(&clt, tls);
        tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/", resp_capture_cb, &resp);

        std::string keyName = "test-" + keyType;
        tlsuv_private_key_t pk;
        int rc = tls->load_pkcs11_key(&pk, to_str(HSM_LIB), nullptr, "2222", nullptr, keyName.c_str());
        REQUIRE(rc == 0);
        CHECK(tls->set_own_cert(tls, pk, nullptr) == 0);

        test.run();

        CHECK(resp.code == HTTP_STATUS_OK);
        CHECK(resp.resp_body_end_called);
        CHECK(resp.body == "you are 'CN=test-" + keyType + "' by CN=test-" + keyType);
    }

    tlsuv_http_close(&clt, nullptr);
    if (tls)
        tls->free_ctx(tls);
}
#endif

TEST_CASE("client_cert_test","[http]") {
    UvLoopTest test;
    tls_context *tls = nullptr;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);

    WHEN("client cert NOT set") {
        tlsuv_http_init(test.loop, &clt, testServerURL("auth").c_str());
        tlsuv_http_set_ssl(&clt, testServerTLS());
        tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/secure/", resp_capture_cb, &resp);

        test.run();

        THEN("request should be bad") {
            CHECK(resp.code == HTTP_STATUS_UNAUTHORIZED);
            CHECK_THAT(resp.body, Catch::Matchers::ContainsSubstring("I don't know you"));
        }

        AND_THEN("response body size Catch::Matchers::ContainsSubstring") {
            size_t body_len = resp.body.size();
            size_t content_len = strtol(resp.headers["Content-Length"].c_str(), nullptr, 10);
            REQUIRE(body_len == content_len);
        }
    }

    WHEN("client cert set") {
        tlsuv_http_init(test.loop, &clt, testServerURL("auth").c_str());
        tls = default_tls_context(test_server_CA, strlen(test_server_CA));
        tlsuv_http_set_ssl(&clt, tls);
        tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/", resp_capture_cb, &resp);

        // client cert downloaded from https://badssl.com/download/
        const char *cert = "-----BEGIN CERTIFICATE-----\n"
                           "MIIEnTCCAoWgAwIBAgIJAPYAapdmy98xMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\n"
                           "BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp\n"
                           "c2NvMQ8wDQYDVQQKDAZCYWRTU0wxMTAvBgNVBAMMKEJhZFNTTCBDbGllbnQgUm9v\n"
                           "dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMjExMjA0MDAwODE5WhcNMjMxMjA0\n"
                           "MDAwODE5WjBvMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQG\n"
                           "A1UEBwwNU2FuIEZyYW5jaXNjbzEPMA0GA1UECgwGQmFkU1NMMSIwIAYDVQQDDBlC\n"
                           "YWRTU0wgQ2xpZW50IENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"
                           "MIIBCgKCAQEAxzdfEeseTs/rukjly6MSLHM+Rh0enA3Ai4Mj2sdl31x3SbPoen08\n"
                           "utVhjPmlxIUdkiMG4+ffe7N+JtDLG75CaxZp9CxytX7kywooRBJsRnQhmQPca8MR\n"
                           "WAJBIz+w/L+3AFkTIqWBfyT+1VO8TVKPkEpGdLDovZOmzZAASi9/sj+j6gM7AaCi\n"
                           "DeZTf2ES66abA5pOp60Q6OEdwg/vCUJfarhKDpi9tj3P6qToy9Y4DiBUhOct4MG8\n"
                           "w5XwmKAC+Vfm8tb7tMiUoU0yvKKOcL6YXBXxB2kPcOYxYNobXavfVBEdwSrjQ7i/\n"
                           "s3o6hkGQlm9F7JPEuVgbl/Jdwa64OYIqjQIDAQABoy0wKzAJBgNVHRMEAjAAMBEG\n"
                           "CWCGSAGG+EIBAQQEAwIHgDALBgNVHQ8EBAMCBeAwDQYJKoZIhvcNAQELBQADggIB\n"
                           "ABlLNovFvSrULgLvJmKX/boSWQOhWE0HDX6bVKyTs48gf7y3DXSOD+bHkBNHL0he\n"
                           "m4HRFSarj+x389oiPEti5i12Ng9OLLHwSHK+7AfnrkhLHA8ML3NWw0GBr5DgdsIv\n"
                           "7MJdGIrXPQwTN5j++ICyY588TfGHH8vU5qb5PrSqClLZSSHU05FTr/Dc1B8hKjjl\n"
                           "d/FKOidLo1YDLFUjaB9x1mZPUic/C489lyPfWqPqoMRd5i/XShST5FPvfGuKRd5q\n"
                           "XKDkrn+GaQ/4iDDdCgekDCCPhOwuulavNxBDjShwZt1TeUrZNSM3U4GeZfyrVBIu\n"
                           "Tr+gBK4IkD9d/vP7sa2NQszF0wRQt3m1wvSWxPz91eH+MQU1dNPzg1hnQgKKIrUC\n"
                           "NTab/CAmSQfKC1thR15sPg5bE0kwJd1AJ1AqTrYxI0VITUV8Gka3tSAp3aKZ2LBg\n"
                           "gYHLI2Rv9jXe5Yx5Dckf3l+YSFp/3dSDkFOgEuZm2FfZl4vNBR+coohpB9+2jRWL\n"
                           "K+4fIkCJba+Y2cEd5usJE18MTH9FU/JKDwzC+eO9SNLFUw3zGUsSwgZsBHP6kiQN\n"
                           "suia9q4M5f+68kzM4+0NU8HwwyzZEtmTBhktKHijExixdvjlMAZ8hAOsFifsevI0\n"
                           "02dUYvtxoHaeXh4jpYHVNnsIf/74uLagiPHtVf7+9UZV\n"
                       "-----END CERTIFICATE-----";
    const char *key = "-----BEGIN PRIVATE KEY-----\n"
                      "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHN18R6x5Oz+u6\n"
                      "SOXLoxIscz5GHR6cDcCLgyPax2XfXHdJs+h6fTy61WGM+aXEhR2SIwbj5997s34m\n"
                      "0MsbvkJrFmn0LHK1fuTLCihEEmxGdCGZA9xrwxFYAkEjP7D8v7cAWRMipYF/JP7V\n"
                      "U7xNUo+QSkZ0sOi9k6bNkABKL3+yP6PqAzsBoKIN5lN/YRLrppsDmk6nrRDo4R3C\n"
                      "D+8JQl9quEoOmL22Pc/qpOjL1jgOIFSE5y3gwbzDlfCYoAL5V+by1vu0yJShTTK8\n"
                      "oo5wvphcFfEHaQ9w5jFg2htdq99UER3BKuNDuL+zejqGQZCWb0Xsk8S5WBuX8l3B\n"
                      "rrg5giqNAgMBAAECggEAVRB/t9b9igmeTlzyQpHPIMvUu3uTpm742JmWpcSe61FA\n"
                      "XmhDzInNdLnIfbnb3p44kj4Coy5PbzKlm01sbNxA4BkiBPE1yen1J/2eU/LJ6QuN\n"
                      "jRjo9drFfR75UWPQ3xu9uJhQY2rocLILXmvy69FlG+ebThh8SPbTMtNaTFMb47An\n"
                      "pk2FrW9+rzPswbklOxls/SDt78usRvfAjslm73IdBTOrbceF+GmYs3/SXz1gu05p\n"
                      "LxY2rhC8piBlqnD/QbXBahZbhjb9SkDFn2typMFZKkJIIKDJaOI2E9tIlZ97/0nZ\n"
                      "txqchMty8IuU9YYAfLXCmj2IEfnvLtL7thLfKLuWAQKBgQDyXBpEgKFzfy2a1AI0\n"
                      "+1qL/u5UN14l7S6/wmyDTgVMXwoxhwPRXWD5PutQ8D6tMfC/y4AYt3OXg1blCvLD\n"
                      "XysNj5SK+dpmQR0SyeWjd9zwxJAXvx0McJefCYd86YGcGhJsuX5bkHIeQlEc6df7\n"
                      "yoqr1480VQx/+Fk1i6Zr0EIUFQKBgQDSbalUOfXZh2EVRQEgf3VoPlxAiwGGQcVT\n"
                      "i+pbjMG3pOwmkVyJZusGtN5HN4Oi7n1oiyfMYGsszKQ5j4TDBGS70pNUzhTv3Vn8\n"
                      "0Vsfz0arJRqJxviiv4FfDmsYXwObNKwOjR+LEn1NUPkOYOLdz1lDuWOu11LE90Dy\n"
                      "Q6hg8WwCmQKBgQDTy5lI9AAjpqh7/XpQQrhGT2qHPjuQeU25Vnbt6GjI7OVDkvHL\n"
                      "LQdpyYprGQgs4s+5TGWNNARYC/cMAh1Ujv5Yw3jUWrR5V73IhZeg20bBQYWKuwDv\n"
                      "thVKblFw377cZAxl51R9QCX6O4oW8mRFLiMxORd0bD6YNrf/CyNMZJraYQKBgAE7\n"
                      "o0JbFJWxtV/qh5cpKAb0VpYKOngO6pkSuMzQhlINJVUUhPZJJBdl9+dy69KIkzOJ\n"
                      "nTIVXotkp5GuxZhe7jgrg7F7g6PkKCLTFzWYgVF/ZihoggxyEs/7xaTe6aZ/KILt\n"
                      "UMH/2bwaPVtYNfwWuu8qpurfWBzPVhIVU2c+AuQBAoGAXMbw10vyiznlhyMFw5kx\n"
                      "SzlBMqJBLJkzQBtpvXuT0lqqxTSNC3N4WxgVOLCHa6HqXiB0790YL8/RWunsXTk2\n"
                      "c7ugThP6iMPNVAycWkIF4vvHTwZ9RCSmEQabRaqGGLz/bhLL3fi3lPGCR+iW2Dxq\n"
                      "GTH3fhaM/pZZGdIC75x/69Y=\n"
                      "-----END PRIVATE KEY-----";
        tlsuv_private_key_t pk = nullptr;
        int rc = tls->load_key(&pk, key, strlen(key) + 1);
        REQUIRE(rc == 0);
        REQUIRE(pk != nullptr);

        tlsuv_certificate_t c = nullptr;
        CHECK(tls->load_cert(&c, cert, strlen(cert)) == 0);
        CHECK(tls->set_own_cert(tls, pk, c) == 0);

        test.run();


        CHECK(resp.code == HTTP_STATUS_OK);
        CHECK(resp.resp_body_end_called);
        CHECK(resp.body == "you are 'CN=BadSSL Client Certificate,O=BadSSL,L=San Francisco,ST=California,C=US' by CN=BadSSL Client Root Certificate Authority,O=BadSSL,L=San Francisco,ST=California,C=US");
        c->free(c);
    }

    tlsuv_http_close(&clt, nullptr);
    if (tls)
        tls->free_ctx(tls);
}

const int ONE_SECOND = 1000000;
const int ONE_MILLI = 1000;

static long duration(uv_timeval64_t &start, uv_timeval64_t &stop) {
    return stop.tv_sec * ONE_SECOND + stop.tv_usec - start.tv_sec * ONE_SECOND - start.tv_usec;
}

TEST_CASE("client_idle_test","[http]") {
    UvLoopTest test;

    tlsuv_http_t clt;

    tlsuv_http_body_cb bodyCb = [](tlsuv_http_req_t *req, char *b, ssize_t len) {
        auto r = static_cast<resp_capture *>(req->data);

        if (len == UV_EOF) {
            uv_gettimeofday(&r->resp_endtime);
        }
    };
    resp_capture resp(bodyCb);
    tlsuv_http_init(test.loop, &clt, testServerURL("https").c_str());
    tlsuv_http_set_ssl(&clt, testServerTLS());
    tlsuv_http_idle_keepalive(&clt, 5000);
    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/get", resp_capture_cb, &resp);

    WHEN("client idle timeout is set to 5 seconds") {
        uv_timeval64_t start;
        uv_gettimeofday(&start);
        test.run();
        uv_timeval64_t stop;
        uv_gettimeofday(&stop);

        THEN("request should be fast and then idle for 5 seconds") {
            CHECK(resp.code == HTTP_STATUS_OK);
            CHECK(duration(start, resp.resp_endtime) < 2 * ONE_SECOND);
            CHECK(duration(resp.resp_endtime, stop) >= (5 * ONE_SECOND - ONE_MILLI));
        }

        tlsuv_http_close(&clt, nullptr);
    }
}

// hidden test
// can't rely on server closing connection in time
TEST_CASE("server_idle_close","[.]") {
    UvLoopTest test;

    tlsuv_http_t clt;

    tlsuv_http_body_cb body_cb = [](tlsuv_http_req_t *req, char *b, ssize_t len) {
        auto r = static_cast<resp_capture *>(req->data);

        if (len == UV_EOF) {
            uv_gettimeofday(&r->resp_endtime);
        }
    };
    resp_capture resp(body_cb);

    tlsuv_http_init(test.loop, &clt, "http://www.aptivate.org");
    tlsuv_http_idle_keepalive(&clt, -1);
    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/", resp_capture_cb, &resp);

    WHEN("client timeout is set to -1") {
        uv_timeval64_t start;
        uv_gettimeofday(&start);

        test.run();

        uv_timeval64_t stop;
        uv_gettimeofday(&stop);

        THEN("request should be fast and then idle until server disconnects") {
            REQUIRE(resp.code == HTTP_STATUS_OK);
            REQUIRE(duration(start, resp.resp_endtime) < ONE_SECOND);
            auto test_duration = duration(start, stop);
            REQUIRE(test_duration >= 5 * ONE_SECOND);
            REQUIRE(test_duration < 30 * ONE_SECOND);
        }

        tlsuv_http_close(&clt, nullptr);
    }
}

TEST_CASE("basic_test", "[http]") {
    auto connector = GENERATE((const tlsuv_connector_t *)nullptr, proxy);

    tlsuv_set_global_connector(connector);
    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);
    tlsuv_http_init(test.loop, &clt, testServerURL("https").c_str());
    tlsuv_http_set_ssl(&clt, testServerTLS());
    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/json", resp_capture_cb, &resp);

    test.run();

    THEN("request should be fast and then idle for 5 seconds " << (connector ? "via proxy" : "direct")) {
        CHECK(resp.code == HTTP_STATUS_OK);
        CHECK_THAT(resp.http_version, Equals("1.1"));
        CHECK_THAT(resp.status, Equals("OK"));

        CHECK_THAT(resp.headers["Content-Type"], Catch::Matchers::StartsWith("application/json"));
    }

    tlsuv_http_close(&clt, nullptr);

    tlsuv_set_global_connector(nullptr);
}

TEST_CASE("invalid CA", "[http]") {
    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);
    tlsuv_http_init(test.loop, &clt, testServerURL("https").c_str());
    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/json", resp_capture_cb, &resp);

    test.run();

    THEN("default CA should not work") {
        CHECK(resp.code == UV_ECONNABORTED);
    }

    tlsuv_http_close(&clt, nullptr);
}


TEST_CASE("http_prefix", "[http]") {
    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);
    tlsuv_http_init(test.loop, &clt, (testServerURL("http") + "/bytes").c_str());
    tlsuv_http_set_ssl(&clt, testServerTLS());
    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/256", resp_capture_cb, &resp);

    test.run();

    REQUIRE(resp.code == HTTP_STATUS_OK);
    CHECK_THAT(resp.headers["Content-Length"], Equals("256"));

    tlsuv_http_close(&clt, nullptr);
}

TEST_CASE("http_prefix_after", "[http]") {
    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);
    tlsuv_http_init(test.loop, &clt, testServerURL("http").c_str());
    tlsuv_http_set_ssl(&clt, testServerTLS());

    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/256", resp_capture_cb, &resp);
    tlsuv_http_set_path_prefix(&clt, "/bytes");

    test.run();

    REQUIRE(resp.code == HTTP_STATUS_OK);
    CHECK_THAT(resp.headers["Content-Length"], Equals("256"));

    tlsuv_http_close(&clt, nullptr);
}

TEST_CASE("content_length_test", "[http]") {
    UvLoopTest test;
    std::string scheme = GENERATE("http", "https");

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);
    tlsuv_http_init(test.loop, &clt, testServerURL(scheme).c_str());
    tlsuv_http_set_ssl(&clt, testServerTLS());

    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "POST", "/json", resp_capture_cb, &resp);

    WHEN(scheme << ": set Content-Length first") {
        int rc = tlsuv_http_req_header(req, "Content-Length", "20");
        CHECK(rc == 0);
        CHECK(req->req_body_size == 20);
        CHECK(!req->req_chunked);

        rc = tlsuv_http_req_header(req, "Transfer-Encoding", "chunked");
        CHECK(rc == UV_EINVAL);
        CHECK(req->req_body_size == 20);
        CHECK(!req->req_chunked);
    }

    WHEN(scheme << ": set Chunked first") {
        int rc = tlsuv_http_req_header(req, "Transfer-Encoding", "chunked");
        CHECK(rc == 0);
        CHECK(req->req_body_size == -1);
        CHECK(req->req_chunked);

        rc = tlsuv_http_req_header(req, "Content-Length", "20");
        CHECK(rc == UV_EINVAL);
        CHECK(req->req_body_size == -1);
        CHECK(req->req_chunked);
    }

    tlsuv_http_close(&clt, nullptr);
}

TEST_CASE("multiple requests", "[http]") {
    UvLoopTest test;

    tlsuv_http_t clt;
    tlsuv_http_init(test.loop, &clt, testServerURL("https").c_str());
    tlsuv_http_set_ssl(&clt, testServerTLS());

    resp_capture resp1(resp_body_cb);
    tlsuv_http_req_t *req1 = tlsuv_http_req(&clt, "GET", "/json", resp_capture_cb, &resp1);

    resp_capture resp2(resp_body_cb);
    tlsuv_http_req_t *req2 = tlsuv_http_req(&clt, "GET", "/json", resp_capture_cb, &resp2);

    WHEN("two non-keepalive requests") {
        tlsuv_http_req_header(req1, "Connection", "close");
        tlsuv_http_req_header(req2, "Connection", "close");
        test.run();

        THEN("both requests should succeed") {
            CHECK(resp1.code == HTTP_STATUS_OK);
            CHECK_THAT(resp1.http_version, Equals("1.1"));
            CHECK_THAT(resp1.status, Equals("OK"));
            CHECK_THAT(resp1.headers["Content-Type"], StartsWith("application/json"));
            CHECK_THAT(resp1.headers["Connection"], Equals("close"));

            CHECK(resp2.code == HTTP_STATUS_OK);
            CHECK_THAT(resp2.http_version, Equals("1.1"));
            CHECK_THAT(resp2.status, Equals("OK"));
            CHECK_THAT(resp2.headers["Content-Type"], StartsWith("application/json"));
            CHECK_THAT(resp2.headers["Connection"], Equals("close"));
        }
    }

    WHEN("two keep-alive requests") {
        tlsuv_http_req_header(req1, "Connection", "keep-alive");
        tlsuv_http_req_header(req2, "Connection", "keep-alive");
        test.run();

        THEN("both requests should succeed") {
            CHECK(resp1.code == HTTP_STATUS_OK);
            CHECK_THAT(resp1.http_version, Equals("1.1"));
            CHECK_THAT(resp1.status, Equals("OK"));
            CHECK_THAT(resp1.headers["Content-Type"], StartsWith("application/json"));
            CHECK_THAT(resp1.headers["Connection"], !StartsWith("close"));

            CHECK(resp2.code == HTTP_STATUS_OK);
            CHECK_THAT(resp2.http_version, Equals("1.1"));
            CHECK_THAT(resp2.status, Equals("OK"));
            CHECK_THAT(resp2.headers["Connection"], !Equals("close"));
        }
    }

    tlsuv_http_close(&clt, nullptr);
}

// test proper client->engine cleanup between requests
// run in valgrind to see any leaks
TEST_CASE("TLS reconnect", "[http]") {
    UvLoopTest test;
    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);
    resp_capture resp2(resp_body_cb);

    tlsuv_http_init(test.loop, &clt, testServerURL("https").c_str());
    tlsuv_http_set_ssl(&clt, testServerTLS());
    tlsuv_http_header(&clt, "Connection", "close");

    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/json", resp_capture_cb, &resp);
    tlsuv_http_req_t *req2 = tlsuv_http_req(&clt, "GET", "/anything", resp_capture_cb, &resp2);

    test.run();

    CHECK(resp.code == 200);
    CHECK(resp2.code == 200);

    tlsuv_http_close(&clt, nullptr);
}

typedef struct verify_ctx_s {
    tls_context *tls;
    const char *data;
    size_t datalen;
    char *sig;
    size_t siglen;
} verify_ctx;

int cert_verify(const tlsuv_certificate_s * crt, void *ctx) {
    auto vtx = (verify_ctx *)ctx;

    int rc = crt->verify(crt, hash_SHA256, vtx->data, vtx->datalen, vtx->sig, vtx->siglen);
    return rc;
}

TEST_CASE("large POST(GH-87)", "[http][gh-87]") {
    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);

    tlsuv_http_init(test.loop, &clt, testServerURL("https").c_str());
    tlsuv_http_set_ssl(&clt, testServerTLS());

    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "POST", "/anything", resp_capture_cb, &resp);
    int buf_size = 64 * 1024;
    char *buf = (char*)calloc(1,buf_size);
    memset(buf, 'Z', buf_size - 1);
    char length[16];
    snprintf(length, sizeof(length), "%d", buf_size);
    tlsuv_http_req_header(req, "Content-Type", "application/octet-stream");
    tlsuv_http_req_header(req, "Content-Length", length);
    tlsuv_http_req_header(req, "Connection", "Close");
    tlsuv_http_req_data(req, buf, 64 * 1024, req_body_cb);

    test.run();

    CHECK(resp.code == 200);

    tlsuv_http_close(&clt, nullptr);
    free(buf);
}

TEST_CASE("TLS verify with JWT", "[http]") {
    INFO("skipping JWT test");
    return;

    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);
    const char *jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
                      "eyJlbSI6Im90dCIsImV4cCI6MTU5MTE4NzM1MSwiaXNzIjoiaHR0cHM6Ly9kZW1vNC56aXRpLm"
                      "5ldGZvdW5kcnkuaW86NDQzIiwianRpIjoiNDU5ZTM4NDktNmUwMi00Mzc1LTg2MzAtOGZmYjJk"
                      "NTFiYjU0Iiwic3ViIjoiZDMxYzAwNDQtMTI3OC00OTdhLWJmNTktMTdjOWI5ZGI0MGEwIn0."
                      "tDzEmiggOdDti9srOIc41RaoBZqFTYeI2P3BnA9mmhFocYPSqdbG3F23x8pAPJZfEs1D9WLRPI"
                      "YsOAdA1ZAd7_CV77pzgxTNampbe8zl3zzMy19k63vMRbZz2B1mw8javEgHM54R5R765obu4je3"
                      "LTFBo6wmTXrjTulmcCpYv_XekDAEKBhr9RcgvPr9liBHU4k6navtkSF7NLOwSNLg6Kq1U0aTkc"
                      "pqeqnWamg95-LnIKdgHQ9TIIzWrES3ASDEDZn_rCi1oiGUTXvD4ZbOxYj5bzUCxw0C3-dlAdlA"
                      "Eo2uY9YP1HWCpcise0a3SdB9GXaCQ5AX9k_6TbYDb6r-gxo7dfAvY352QVK0Rg0lXw98XSftn3"
                      "qwjM5hc7M07gDiD3YIY7W1OFbefcH1JnAs-8K9jIWynI8-jAG3x-tqJiI856arUCzNRwcqB8PN"
                      "VM6nOp8acTrrO_gDunYz4X_GFv70exsT_ShjGAIgng8uZtksByHqKejTZDcXkvggYhnAGPal07"
                      "Xl5K_P2VDE75DPalu5RlHSDCmRVpkXTe0YfyT09-DzRxDDghYRVhgs6qwmfzvHiJTYTtoGnAC6"
                      "TLi_JR5k2zu4FDEu01W6MuYt4Oxn1BREtkm58rr1WtEPjuByUWV95FvCE9ux1p61TzOuG_vBD2"
                      "zbclP5GIA-ry9cbnU";
    const char *dot = strchr(jwt, '.');
    dot = strchr(dot + 1, '.');

    // no default CAs
    tls_context *tls = default_tls_context("", 0);
    verify_ctx vtx;
    vtx.tls = tls;
    vtx.data = jwt;
    vtx.datalen = dot - jwt;
    tlsuv_base64url_decode(dot + 1, &vtx.sig, &vtx.siglen);

    tls->set_cert_verify(tls, cert_verify, &vtx);
    tlsuv_http_init(test.loop, &clt, "https://demo4.ziti.netfoundry.io");
    tlsuv_http_set_ssl(&clt, tls);

    tlsuv_http_header(&clt, "Connection", "close");

    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/version", resp_capture_cb, &resp);

    test.run();

    CHECK(resp.code == 200);

    tlsuv_http_close(&clt, nullptr);

    free(vtx.sig);
    tls->free_ctx(tls);
}

TEST_CASE("TLS to IP address", "[http]") {
    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);

    tlsuv_http_init(test.loop, &clt, "https://1.1.1.1");
    tlsuv_http_header(&clt, "Connection", "close");

    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/dns-query?name=google.com&type=AAAA", resp_capture_cb, &resp);
    tlsuv_http_req_header(req, "Accept", "application/dns-json");

    test.run();

    CHECK(resp.code == 200);
    CHECK(resp.headers["Content-Type"] == "application/dns-json");
    CHECK_THAT(resp.body, Catch::Matchers::ContainsSubstring("\"Answer\":[{\"name\":\"google.com\""));
    tlsuv_http_close(&clt, nullptr);
}

TEST_CASE("connect timeout", "[http]") {
    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);
    resp_capture resp2(resp_body_cb);

    uv_gettimeofday(&resp.resp_start);

    tlsuv_http_init(test.loop, &clt, "https://10.1.1.1"); // not reachable
    tlsuv_http_connect_timeout(&clt, 10); // should be short enough
    tlsuv_http_header(&clt, "Connection", "close");

    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/json", resp_capture_cb, &resp);
    tlsuv_http_req_t *req2 = tlsuv_http_req(&clt, "GET", "/json", resp_capture_cb, &resp2);

    tlsuv_http_req_header(req, "Accept", "application/json");
    tlsuv_http_req_header(req2, "Accept", "application/json");

    test.run();

    CHECK(resp.code == UV_ETIMEDOUT);
    CHECK(resp2.code == UV_ETIMEDOUT);
    tlsuv_http_close(&clt, nullptr);
}



TEST_CASE("HTTP gzip", "[http]") {
    UvLoopTest test;

    auto clt = new tlsuv_http_t;
    resp_capture resp(resp_body_cb);
    tlsuv_http_init(test.loop, clt, testServerURL("https").c_str());
    tlsuv_http_set_ssl(clt, testServerTLS());
    tlsuv_http_req_t *req = tlsuv_http_req(clt, "GET", "/gzip", resp_capture_cb, &resp);

    test.run();

    CHECK(resp.code == HTTP_STATUS_OK);
    CHECK_THAT(resp.http_version, Equals("1.1"));
    CHECK_THAT(resp.status, Equals("OK"));
    CHECK_THAT(resp.headers["Content-Type"], StartsWith("application/json"));
    CHECK(resp.headers["Content-Encoding"] == "gzip");
    CHECK_THAT(resp.body, Catch::Matchers::ContainsSubstring(R"("Accept-Encoding")") && Catch::Matchers::ContainsSubstring("gzip, deflate"));
    CHECK(resp.resp_body_end_called == 1);

    std::cout << resp.req_body << std::endl;

    tlsuv_http_close(clt, [](tlsuv_http_t *c) {
        delete c;
    });
}

TEST_CASE("HTTP deflate", "[http]") {
    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);
    tlsuv_http_init(test.loop, &clt, testServerURL("https").c_str());
    tlsuv_http_set_ssl(&clt, testServerTLS());
    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "/deflate", resp_capture_cb, &resp);

    test.run();

    CHECK(resp.code == HTTP_STATUS_OK);
    CHECK_THAT(resp.http_version, Equals("1.1"));
    CHECK_THAT(resp.status, Equals("OK"));
    CHECK_THAT(resp.headers["Content-Type"], StartsWith("application/json"));
    CHECK(resp.headers["Content-Encoding"] == "deflate");
    CHECK_THAT(resp.body, Catch::Matchers::ContainsSubstring(R"("Accept-Encoding")") &&
                          Catch::Matchers::ContainsSubstring("gzip, deflate"));
    CHECK(resp.resp_body_end_called == 1);


    std::cout << resp.req_body << std::endl;

    tlsuv_http_close(&clt, nullptr);
}

TEST_CASE("URL encode", "[http]") {
    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);

    tlsuv_http_init(test.loop, &clt, "https://localhost:8443/anything");
    tlsuv_http_set_ssl(&clt, testServerTLS());
    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "GET", "", resp_capture_cb, &resp);
    tlsuv_http_pair q = {
            .name = "query",
            .value = "this is a <test>!"
    };
    tlsuv_http_req_query(req, 1, &q);

    test.run();

    CHECK(resp.code == HTTP_STATUS_OK);
    CHECK_THAT(resp.http_version, Equals("1.1"));
    CHECK_THAT(resp.status, Equals("OK"));
    CHECK(resp.resp_body_end_called == 1);
    auto j = json_parse_string(resp.body.c_str());
    auto json = json_value_get_object(j);
    auto query = json_array_get_string(json_object_dotget_array(json, "args.query"), 0);
    auto url = json_object_dotget_string(json, "url");

    CHECK_THAT(query, Equals("this is a <test>!"));

    CHECK_THAT(url, Catch::Matchers::Equals("http://localhost/anything?query=this%20is%20a%20%3Ctest%3E!"));

    std::cout << resp.req_body << std::endl;

    tlsuv_http_close(&clt, nullptr);
    json_value_free(j);
}

class testdata {
public:
    testdata(): resp1(nullptr), resp2(nullptr), r1(nullptr), r2(nullptr)
    {}

    tlsuv_http_t clt;
    tlsuv_http_req_t *r1;
    tlsuv_http_req_t *r2;

    resp_capture resp1;
    resp_capture resp2;

};

TEST_CASE("form test", "[http]") {
    std::string scheme = GENERATE("http", "https");
    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);

    tlsuv_http_init(test.loop, &clt, testServerURL(scheme).c_str());
    tlsuv_http_set_ssl(&clt, testServerTLS());
    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "POST", "/post", resp_capture_cb, &resp);

    tlsuv_http_pair req_form[] = {
            {"ziti", "is awesome!"},
            {"message", "Check out https://openziti.io"},
    };
    tlsuv_http_req_form(req, 2, req_form);

    test.run();

    CHECK(resp.code == HTTP_STATUS_OK);
    CHECK_THAT(resp.http_version, Equals("1.1"));
    CHECK_THAT(resp.status, Equals("OK"));
    CHECK(resp.resp_body_end_called == 1);
    auto jval = json_parse_string(resp.body.c_str());
    auto json = json_value_get_object(jval);
    auto form = json_object_dotget_object(json, "form");
    CHECK_THAT(json_array_get_string(json_object_dotget_array(form, "ziti"), 0), Equals("is awesome!"));
    CHECK_THAT(json_array_get_string(json_object_dotget_array(form, "message"), 0), Equals("Check out https://openziti.io"));

    std::cout << resp.req_body << std::endl;

    tlsuv_http_close(&clt, nullptr);

    json_value_free(jval);
}

TEST_CASE("form test too big", "[http]") {
    std::string scheme = GENERATE("http", "https");
    UvLoopTest test;

    tlsuv_http_t clt;
    resp_capture resp(resp_body_cb);

    tlsuv_http_init(test.loop, &clt, testServerURL(scheme).c_str());
    tlsuv_http_set_ssl(&clt, testServerTLS());
    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "POST", "/post", resp_capture_cb, &resp);

    auto g = Catch::Generators::random(5,255);
    std::string blob;
    for (int i = 0; i < (16 * 1024) && g.next(); i++) {
        char c = (char)g.get();
        blob.append(&c, 1);
    }
    tlsuv_http_pair req_form[] = {
            {"ziti", "is awesome!"},
            {"message", "Check out https://openziti.io"},
            {"blob", blob.c_str()},
    };
    REQUIRE(tlsuv_http_req_form(req, 3, req_form) == UV_ENOMEM);

    test.run();

    REQUIRE(resp.code == UV_ENOMEM);
    REQUIRE(resp.status == "form data too big");

    tlsuv_http_close(&clt, nullptr);
}

TEST_CASE("test req header too big", "[http]") {
    std::string scheme = GENERATE("http", "https");

    WHEN("test " + scheme) {
        UvLoopTest test;

        tlsuv_http_t clt;
        resp_capture resp(resp_body_cb);


        tlsuv_http_init(test.loop, &clt, testServerURL(scheme).c_str());
        tlsuv_http_set_ssl(&clt, testServerTLS());
        tlsuv_http_req_t *req = tlsuv_http_req(&clt, "POST", "/post", resp_capture_cb, &resp);

        auto g = Catch::Generators::random((int) 'A', (int) 'z');
        std::string blob;
        for (int i = 0; i < (8 * 1024) && g.next(); i++) {
            char c = (char) g.get();
            blob.append(&c, 1);
        }
        tlsuv_http_req_header(req, "X-LargeHeader", blob.c_str());

        test.run();

        REQUIRE(resp.code == UV_ENOMEM);
        REQUIRE(resp.status == "request header too big");

        tlsuv_http_close(&clt, nullptr);
    }
}

TEST_CASE("test request cancel", "[http]") {
    UvLoopTest test;

    testdata td;

    tlsuv_http_init(test.loop, &td.clt, testServerURL("https").c_str());
    tlsuv_http_set_ssl(&td.clt, testServerTLS());

    auto r1_cb = [](tlsuv_http_resp_t *resp, void *p) {
        auto t = (testdata*)p;
        tlsuv_http_req_cancel(&t->clt, t->r2);
        resp_capture_cb(resp, &t->resp1);
    };

    auto r2_cb = [](tlsuv_http_resp_t *resp, void *t) {
        auto _td = (testdata*)t;
        resp_capture_cb(resp, &_td->resp2);
    };

    td.r1 = tlsuv_http_req(&td.clt, "GET", "/json", r1_cb, &td);

    td.r2 = tlsuv_http_req(&td.clt, "GET", "/anything", r2_cb, &td);

    test.run();

    CHECK(td.resp1.code == HTTP_STATUS_OK);
    CHECK(td.resp2.code == UV_ECANCELED);

    tlsuv_http_close(&td.clt, nullptr);
}

#define TEST_FIELD(f, VAL)                              \
    if ((VAL) == nullptr) {                             \
        CHECK(url.f == nullptr);                        \
        CHECK(url.f##_len == 0);                        \
    } else {                                            \
        CHECK(url.f##_len == strlen(VAL));              \
        CHECK(strncmp(url.f, (VAL), url.f##_len) == 0); \
    }

static void URL_TEST(const char *s, int RES, const char *SCHEME, const char *HOST, int PORT, const char *PATH, const char *QUERY) {
    tlsuv_url_s url = {0};
    CHECK(tlsuv_parse_url(&url, s) == RES);
    if ((RES) == 0) {
        TEST_FIELD(scheme, SCHEME);
        TEST_FIELD(hostname, HOST);
        TEST_FIELD(path, PATH);
        TEST_FIELD(query, QUERY);
        CHECK(url.port == (PORT));
    }
}

TEST_CASE("url parse", "[http]") {
    URL_TEST("wss://websocket.org/echo?foo=bar", 0, "wss", "websocket.org", 0, "/echo", "foo=bar");
    URL_TEST("wss://websocket.org:443/echo?foo=bar", 0, "wss", "websocket.org", 443, "/echo", "foo=bar");
    URL_TEST("wss://websocket.org/echo", 0, "wss", "websocket.org", 0, "/echo", nullptr);
    URL_TEST("websocket.org:443/echo", 0, nullptr, "websocket.org", 443, "/echo", nullptr);
    URL_TEST("file:///echo.txt", 0, "file", nullptr, 0, "/echo.txt", nullptr);
    URL_TEST("/path/only/echo.txt", 0, nullptr, nullptr, 0, "/path/only/echo.txt", nullptr);
    URL_TEST(":443/echo", -1, nullptr, "websocket.org", 443, "/echo", nullptr);
    URL_TEST("websocket.org:443echo", -1, nullptr, "websocket.org", 443, "/echo", nullptr);
    URL_TEST("websocket.org:443443/echo", -1, nullptr, "websocket.org", 443, "/echo", nullptr);
}

TEST_CASE("url parse auth", "[http]") {
    tlsuv_url_s url;

    CHECK(tlsuv_parse_url(&url, "https://foo:passwd@host:3128") == 0);
    CHECK(url.username != nullptr);
    CHECK(url.username_len == strlen("foo"));
    CHECK(strncmp("foo", url.username, url.username_len) == 0);

    CHECK(url.password != nullptr);
    CHECK(url.password_len == strlen("passwd"));
    CHECK(strncmp("passwd", url.password, url.password_len) == 0);

    CHECK(url.hostname != nullptr);
    CHECK(url.hostname_len == strlen("host"));
    CHECK(strncmp("host", url.hostname, url.hostname_len) == 0);


    CHECK(tlsuv_parse_url(&url, "https://bar@host:3128") == 0);
    CHECK(url.username != nullptr);
    CHECK(url.username_len == strlen("bar"));
    CHECK(strncmp("bar", url.username, url.username_len) == 0);

    CHECK(url.password == nullptr);
    CHECK(url.password_len == 0);

    CHECK(url.hostname != nullptr);
    CHECK(url.hostname_len == strlen("host"));
    CHECK(strncmp("host", url.hostname, url.hostname_len) == 0);
}
