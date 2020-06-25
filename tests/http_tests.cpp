/*
Copyright 2019-2020 NetFoundry, Inc.

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

#include "catch.hpp"

#include <uv_mbed/um_http.h>
#include <uv_mbed/tls_engine.h>
#include <map>
#include <string>
#include <cstring>

using namespace std;
using namespace Catch::Matchers;

class resp_capture {
public:

    um_http_body_cb body_cb;

    resp_capture(um_http_body_cb cb) : body_cb(cb) {}

    resp_capture() : resp_capture(nullptr) {}

    string http_version;
    ssize_t code{};
    string status;
    map<string, string> headers;

    string body;
    string req_body;

    bool resp_body_end_called{};
    bool req_body_cb_called{};

    uv_timeval64_t resp_endtime{};
};

void req_body_cb(um_http_req_t *req, const char *chunk, ssize_t status) {
    auto rc = static_cast<resp_capture *>(req->data);
    rc->req_body.append(chunk);
    rc->req_body_cb_called = true;
}

void resp_body_cb(um_http_req_t *req, const char *chunk, ssize_t len) {
    auto rc = static_cast<resp_capture *>(req->data);

    if (len > 0) {
        rc->body.append(chunk, len);
    }
    else if (len == UV_EOF) {
        rc->resp_body_end_called = true;
    }
}

void resp_capture_cb(um_http_resp_t *resp, void *data) {
    auto rc = static_cast<resp_capture *>(data);
    rc->code = resp->code;
    rc->status = resp->status ? resp->status : "no status";
    rc->http_version = resp->http_version;

    um_http_hdr *h;
    for (h = resp->headers; h != NULL && h->name != nullptr; h++) {
        rc->headers[h->name] = h->value;
    }

    resp->body_cb = rc->body_cb;
}

void test_timeout(uv_timer_t *t) {
    printf("timeout stopping loop\n");
    uv_stop(t->loop);
}

static string part2("this is part 2");

void send_part2(uv_timer_t *t) {
    auto req = static_cast<um_http_req_t *>(t->data);
    um_http_req_data(req, part2.c_str(), part2.length(), req_body_cb);
    um_http_req_end(req);

    uv_close((uv_handle_t *) (t), nullptr);

}

TEST_CASE("http_tests", "[http]") {

    auto scheme = GENERATE(as < std::string > {}, "http", "https");

    uv_loop_t *loop = uv_default_loop();
    um_http_t clt;
    uv_timer_t *timer = static_cast<uv_timer_t *>(malloc(sizeof(uv_timer_t)));
    uv_timer_init(loop, timer);
    uv_unref((uv_handle_t *) timer);
    uv_timer_start(timer, test_timeout, 5000, 0);
    resp_capture resp(resp_body_cb);

    WHEN("resolve failure " << scheme) {
        um_http_init(loop, &clt, (scheme + "://not.a.real.host").c_str());
        um_http_req_t *req = um_http_req(&clt, "GET", "/", resp_capture_cb, &resp);

        uv_run(loop, UV_RUN_DEFAULT);

        REQUIRE(resp.code == UV_EAI_NONAME);
    }

    WHEN(scheme << " connect failure") {
        string url = scheme + "://localhost:1222";
        um_http_init(loop, &clt, url.c_str());
        um_http_req_t *req = um_http_req(&clt, "GET", "/", resp_capture_cb, &resp);

        uv_run(loop, UV_RUN_DEFAULT);

        REQUIRE(resp.code == UV_ECONNREFUSED);
    }

    WHEN(scheme << " redirect google.com ") {
        um_http_init(loop, &clt, (scheme + "://google.com").c_str());
        um_http_req_t *req = um_http_req(&clt, "GET", "/", resp_capture_cb, &resp);

        uv_run(loop, UV_RUN_DEFAULT);

        REQUIRE(resp.code == HTTP_STATUS_MOVED_PERMANENTLY);
        REQUIRE_THAT(resp.headers["Location"], Equals(scheme + "://www.google.com/"));
        REQUIRE_THAT(resp.headers["Content-Type"], Catch::Matchers::StartsWith("text/html"));
    }

//    WHEN(scheme << " redirect") {
//        um_http_init(loop, &clt, "http://httpbin.org");
//        um_http_req_t *req = um_http_req(&clt, "GET", "/redirect/2", resp_capture_cb, &resp);
//
//        uv_run(loop, UV_RUN_DEFAULT);
//
//        REQUIRE(resp.code == HTTP_STATUS_FOUND);
//        REQUIRE(resp.headers["Location"] == "/relative-redirect/1");
//        REQUIRE_THAT(resp.headers["Content-Type"], Catch::Matchers::StartsWith("text/html"));
//    }

    WHEN(scheme << " body GET") {
        um_http_init(loop, &clt, "http://httpbin.org");
        um_http_req_t *req = um_http_req(&clt, "GET", "/get", resp_capture_cb, &resp);

        uv_run(loop, UV_RUN_DEFAULT);

        REQUIRE(resp.code == HTTP_STATUS_OK);
        REQUIRE(resp.resp_body_end_called);
        REQUIRE_THAT(resp.headers["Content-Type"], Catch::Matchers::StartsWith("application/json"));
        int body_len = resp.body.size();
        int content_len = atoi(resp.headers["Content-Length"].c_str());
        REQUIRE(body_len == content_len);
    }

    WHEN(scheme << " send headers") {
        um_http_init(loop, &clt, "http://httpbin.org");
        um_http_header(&clt, "Client-Header", "This is client header");

        um_http_req_t *req = um_http_req(&clt, "GET", "/get", resp_capture_cb, &resp);
        um_http_req_header(req, "Request-Header", "this is request header");

        resp_capture resp2(resp_body_cb);
        um_http_req_t *req2 = um_http_req(&clt, "GET", "/get", resp_capture_cb, &resp2);

        uv_run(loop, UV_RUN_DEFAULT);

        REQUIRE(resp.code == HTTP_STATUS_OK);
        REQUIRE(resp2.code == HTTP_STATUS_OK);
        REQUIRE_THAT(resp.body, Contains("\"Client-Header\": \"This is client header\""));
        REQUIRE_THAT(resp2.body, Contains("\"Client-Header\": \"This is client header\""));

        REQUIRE_THAT(resp.body, Contains("\"Request-Header\": \"this is request header\""));
        REQUIRE_THAT(resp2.body, !Contains("\"Request-Header\": \"this is request header\""));
    }

    WHEN(scheme << " POST body") {
        um_http_init(loop, &clt, (scheme + "://httpbin.org").c_str());
        um_http_req_t *req = um_http_req(&clt, "POST", "/post", resp_capture_cb, &resp);
        string req_body("this is a test message");
        um_http_req_data(req, req_body.c_str(), req_body.length(), req_body_cb);

        uv_run(loop, UV_RUN_DEFAULT);

        THEN("request should complete") {
            REQUIRE(resp.code == HTTP_STATUS_OK);
            REQUIRE(resp.resp_body_end_called);
        }
        REQUIRE_THAT(resp.headers["Content-Type"], Catch::Matchers::StartsWith("application/json"));
        int body_len = resp.body.size();
        int content_len = atoi(resp.headers["Content-Length"].c_str());
        REQUIRE(body_len == content_len);

        REQUIRE_THAT(resp.body, Contains(req_body));
        REQUIRE(resp.req_body_cb_called);
    }


    WHEN(scheme << " posting chunked") {
        um_http_init(loop, &clt, (scheme + "://httpbin.org").c_str());
        um_http_req_t *req = um_http_req(&clt, "POST", "/post", resp_capture_cb, &resp);
        um_http_req_header(req, "Transfer-Encoding", "chunked");

        string part1("this is part1");
        um_http_req_data(req, part1.c_str(), part1.length(), req_body_cb);

        uv_timer_t p2_timer;
        uv_timer_init(loop, &p2_timer);
        p2_timer.data = req;
        uv_timer_start(&p2_timer, send_part2, 1000, 0);

        uv_run(loop, UV_RUN_DEFAULT);

        THEN("request should complete") {
            REQUIRE(resp.code == HTTP_STATUS_OK);
            REQUIRE_THAT(resp.headers["Content-Type"], Catch::Matchers::StartsWith("application/json"));
            REQUIRE(resp.resp_body_end_called);
        }
        int body_len = resp.body.size();
        int content_len = atoi(resp.headers["Content-Length"].c_str());

        THEN("response body size matches") {
            REQUIRE(body_len == content_len);
        }

        THEN("request sent completely") {
            REQUIRE_THAT(resp.req_body, Equals(part1 + part2));
            REQUIRE(resp.req_body_cb_called);
        }
    }
    um_http_close(&clt);
    uv_timer_stop(timer);

    uv_close(reinterpret_cast<uv_handle_t *>(timer), [](uv_handle_t* h){ free(h); });

    // need to run loop one to process all closing handles
    uv_run(loop, UV_RUN_ONCE);
}

TEST_CASE("client_cert_test","[http]") {
    uv_loop_t *loop = uv_loop_new();
    um_http_t clt;
    resp_capture resp(resp_body_cb);
    um_http_init(loop, &clt, "https://client.badssl.com");
    um_http_req_t *req = um_http_req(&clt, "GET", "/", resp_capture_cb, &resp);

    WHEN("client cert NOT set") {

        uv_run(loop, UV_RUN_DEFAULT);

        THEN("request should be bad") {
            REQUIRE(resp.code == HTTP_STATUS_BAD_REQUEST);
            REQUIRE(resp.resp_body_end_called);
        }
        int body_len = resp.body.size();
        int content_len = atoi(resp.headers["Content-Length"].c_str());

        AND_THEN("response body size matches") {
            REQUIRE(body_len == content_len);
        }
    }

    WHEN("client cert set") {
        tls_context *tls = default_tls_context(nullptr, 0);

        // client cert downloaded from https://badssl.com/download/
        const char *cert = "-----BEGIN CERTIFICATE-----\n"
                       "MIIEqDCCApCgAwIBAgIUK5Ns4y2CzosB/ZoFlaxjZqoBTIIwDQYJKoZIhvcNAQEL\n"
                       "BQAwfjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\n"
                       "DVNhbiBGcmFuY2lzY28xDzANBgNVBAoMBkJhZFNTTDExMC8GA1UEAwwoQmFkU1NM\n"
                       "IENsaWVudCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xOTExMjcwMDE5\n"
                       "NTdaFw0yMTExMjYwMDE5NTdaMG8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxp\n"
                       "Zm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQKDAZCYWRTU0wx\n"
                       "IjAgBgNVBAMMGUJhZFNTTCBDbGllbnQgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3\n"
                       "DQEBAQUAA4IBDwAwggEKAoIBAQDHN18R6x5Oz+u6SOXLoxIscz5GHR6cDcCLgyPa\n"
                       "x2XfXHdJs+h6fTy61WGM+aXEhR2SIwbj5997s34m0MsbvkJrFmn0LHK1fuTLCihE\n"
                       "EmxGdCGZA9xrwxFYAkEjP7D8v7cAWRMipYF/JP7VU7xNUo+QSkZ0sOi9k6bNkABK\n"
                       "L3+yP6PqAzsBoKIN5lN/YRLrppsDmk6nrRDo4R3CD+8JQl9quEoOmL22Pc/qpOjL\n"
                       "1jgOIFSE5y3gwbzDlfCYoAL5V+by1vu0yJShTTK8oo5wvphcFfEHaQ9w5jFg2htd\n"
                       "q99UER3BKuNDuL+zejqGQZCWb0Xsk8S5WBuX8l3Brrg5giqNAgMBAAGjLTArMAkG\n"
                       "A1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgeAMAsGA1UdDwQEAwIF4DANBgkqhkiG\n"
                       "9w0BAQsFAAOCAgEAZBauLzFSOijkDadcippr9C6laHebb0oRS54xAV70E9k5GxfR\n"
                       "/E2EMuQ8X+miRUMXxKquffcDsSxzo2ac0flw94hDx3B6vJIYvsQx9Lzo95Im0DdT\n"
                       "DkHFXhTlv2kjQwFVnEsWYwyGpHMTjanvNkO7sBP9p1bN1qTE3QAeyMZNKWJk5xPl\n"
                       "U298ERar6tl3Z2Cl8mO6yLhrq4ba6iPGw08SENxzuAJW+n8r0rq7EU+bMg5spgT1\n"
                       "CxExzG8Bb0f98ZXMklpYFogkcuH4OUOFyRodotrotm3iRbuvZNk0Zz7N5n1oLTPl\n"
                       "bGPMwBcqaGXvK62NlaRkwjnbkPM4MYvREM0bbAgZD2GHyANBTso8bdWvhLvmoSjs\n"
                       "FSqJUJp17AZ0x/ELWZd69v2zKW9UdPmw0evyVR19elh/7dmtF6wbewc4N4jxQnTq\n"
                       "IItuhIWKWB9edgJz65uZ9ubQWjXoa+9CuWcV/1KxuKCbLHdZXiboLrKm4S1WmMYW\n"
                       "d0sJm95H9mJzcLyhLF7iX2kK6K9ug1y02YCVXBC9WGZc2x6GMS7lDkXSkJFy3EWh\n"
                       "CmfxkmFGwOgwKt3Jd1pF9ftcSEMhu4WcMgxi9vZr9OdkJLxmk033sVKI/hnkPaHw\n"
                       "g0Y2YBH5v0xmi8sYU7weOcwynkjZARpUltBUQ0pWCF5uJsEB8uE8PPDD3c4=\n"
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
        tls->api->set_own_cert(tls->ctx, cert, strlen(cert) + 1, key, strlen(key) + 1);
        um_http_set_ssl(&clt, tls);

        uv_run(loop, UV_RUN_DEFAULT);

        THEN("request should complete") {
            REQUIRE(resp.code == HTTP_STATUS_OK);
            REQUIRE(resp.resp_body_end_called);
        }
        int body_len = resp.body.size();
        int content_len = atoi(resp.headers["Content-Length"].c_str());

        THEN("response body size matches") {
            REQUIRE(body_len == content_len);
        }
        tls->api->free_ctx(tls);
    }

    um_http_close(&clt);
    uv_run(loop, UV_RUN_ONCE);
    uv_loop_close(loop);
    free(loop);
}

const int ONE_SECOND = 1000000;

static long duration(uv_timeval64_t &start, uv_timeval64_t &stop) {
    return stop.tv_sec * ONE_SECOND + stop.tv_usec - start.tv_sec * ONE_SECOND - start.tv_usec;
}

TEST_CASE("client_idle_test","[http]") {
    uv_loop_t *loop = uv_loop_new();
    um_http_t clt;

    um_http_body_cb bodyCb = [](um_http_req_t *req, const char *b, ssize_t len) {
        auto r = static_cast<resp_capture *>(req->data);

        if (len == UV_EOF) {
            uv_gettimeofday(&r->resp_endtime);
        }
    };
    resp_capture resp(bodyCb);
    um_http_init(loop, &clt, "https://httpbin.org");
    um_http_idle_keepalive(&clt, 5000);
    um_http_req_t *req = um_http_req(&clt, "GET", "/get", resp_capture_cb, &resp);

    WHEN("client idle timeout is set to 5 seconds") {
        uv_timeval64_t start;
        uv_gettimeofday(&start);
        uv_run(loop, UV_RUN_DEFAULT);
        uv_timeval64_t stop;
        uv_gettimeofday(&stop);

        THEN("request should be fast and then idle for 5 seconds") {
            CHECK(resp.code == HTTP_STATUS_OK);
            CHECK(duration(start, resp.resp_endtime) < 2 * ONE_SECOND);
            CHECK(duration(resp.resp_endtime, stop) >= 5 * ONE_SECOND);
        }

        um_http_close(&clt);
    }
    uv_run(loop, UV_RUN_ONCE);

    uv_loop_close(loop);
    free(loop);
}

// hidden test
// can't rely on server closing connection in time
TEST_CASE("server_idle_close","[.]") {
    uv_loop_t *loop = uv_default_loop();
    um_http_t clt;

    um_http_body_cb body_cb = [](um_http_req_t *req, const char *b, ssize_t len) {
        auto r = static_cast<resp_capture *>(req->data);

        if (len == UV_EOF) {
            uv_gettimeofday(&r->resp_endtime);
        }
    };
    resp_capture resp(body_cb);

    um_http_init(loop, &clt, "http://www.aptivate.org");
    um_http_idle_keepalive(&clt, -1);
    um_http_req_t *req = um_http_req(&clt, "GET", "/", resp_capture_cb, &resp);

    WHEN("client timeout is set to -1") {
        uv_timeval64_t start;
        uv_gettimeofday(&start);
        uv_run(loop, UV_RUN_DEFAULT);
        uv_timeval64_t stop;
        uv_gettimeofday(&stop);

        THEN("request should be fast and then idle until server disconnects") {
            REQUIRE(resp.code == HTTP_STATUS_OK);
            REQUIRE(duration(start, resp.resp_endtime) < ONE_SECOND);
            auto test_duration = duration(start, stop);
            REQUIRE(test_duration >= 5 * ONE_SECOND);
            REQUIRE(test_duration < 30 * ONE_SECOND);
        }

        um_http_close(&clt);
    }
    uv_run(loop, UV_RUN_ONCE);

    uv_loop_close(loop);
    free(loop);
}

extern "C" void uv_mbed_set_debug(int level, FILE *out);

TEST_CASE("basic_test", "[http]") {
    uv_loop_t *loop = uv_loop_new();
    um_http_t clt;
    resp_capture resp(resp_body_cb);
    um_http_init(loop, &clt, "http://httpbin.org");
    um_http_req_t *req = um_http_req(&clt, "GET", "/json", resp_capture_cb, &resp);

    WHEN("client idle timeout is set to 5 seconds") {
        uv_run(loop, UV_RUN_DEFAULT);

        THEN("request should be fast and then idle for 5 seconds") {
            CHECK(resp.code == HTTP_STATUS_OK);
            CHECK_THAT(resp.http_version, Equals("1.1"));
            CHECK_THAT(resp.status, Equals("OK"));

            CHECK_THAT(resp.headers["Content-Type"], Equals("application/json"));
        }

        um_http_close(&clt);
    }
    uv_run(loop, UV_RUN_ONCE);

    uv_loop_close(loop);
    free(loop);
}


TEST_CASE("conten_length_test", "[http]") {
    uv_loop_t *loop = uv_loop_new();
    um_http_t clt;
    resp_capture resp(resp_body_cb);
    um_http_init(loop, &clt, "http://httpbin.org");
    um_http_req_t *req = um_http_req(&clt, "POST", "/json", resp_capture_cb, &resp);

    WHEN("set Content-Length first") {
        int rc = um_http_req_header(req, "Content-Length", "20");
        CHECK(rc == 0);
        CHECK(req->req_body_size == 20);
        CHECK(!req->req_chunked);

        rc = um_http_req_header(req, "Transfer-Encoding", "chunked");
        CHECK(rc == UV_EINVAL);
        CHECK(req->req_body_size == 20);
        CHECK(!req->req_chunked);
    }

    WHEN("set Chunked first") {
        int rc = um_http_req_header(req, "Transfer-Encoding", "chunked");
        CHECK(rc == 0);
        CHECK(req->req_body_size == -1);
        CHECK(req->req_chunked);

        rc = um_http_req_header(req, "Content-Length", "20");
        CHECK(rc == UV_EINVAL);
        CHECK(req->req_body_size == -1);
        CHECK(req->req_chunked);
    }

    um_http_close(&clt);
    uv_run(loop, UV_RUN_ONCE);

    uv_loop_close(loop);
    free(loop);
}
