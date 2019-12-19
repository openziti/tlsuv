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

#include "catch.hpp"

#include <uv_mbed/um_http.h>
#include <map>
#include <string>

using namespace std;
using namespace Catch::Matchers;

struct resp_capture {
    ssize_t code;
    map<string, string> headers;

    string body;
    string req_body;

    bool resp_body_end_called;
    bool req_body_cb_called;
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

void resp_capture_cb(um_http_req_t *req, int code, um_header_list *headers) {
    auto rc = static_cast<resp_capture *>(req->data);
    rc->code = code;

    if (headers != nullptr) {
        um_http_hdr *h;
        LIST_FOREACH(h, headers, _next) {
            rc->headers[h->name] = h->value;
        }
    }
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

    uv_close(reinterpret_cast<uv_handle_t *>(t), nullptr);

}

TEST_CASE("http_tests", "[http]") {

    auto scheme = GENERATE(as < std::string > {}, "http", "https");

    uv_loop_t *loop = uv_default_loop();
    um_http_t clt;
    auto *timer = new uv_timer_t;
    uv_timer_init(loop, timer);
    uv_unref((uv_handle_t *) timer);
    uv_timer_start(timer, test_timeout, 5000, 0);
    struct resp_capture resp = {0};

    WHEN("resolve failure " << scheme) {
        um_http_init(loop, &clt, (scheme + "://not.a.real.host").c_str());
        um_http_req_t *req = um_http_req(&clt, "GET", "/");
        req->data = &resp;
        req->resp_cb = resp_capture_cb;

        uv_run(loop, UV_RUN_DEFAULT);

        REQUIRE(resp.code == UV_EAI_NONAME);
        um_http_close(&clt);
        uv_timer_stop(timer);
        free(timer);
    }

    WHEN(scheme << " connect failure") {
        string url = scheme + "://localhost:1222";
        um_http_init(loop, &clt, url.c_str());
        um_http_req_t *req = um_http_req(&clt, "GET", "/");
        req->data = &resp;
        req->resp_cb = resp_capture_cb;

        uv_run(loop, UV_RUN_DEFAULT);

        REQUIRE(resp.code == UV_ECONNREFUSED);
        um_http_close(&clt);
        uv_timer_stop(timer);
        free(timer);
    }

    WHEN(scheme << " redirect google.com ") {
        um_http_init(loop, &clt, (scheme + "://google.com").c_str());
        um_http_req_t *req = um_http_req(&clt, "GET", "/");
        req->data = &resp;
        req->resp_cb = resp_capture_cb;

        uv_run(loop, UV_RUN_DEFAULT);

        REQUIRE(resp.code == HTTP_STATUS_MOVED_PERMANENTLY);
        REQUIRE_THAT(resp.headers["Location"], Equals(scheme + "://www.google.com/"));
        REQUIRE_THAT(resp.headers["Content-Type"], Catch::Matchers::StartsWith("text/html"));
        um_http_close(&clt);
        uv_timer_stop(timer);
        free(timer);
    }

    WHEN(scheme << " redirect") {
        um_http_init(loop, &clt, "http://httpbin.org");
        um_http_req_t *req = um_http_req(&clt, "GET", "/redirect/2");
        req->data = &resp;
        req->resp_cb = resp_capture_cb;

        uv_run(loop, UV_RUN_DEFAULT);

        REQUIRE(resp.code == HTTP_STATUS_FOUND);
        REQUIRE(resp.headers["Location"] == "/relative-redirect/1");
        REQUIRE_THAT(resp.headers["Content-Type"], Catch::Matchers::StartsWith("text/html"));
        um_http_close(&clt);
        uv_timer_stop(timer);
        free(timer);
    }

    WHEN(scheme << " body GET") {
        um_http_init(loop, &clt, "http://httpbin.org");
        um_http_req_t *req = um_http_req(&clt, "GET", "/get");
        req->data = &resp;
        req->resp_cb = resp_capture_cb;
        req->body_cb = resp_body_cb;

        uv_run(loop, UV_RUN_DEFAULT);

        REQUIRE(resp.code == HTTP_STATUS_OK);
        REQUIRE(resp.resp_body_end_called);
        REQUIRE_THAT(resp.headers["Content-Type"], Catch::Matchers::StartsWith("application/json"));
        int body_len = resp.body.size();
        int content_len = atoi(resp.headers["Content-Length"].c_str());
        REQUIRE(body_len == content_len);
        uv_timer_stop(timer);
        um_http_close(&clt);
        free(timer);

    }

    WHEN(scheme << " send headers") {
        um_http_init(loop, &clt, "http://httpbin.org");
        um_http_header(&clt, "Client-Header", "This is client header");

        um_http_req_t *req = um_http_req(&clt, "GET", "/get");
        um_http_req_header(req, "Request-Header", "this is request header");
        req->data = &resp;
        req->resp_cb = resp_capture_cb;
        req->body_cb = resp_body_cb;

        struct resp_capture resp2 = {0};
        um_http_req_t *req2 = um_http_req(&clt, "GET", "/get");
        req2->data = &resp2;
        req2->resp_cb = resp_capture_cb;
        req2->body_cb = resp_body_cb;

        uv_run(loop, UV_RUN_DEFAULT);

        REQUIRE(resp.code == HTTP_STATUS_OK);
        REQUIRE(resp2.code == HTTP_STATUS_OK);
        REQUIRE_THAT(resp.body, Contains("\"Client-Header\": \"This is client header\""));
        REQUIRE_THAT(resp2.body, Contains("\"Client-Header\": \"This is client header\""));

        REQUIRE_THAT(resp.body, Contains("\"Request-Header\": \"this is request header\""));
        REQUIRE_THAT(resp2.body, !Contains("\"Request-Header\": \"this is request header\""));

        um_http_close(&clt);
        uv_timer_stop(timer);
        free(timer);
    }

    WHEN(scheme << " POST body") {
        um_http_init(loop, &clt, (scheme + "://httpbin.org").c_str());
        um_http_req_t *req = um_http_req(&clt, "POST", "/post");
        req->data = &resp;
        req->resp_cb = resp_capture_cb;
        req->body_cb = resp_body_cb;
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
        um_http_close(&clt);
        uv_timer_stop(timer);
        free(timer);
    }


    WHEN(scheme << " posting chunked") {
        um_http_init(loop, &clt, (scheme + "://httpbin.org").c_str());
        um_http_req_t *req = um_http_req(&clt, "POST", "/post");
        um_http_req_header(req, "Transfer-Encoding", "chunked");

        req->data = &resp;
        req->resp_cb = resp_capture_cb;
        req->body_cb = resp_body_cb;
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
        um_http_close(&clt);
        uv_timer_stop(timer);
        free(timer);
    }
}
