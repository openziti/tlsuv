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

// tests for HTTP clients running over a caller-supplied source link (tlsuv_src_t)

#include <catch2/catch_all.hpp>
#include "fixtures.h"
#include "http_capture.h"

#include <tlsuv/http.h>
#include <tlsuv/src_t.h>
#include <uv.h>
#include <uv_link_t.h>

#if _WIN32
#include <ws2tcpip.h>
#else
#include <netdb.h>
#endif

// minimal tlsuv_src_t over a plain TCP connection, so HTTPS goes through tls_link
// (the set_io engine path) instead of tlsuv_stream_t
struct tcp_src {
    tlsuv_SRC_FIELDS
    uv_tcp_t tcp;
    uv_link_source_t source;
    uv_connect_t conn_req;
};

static int tcp_src_connect(tlsuv_src_t *sl, const char *host, const char *port,
                           tlsuv_src_connect_cb cb, void *ctx) {
    auto src = (tcp_src *) sl;
    src->connect_cb = cb;
    src->connect_ctx = ctx;

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *ai = nullptr;
    if (getaddrinfo(host, port, &hints, &ai) != 0) {
        return UV_EAI_NONAME;
    }

    uv_tcp_init(src->loop, &src->tcp);
    src->conn_req.data = src;
    int rc = uv_tcp_connect(&src->conn_req, &src->tcp, ai->ai_addr, [](uv_connect_t *r, int status) {
        auto src = (tcp_src *) r->data;
        if (status == 0) {
            uv_link_source_init(&src->source, (uv_stream_t *) &src->tcp);
            src->link = (uv_link_t *) &src->source;
        }
        src->connect_cb((tlsuv_src_t *) src, status, src->connect_ctx);
    });
    freeaddrinfo(ai);
    return rc;
}

static void tcp_src_release(tlsuv_src_t *sl) {
    auto src = (tcp_src *) sl;
    // closing the source link already closes the stream
    if (!uv_is_closing((uv_handle_t *) &src->tcp)) {
        uv_close((uv_handle_t *) &src->tcp, nullptr);
    }
}

TEST_CASE("https over custom src", "[http]") {
    UvLoopTest test;

    tcp_src src{};
    src.loop = test.loop;
    src.connect = tcp_src_connect;
    src.release = tcp_src_release;
    src.cancel = [](tlsuv_src_t *) {};

    tlsuv_http_t clt{};
    tlsuv_http_init_with_src(test.loop, &clt, testServerURL("https").c_str(), (tlsuv_src_t *) &src);
    tlsuv_http_set_ssl(&clt, testServerTLS());

    // small response, then a larger one on the same connection: the latter takes
    // several TLS records and (with async engines) several wakeups to deliver
    // note: not "small" -- windows headers #define small char
    resp_capture json_resp(resp_body_cb);
    resp_capture bytes_resp(resp_body_cb);
    tlsuv_http_req(&clt, "GET", "/json", resp_capture_cb, &json_resp);
    tlsuv_http_req(&clt, "GET", "/bytes/100000", resp_capture_cb, &bytes_resp);

    // resp_capture starts with code = -666, so wait for the body only (the fixture timeout bounds a hang)
    test.run(UNTIL(bytes_resp.resp_body_end_called));

    CHECK(json_resp.code == HTTP_STATUS_OK);
    CHECK(json_resp.resp_body_end_called);
    CHECK_THAT(json_resp.headers["Content-Type"], Catch::Matchers::StartsWith("application/json"));

    REQUIRE(bytes_resp.code == HTTP_STATUS_OK);
    CHECK(bytes_resp.resp_body_end_called);
    CHECK(bytes_resp.body.size() == 100000);

    tlsuv_http_close(&clt, nullptr);
    test.run();
}
