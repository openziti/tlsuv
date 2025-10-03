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

#include <catch2/catch_all.hpp>

#include <tlsuv/connector.h>

#include "fixtures.h"
#include "tlsuv/tlsuv.h"

#if _WIN32
#include <winsock.h>
#else
#include <unistd.h>
#endif

TEST_CASE_METHOD(UvLoopTest, "default connect fail", "[connector]") {
    auto connector = tlsuv_global_connector();

    struct result_s {
        bool called;
        int err;
        uv_os_sock_t sock;
    } result = {false, 0,0};

    auto cr = connector->connect(loop, connector, "127.0.0.1", "7553",
                                 [](uv_os_sock_t s, int err, void *ctx) {
                                     auto r = (result_s *) (ctx);
                                     r->called = true;
                                     r->sock = s;
                                     r->err = err;
                                 }, (void *) &result);
    CHECK(cr != nullptr);

    run(UNTIL(result.called));

    INFO("error => " << uv_strerror(result.err));
    REQUIRE(result.err == UV_ECONNREFUSED);

#if _WIN32
    closesocket(result.sock);
#else
    close(result.sock);
#endif

}

TEST_CASE_METHOD(UvLoopTest, "default connector", "[connector]") {
    auto connector = tlsuv_global_connector();

    struct result_s {
        bool called;
        int err;
        uv_os_sock_t sock;
    } result = {false, 0,0};

    connector->connect(loop, connector, "localhost", "7443",
                       [](uv_os_sock_t s, int err, void *ctx){
                           auto r = (result_s *)(ctx);
                           r->called = true;
                           r->sock = s;
                           r->err = err;
    }, (void*)&result);


    run(UNTIL(result.called));

    REQUIRE(result.err == 0);
    sockaddr_in6 peer = {0};
    socklen_t peerlen = sizeof(peer);
    REQUIRE(getpeername(result.sock, (sockaddr*)&peer, &peerlen) == 0);

    if (peer.sin6_family == AF_INET) {
        char dest[256];
        uv_ip4_name((sockaddr_in*)&peer, dest, sizeof(dest));
        INFO("connected to address: " << dest << ":" << ntohs(((sockaddr_in*)&peer)->sin_port));
        REQUIRE(((sockaddr_in*)&peer)->sin_port == htons(7443));
    } else if (peer.sin6_family == AF_INET6) {
        char dest[256];
        uv_ip6_name(&peer, dest, sizeof(dest));
        INFO("connected to address: " << dest << ":" << ntohs(peer.sin6_port));
        REQUIRE(peer.sin6_port == htons(7443));
    }

#if _WIN32
    closesocket
#else
    close
#endif
         (result.sock);
}

TEST_CASE_METHOD(UvLoopTest, "proxy connector", "[connector]") {

    auto proxy_port = "13128";
    auto target_port = "7443";

    auto connector =
            tlsuv_new_proxy_connector(tlsuv_PROXY_HTTP, "127.0.0.1", proxy_port);

    struct result_s {
        bool called;
        int err;
        uv_os_sock_t sock;
    } result = {false, 0, (uv_os_sock_t)-1};

    connector->connect(loop, connector, "127.0.0.1", target_port,
                       [](uv_os_sock_t s, int err, void* ctx){
                           auto r = (result_s *) ctx;
                           r->called = true;
                           r->sock = s;
                           r->err = err;
                       }, &result);

    run(UNTIL(result.called));

    INFO("err = " << result.err << " sock = " << result.sock);
    REQUIRE(result.err == 0);
    sockaddr_in peer = {0};
    socklen_t peerlen = sizeof(peer);
    REQUIRE(getpeername(result.sock, (sockaddr*)&peer, &peerlen) == 0);
    CHECK(ntohs(peer.sin_port) == 13128);

    char dest[256];
    uv_ip4_name((sockaddr_in*)&peer, dest, sizeof(dest));
    fprintf(stderr, "dest = %s\n", dest);

#if _WIN32
    closesocket
#else
    close
#endif
         (result.sock);

    connector->free(connector);
}

TEST_CASE("base64 encode", "[connector]") {
    auto msg = "this is a long message!";

    auto len = strlen(msg);
    char b64[128];

    for (int i = 1; i <= len; i++) {
        char *b = b64;
        size_t outlen = sizeof(b64);
        CHECK(tlsuv_base64_encode((const uint8_t *)msg, i, &b, &outlen) == 0);
        INFO("base64 encode: " << std::string(b64, outlen));
        CHECK(strlen(b) == outlen);
    }

    char *out = NULL;
    size_t outlen = 0;
    CHECK(tlsuv_base64_encode((const uint8_t *)msg, len, &out, &outlen) == 0);
    INFO("len[" << outlen <<"] " << out);
    CHECK(strlen(out) == outlen);
    free(out);

}

// test cancellation
// connection is targeting a black-holed port
TEST_CASE_METHOD(UvLoopTest, "connect cancel", "[connector]") {
    auto setup = GENERATE(
            std::make_pair("default", tlsuv_global_connector()),
            std::make_pair("proxy", tlsuv_new_proxy_connector(tlsuv_PROXY_HTTP, "127.0.0.1", "13128")),
            std::make_pair("unreachable proxy", tlsuv_new_proxy_connector(tlsuv_PROXY_HTTP, "yahoo.com", "13128"))
    );

    struct result_s {
        bool called;
        int err;
        uv_os_sock_t sock;
    } result = {false, 0,0};

    WHEN("connector = " << setup.first) {
        auto connector = setup.second;

        auto cr = connector->connect(loop, connector, "yahoo.com", "7443",
                                     [](uv_os_sock_t s, int err, void *ctx) {
                                         auto r = (result_s *) (ctx);
                                         r->called = true;
                                         r->sock = s;
                                         r->err = err;
                                     }, (void *) &result);
        CHECK(cr != nullptr);

        run(1);

        THEN("callback should not be yet called") {
            CHECK(!result.called);

            AND_THEN("cancellation caused callback") {
                connector->cancel(cr);
                run(UNTIL(result.called));

                INFO("error => " << uv_strerror(result.err));
                CHECK(result.err == UV_ECANCELED);
            }
        }
#if _WIN32
        closesocket(result.sock);
#else
        close(result.sock);
#endif
        connector->free((void*)connector);
    }
}