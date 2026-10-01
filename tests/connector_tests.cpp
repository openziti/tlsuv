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

static void close_sock(uv_os_sock_t s) {
#if _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

TEST_CASE_METHOD(UvLoopTest, "default connect fail", "[connector]") {
    auto connector = tlsuv_global_connector();

    struct result_s {
        bool called;
        int err;
        uv_os_sock_t sock;
    } result = {false, 0,0};
    DEFER {
        if (result.called && result.err == 0) close_sock(result.sock);
    };

    auto cr = connector->connect(loop, connector, "127.0.0.1", "7553", nullptr,
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
}

TEST_CASE_METHOD(UvLoopTest, "default connector", "[connector]") {
    auto connector = tlsuv_global_connector();

    struct result_s {
        bool called;
        int err;
        uv_os_sock_t sock;
    } result = {false, 0,0};
    DEFER {
        if (result.called && result.err == 0) close_sock(result.sock);
    };

    connector->connect(loop, connector, "localhost", "7443", nullptr,
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
    DEFER {
        if (result.called && result.err == 0) close_sock(result.sock);
        // not while a connect is still pending (the test timed out): it would use it
        if (result.called) connector->free(connector);
    };

    connector->connect(loop, connector, "127.0.0.1", target_port, nullptr,
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
}

TEST_CASE_METHOD(UvLoopTest, "connect with ipv4 source address", "[connector]") {
    // a local listener stands in for the destination -- this test doesn't depend on the
    // external test server/proxy infra, only on being able to bind an arbitrary local port.
    uv_tcp_t server{};
    uv_tcp_init(loop, &server);
    sockaddr_in listen_addr{};
    uv_ip4_addr(TEST_SERVER, 0, &listen_addr);
    REQUIRE(uv_tcp_bind(&server, (const sockaddr *) &listen_addr, 0) == 0);
    REQUIRE(uv_listen((uv_stream_t *) &server, 1, [](uv_stream_t *s, int status) {
        auto *client = t_alloc<uv_tcp_t>();
        uv_tcp_init(s->loop, client);
        if (uv_accept(s, (uv_stream_t *) client) == 0) {
            uv_close((uv_handle_t *) client, [](uv_handle_t *h) { free(h); });
        }
    }) == 0);
    DEFER { uv_close((uv_handle_t *) &server, nullptr); drain(); };

    sockaddr_storage bound{};
    int bound_len = sizeof(bound);
    uv_tcp_getsockname(&server, (sockaddr *) &bound, &bound_len);
    char target_port[12];
    snprintf(target_port, sizeof(target_port), "%d", ntohs(((sockaddr_in *) &bound)->sin_port));

    auto connector = tlsuv_global_connector();

    struct result_s {
        bool called;
        int err;
        uv_os_sock_t sock;
    } result = {false, 0, (uv_os_sock_t) -1};
    DEFER {
        if (result.called && result.err == 0) close_sock(result.sock);
    };

    sockaddr_in src_addr{};
    uv_ip4_addr(TEST_SERVER, 58731, &src_addr);
    auto req = connector->connect(loop, connector, TEST_SERVER, target_port, (const sockaddr *) &src_addr,
                                  [](uv_os_sock_t s, int err, void *ctx) {
                                      auto r = (result_s *) ctx;
                                      r->called = true;
                                      r->sock = s;
                                      r->err = err;
                                  }, &result);
    REQUIRE(req != nullptr);

    run(UNTIL(result.called));

    REQUIRE(result.err == 0);
    sockaddr_in local{};
    socklen_t local_len = sizeof(local);
    REQUIRE(getsockname(result.sock, (sockaddr *) &local, &local_len) == 0);
    CHECK(ntohs(local.sin_port) == 58731);
}

TEST_CASE_METHOD(UvLoopTest, "connect with ipv6 source address", "[connector]") {
    uv_tcp_t server{};
    uv_tcp_init(loop, &server);
    sockaddr_in6 listen_addr{};
    uv_ip6_addr("::1", 0, &listen_addr);
    REQUIRE(uv_tcp_bind(&server, (const sockaddr *) &listen_addr, 0) == 0);
    REQUIRE(uv_listen((uv_stream_t *) &server, 1, [](uv_stream_t *s, int status) {
        auto *client = t_alloc<uv_tcp_t>();
        uv_tcp_init(s->loop, client);
        if (uv_accept(s, (uv_stream_t *) client) == 0) {
            uv_close((uv_handle_t *) client, [](uv_handle_t *h) { free(h); });
        }
    }) == 0);
    DEFER { uv_close((uv_handle_t *) &server, nullptr); drain(); };

    sockaddr_storage bound{};
    int bound_len = sizeof(bound);
    uv_tcp_getsockname(&server, (sockaddr *) &bound, &bound_len);
    char target_port[12];
    snprintf(target_port, sizeof(target_port), "%d", ntohs(((sockaddr_in6 *) &bound)->sin6_port));

    auto connector = tlsuv_global_connector();

    struct result_s {
        bool called;
        int err;
        uv_os_sock_t sock;
    } result = {false, 0, (uv_os_sock_t) -1};
    DEFER {
        if (result.called && result.err == 0) close_sock(result.sock);
    };

    sockaddr_in6 src_addr{};
    uv_ip6_addr("::1", 58732, &src_addr);
    auto req = connector->connect(loop, connector, "::1", target_port, (const sockaddr *) &src_addr,
                                  [](uv_os_sock_t s, int err, void *ctx) {
                                      auto r = (result_s *) ctx;
                                      r->called = true;
                                      r->sock = s;
                                      r->err = err;
                                  }, &result);
    REQUIRE(req != nullptr);

    run(UNTIL(result.called));

    REQUIRE(result.err == 0);
    sockaddr_in6 local{};
    socklen_t local_len = sizeof(local);
    REQUIRE(getsockname(result.sock, (sockaddr *) &local, &local_len) == 0);
    char ip[64];
    uv_ip6_name(&local, ip, sizeof(ip));
    CHECK(std::string(ip) == "::1");
    CHECK(ntohs(local.sin6_port) == 58732);
}

TEST_CASE_METHOD(UvLoopTest, "connect races multiple candidates with source address family filter", "[connector]") {
    // "yahoo.com" is the dual-stack (A+AAAA) hostname already relied on elsewhere in this suite
    // (see "connect cancel") -- unlike "localhost", whose resolution depends on the local
    // resolver/hosts file and isn't reliably dual-stack across environments (the "default
    // connector" test above has to branch on AF_INET vs AF_INET6 for exactly that reason).
    // this exercises on_resolve()'s real multi-connect (candidate-racing) loop: forcing the
    // source address to a specific family (via a wildcard bind of just that family) must cause
    // the other family's candidate(s) to be skipped rather than raced, so the connection can
    // only land on a peer of the forced family.
    auto connector = tlsuv_global_connector();

    struct result_s {
        bool called;
        int err;
        uv_os_sock_t sock;
    } result = {false, 0, (uv_os_sock_t) -1};
    DEFER {
        if (result.called && result.err == 0) close_sock(result.sock);
    };

    sockaddr_in src_addr{};
    uv_ip4_addr("0.0.0.0", 0, &src_addr); // force IPv4: binds to any local IPv4 address
    auto req = connector->connect(loop, connector, "yahoo.com", "443", (const sockaddr *) &src_addr,
                                  [](uv_os_sock_t s, int err, void *ctx) {
                                      auto r = (result_s *) ctx;
                                      r->called = true;
                                      r->sock = s;
                                      r->err = err;
                                  }, &result);
    REQUIRE(req != nullptr);

    run(UNTIL(result.called));

    REQUIRE(result.err == 0);
    sockaddr_storage local{};
    socklen_t local_len = sizeof(local);
    REQUIRE(getsockname(result.sock, (sockaddr *) &local, &local_len) == 0);
    // only holds if yahoo.com's AAAA candidate(s) were actually skipped rather than raced
    CHECK(local.ss_family == AF_INET);
}

TEST_CASE_METHOD(UvLoopTest, "connect fails when no candidate matches source address family", "[connector]") {
    // "127.0.0.1" only ever resolves to a single IPv4 candidate -- an IPv6 source address can
    // never match it, so every candidate gets skipped and the connect must fail cleanly with
    // EAFNOSUPPORT, not hang or silently connect unbound.
    uv_tcp_t server{};
    uv_tcp_init(loop, &server);
    sockaddr_in listen_addr{};
    uv_ip4_addr("127.0.0.1", 0, &listen_addr);
    REQUIRE(uv_tcp_bind(&server, (const sockaddr *) &listen_addr, 0) == 0);
    REQUIRE(uv_listen((uv_stream_t *) &server, 1, [](uv_stream_t *s, int status) {
        auto *client = t_alloc<uv_tcp_t>();
        uv_tcp_init(s->loop, client);
        if (uv_accept(s, (uv_stream_t *) client) == 0) {
            uv_close((uv_handle_t *) client, [](uv_handle_t *h) { free(h); });
        }
    }) == 0);
    DEFER { uv_close((uv_handle_t *) &server, nullptr); drain(); };

    sockaddr_storage bound{};
    int bound_len = sizeof(bound);
    uv_tcp_getsockname(&server, (sockaddr *) &bound, &bound_len);
    char target_port[12];
    snprintf(target_port, sizeof(target_port), "%d", ntohs(((sockaddr_in *) &bound)->sin_port));

    auto connector = tlsuv_global_connector();

    struct result_s {
        bool called;
        int err;
        uv_os_sock_t sock;
    } result = {false, 0, (uv_os_sock_t) -1};
    DEFER {
        if (result.called && result.err == 0) close_sock(result.sock);
    };

    sockaddr_in6 src_addr{};
    uv_ip6_addr("::1", 0, &src_addr);
    auto req = connector->connect(loop, connector, "127.0.0.1", target_port, (const sockaddr *) &src_addr,
                                  [](uv_os_sock_t s, int err, void *ctx) {
                                      auto r = (result_s *) ctx;
                                      r->called = true;
                                      r->sock = s;
                                      r->err = err;
                                  }, &result);
    REQUIRE(req != nullptr);

    run(UNTIL(result.called));

    REQUIRE(result.err == UV_EAFNOSUPPORT);
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

        auto cr = connector->connect(loop, connector, "yahoo.com", "7443", nullptr,
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