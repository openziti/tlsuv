/*
Copyright 2025 NetFoundry, Inc.

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

// End-to-end tests for server-side TLS engines (tls_context->new_server_engine).
// Both peers live in this process, so no external test server is needed. Every
// end-to-end case runs over each transport in turn: an in-memory transport
// (engine set_io), a uv_socketpair(), and a loopback TCP socket pair (both
// engine set_io_fd).

#include <catch2/catch_all.hpp>

#include <tlsuv/tls_engine.h>
#include "fixtures.h"
#include <uv.h>

#include <algorithm>
#include <cstring>
#include <deque>
#include <memory>
#include <string>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#define SOCKET int
#define INVALID_SOCKET (-1)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include "engine_fixtures.h"

// ---------------------------------------------------------------- transports

// loopback socket pair, both ends non-blocking so a single thread can drive both
// handshakes: BIO_s_socket turns EAGAIN into retry flags, so handshake() returns
// TLS_HS_CONTINUE instead of blocking.
static void set_nonblocking(SOCKET s) {
#if defined(_WIN32)
    u_long mode = 1;
    REQUIRE(ioctlsocket(s, FIONBIO, &mode) == 0);
#else
    int fl = fcntl(s, F_GETFL, 0);
    REQUIRE(fcntl(s, F_SETFL, fl | O_NONBLOCK) == 0);
#endif
}

static void sock_close(SOCKET s) {
    if (s == INVALID_SOCKET) return;
#if defined(_WIN32)
    closesocket(s);
#else
    close(s);
#endif
}

struct socket_transport : transport {
    SOCKET listener = INVALID_SOCKET;
    SOCKET clt_sock = INVALID_SOCKET;
    SOCKET srv_sock = INVALID_SOCKET;

    const char* name() override {
        return "socket_transport";
    }

    socket_transport() {
#if defined(_WIN32)
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
#endif
        listener = socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(listener != INVALID_SOCKET);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = 0; // ephemeral
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        REQUIRE(bind(listener, (sockaddr *) &addr, sizeof(addr)) == 0);
        REQUIRE(listen(listener, 1) == 0);

        socklen_t len = sizeof(addr);
        REQUIRE(getsockname(listener, (sockaddr *) &addr, &len) == 0);

        clt_sock = socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(clt_sock != INVALID_SOCKET);
        // blocking connect: completes immediately on loopback with a pending listen
        REQUIRE(connect(clt_sock, (sockaddr *) &addr, sizeof(addr)) == 0);

        srv_sock = accept(listener, nullptr, nullptr);
        REQUIRE(srv_sock != INVALID_SOCKET);

        set_nonblocking(clt_sock);
        set_nonblocking(srv_sock);
    }

    ~socket_transport() override {
        sock_close(clt_sock);
        sock_close(srv_sock);
        sock_close(listener);
#if defined(_WIN32)
        WSACleanup();
#endif
    }

    void attach(tlsuv_engine_t clt, tlsuv_engine_t srv) override {
        clt->set_io_fd(clt, (tlsuv_sock_t) clt_sock);
        srv->set_io_fd(srv, (tlsuv_sock_t) srv_sock);
    }
};

// uv_socketpair(): a pre-connected pair with no listener, bind or accept. Cheaper
// and less racy than the TCP transport, and on POSIX it is an AF_UNIX pair rather
// than loopback TCP, so it also covers a non-INET socket under the engine.
struct uv_socketpair_transport : transport {
    uv_os_sock_t fds[2] = {(uv_os_sock_t) INVALID_SOCKET, (uv_os_sock_t) INVALID_SOCKET};

    uv_socketpair_transport() {
        REQUIRE(uv_socketpair(SOCK_STREAM, 0, fds, UV_NONBLOCK_PIPE, UV_NONBLOCK_PIPE) == 0);
        set_nonblocking(fds[0]);
        set_nonblocking(fds[1]);
    }

    ~uv_socketpair_transport() override {
        sock_close((SOCKET) fds[0]);
        sock_close((SOCKET) fds[1]);
    }

    void attach(tlsuv_engine_t clt, tlsuv_engine_t srv) override {
        clt->set_io_fd(clt, (tlsuv_sock_t) fds[0]);
        srv->set_io_fd(srv, (tlsuv_sock_t) fds[1]);
    }

    const char* name() override {
        return "socketpair";
    }
};

using transport_factory = std::unique_ptr<transport> (*)();

static std::unique_ptr<transport> make_socketpair() { return std::make_unique<uv_socketpair_transport>(); }
static std::unique_ptr<transport> make_socket() { return std::make_unique<socket_transport>(); }

// ------------------------------------------------------------------- drivers

static int read_some(tlsuv_engine_t e, char *buf, size_t cap, size_t *out) {
    *out = 0;
    for (int i = 0; i < MAX_ITERATIONS; i++) {
        int rc = e->read(e, buf, out, cap);
        if (rc != TLS_AGAIN) return rc;
        uv_sleep(1);
    }
    return TLS_AGAIN;
}

// ------------------------------------------------------------------ contexts

// frees the certificate even when a REQUIRE throws
struct cert_holder {
    tlsuv_certificate_t c = nullptr;
    cert_holder() = default;
    cert_holder(const cert_holder &) = delete;
    cert_holder &operator=(const cert_holder &) = delete;
    ~cert_holder() { if (c) c->free(c); }
};

// --------------------------------------------------------------------- tests

TEST_CASE("server engine requires own cert", "[engine][server]") {
    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);

    // no set_own_cert(): there is no identity to serve
    CHECK(srv.tls->new_server_engine(srv.tls) == nullptr);
}

TEST_CASE("server engine handshake and data", "[engine][server]") {
    auto make = GENERATE(as<transport_factory>{}, make_mem, make_socketpair, make_socket);

    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    srv.set_identity();

    tls_ctx_holder clt(test_ca);

    engine_holder srv_eng(srv.tls->new_server_engine(srv.tls));
    engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));
    REQUIRE(srv_eng.e != nullptr);
    REQUIRE(clt_eng.e != nullptr);

    auto t = make();
    t->attach(clt_eng, srv_eng);

    REQUIRE(do_handshake(clt_eng, srv_eng));

    WHEN("small payload both ways: " << t->name()) {
        check_transfer(clt_eng, srv_eng, "hello server");
        check_transfer(srv_eng, clt_eng, "hello client");
    }

    WHEN("payload spanning multiple TLS records: " << t->name()) {
        std::string big;
        for (int i = 0; i < 4096; i++) big += "0123456789"; // 40KB
        check_transfer(clt_eng, srv_eng, big);
        check_transfer(srv_eng, clt_eng, big);
    }

    WHEN("close notify: " << t->name()) {
#if defined(TEST_applesec)
        // applesec close() does not block: close_notify is produced asynchronously and
        // flushed from the engine's queue, which it can do for socket IO only (set_io
        // callbacks belong to the owner and are not thread safe)
        if (std::string(t->name()) == "mem_transport") {
            SKIP("applesec does not send close_notify over set_io");
        }
#endif
        CHECK(clt_eng->close(clt_eng) == 0);

        char buf[128];
        size_t n = 0;
        CHECK(read_some(srv_eng, buf, sizeof(buf), &n) == TLS_EOF);
    }
}

// a CA that did not sign tests/certs/server.crt
static const char *unrelated_ca = R"(-----BEGIN CERTIFICATE-----
MIIBqjCCAVCgAwIBAgIUSKubiTHEMl29Fr5v20tGMtgmQWowCgYIKoZIzj0EAwIw
MjEUMBIGA1UECgwLdGxzdXYgdGVzdHMxGjAYBgNVBAMMEVVucmVsYXRlZCBUZXN0
IENBMCAXDTI2MTAwMjEzMzc1MVoYDzIxMjYwOTA4MTMzNzUxWjAyMRQwEgYDVQQK
DAt0bHN1diB0ZXN0czEaMBgGA1UEAwwRVW5yZWxhdGVkIFRlc3QgQ0EwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATwn4ApSZjC3I3HwYTFij9gaWQ64dYwJszBrMEJ
XoaQcPtBT/7b5af6KkhyWNtGfMAk9NqcgrDOd7gOgy4ZQruao0IwQDAdBgNVHQ4E
FgQUPpS2JZYaENmsdFXZ5CDTdIBgdRcwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIgJioIfrIHeHaTZBfWnedVSqQ8u0S3
+gcaVIyaqRPNOEwCIQDkZ5OV7VsdPxGD398+1rk7Zflly97Mgo7d0Daet7iSzA==
-----END CERTIFICATE-----
)";

// handshake a new client engine of `clt` against a new server engine of `srv`
static bool handshake_succeeds(tls_context *clt, tls_context *srv) {
    engine_holder srv_eng(srv->new_server_engine(srv));
    engine_holder clt_eng(clt->new_engine(clt, test_host));
    REQUIRE(srv_eng.e != nullptr);
    REQUIRE(clt_eng.e != nullptr);

    auto t = make_mem();
    t->attach(clt_eng, srv_eng);
    return do_handshake(clt_eng, srv_eng);
}

TEST_CASE("client CA bundle decides which server is trusted", "[engine][server]") {
    tls_ctx_holder srv(nullptr);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    srv.set_identity();

    // the test CA is not in the system CA store
    tls_ctx_holder clt(nullptr);
    CHECK_FALSE(handshake_succeeds(clt.tls, srv.tls));

    SECTION("a custom bundle with the signing CA") {
        REQUIRE(clt.tls->set_ca_bundle(clt.tls, test_ca, strlen(test_ca)) == 0);
        CHECK(handshake_succeeds(clt.tls, srv.tls));
    }

    SECTION("a custom bundle without the signing CA") {
        REQUIRE(clt.tls->set_ca_bundle(clt.tls, unrelated_ca, strlen(unrelated_ca)) == 0);
        CHECK_FALSE(handshake_succeeds(clt.tls, srv.tls));
    }

    SECTION("a new bundle replaces the previous one") {
        REQUIRE(clt.tls->set_ca_bundle(clt.tls, test_ca, strlen(test_ca)) == 0);
        CHECK(handshake_succeeds(clt.tls, srv.tls));

        REQUIRE(clt.tls->set_ca_bundle(clt.tls, unrelated_ca, strlen(unrelated_ca)) == 0);
        CHECK_FALSE(handshake_succeeds(clt.tls, srv.tls));

        REQUIRE(clt.tls->set_ca_bundle(clt.tls, test_ca, strlen(test_ca)) == 0);
        CHECK(handshake_succeeds(clt.tls, srv.tls));
    }

    SECTION("NULL goes back to the system CA store") {
        REQUIRE(clt.tls->set_ca_bundle(clt.tls, test_ca, strlen(test_ca)) == 0);
        CHECK(handshake_succeeds(clt.tls, srv.tls));

        REQUIRE(clt.tls->set_ca_bundle(clt.tls, nullptr, 0) == 0);
        CHECK_FALSE(handshake_succeeds(clt.tls, srv.tls));

        // and a custom bundle can be set again afterwards
        REQUIRE(clt.tls->set_ca_bundle(clt.tls, test_ca, strlen(test_ca)) == 0);
        CHECK(handshake_succeeds(clt.tls, srv.tls));
    }

    SECTION("a rejected bundle leaves the current one in place") {
        REQUIRE(clt.tls->set_ca_bundle(clt.tls, test_ca, strlen(test_ca)) == 0);

        const char *bad = "this is not a certificate";
        CHECK(clt.tls->set_ca_bundle(clt.tls, bad, strlen(bad)) != 0);
        CHECK(handshake_succeeds(clt.tls, srv.tls));
    }
}

TEST_CASE("server engine ALPN", "[engine][server]") {
    auto make = GENERATE(as<transport_factory>{}, make_mem, make_socketpair, make_socket);

    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    srv.set_identity();

    tls_ctx_holder clt(test_ca);

    engine_holder srv_eng(srv.tls->new_server_engine(srv.tls));
    engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));

    auto t = make();

    WHEN("server list order wins: " << t->name()) {
        // the client offers baz before bar, so a "bar" result can only come from
        // the server's own preference order
        const char *srv_protos[] = {"bar", "baz"};
        const char *clt_protos[] = {"foo", "baz", "bar"};
        srv_eng->set_protocols(srv_eng, srv_protos, 2);
        clt_eng->set_protocols(clt_eng, clt_protos, 3);

        t->attach(clt_eng, srv_eng);
        REQUIRE(do_handshake(clt_eng, srv_eng));

        CHECK_THAT(srv_eng->get_alpn(srv_eng), Catch::Matchers::Equals("bar"));
        CHECK_THAT(clt_eng->get_alpn(clt_eng), Catch::Matchers::Equals("bar"));
    }

    WHEN("no overlap: " << t->name()) {
        const char *srv_protos[] = {"bar"};
        const char *clt_protos[] = {"foo"};
        srv_eng->set_protocols(srv_eng, srv_protos, 1);
        clt_eng->set_protocols(clt_eng, clt_protos, 1);

        t->attach(clt_eng, srv_eng);
#if defined(TEST_win32crypto) || defined(TEST_applesec)
        // Schannel and Network.framework treat a fully disjoint ALPN offer as a fatal
        // handshake error (SEC_E_APPLICATION_PROTOCOL_MISMATCH / no_application_protocol)
        // rather than completing without a negotiated protocol like the other backends do.
        REQUIRE_FALSE(do_handshake(clt_eng, srv_eng));
#else
        REQUIRE(do_handshake(clt_eng, srv_eng));

        CHECK_THAT(srv_eng->get_alpn(srv_eng), Catch::Matchers::Equals(""));
        CHECK_THAT(clt_eng->get_alpn(clt_eng), Catch::Matchers::Equals(""));
#endif
    }

    WHEN("server offers none: " << t->name()) {
        const char *clt_protos[] = {"foo"};
        clt_eng->set_protocols(clt_eng, clt_protos, 1);

        t->attach(clt_eng, srv_eng);
        REQUIRE(do_handshake(clt_eng, srv_eng));

        CHECK_THAT(srv_eng->get_alpn(srv_eng), Catch::Matchers::Equals(""));
        CHECK_THAT(clt_eng->get_alpn(clt_eng), Catch::Matchers::Equals(""));
    }
}

TEST_CASE("server engine optional client cert", "[engine][server]") {
    auto make = GENERATE(as<transport_factory>{}, make_mem, make_socketpair, make_socket);

    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    srv.set_identity();

    tls_ctx_holder clt(test_ca);

    engine_holder srv_eng(srv.tls->new_server_engine(srv.tls));
    if (srv_eng->get_peer_cert == nullptr) {
        SKIP("get_peer_cert is not implemented");
    }

    SECTION("client presents a certificate") {
#if defined(TEST_applesec)
        // Network.framework has no public optional-client-auth mode, so the applesec
        // server engine never requests client certificates
        SKIP("applesec server engine does not request client certificates");
#endif
        clt.set_identity();

        engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));

        auto t = make();
        t->attach(clt_eng, srv_eng);
        REQUIRE(do_handshake(clt_eng, srv_eng));

        REQUIRE(srv_eng->get_peer_cert != nullptr);
        cert_holder peer;
        REQUIRE(srv_eng->get_peer_cert(srv_eng, &peer.c) == 0);
        REQUIRE(peer.c != nullptr);

        const char *text = peer.c->get_text(peer.c);
        REQUIRE(text != nullptr);
        CHECK_THAT(text, Catch::Matchers::ContainsSubstring("CN=localhost"));

        char *pem = nullptr;
        size_t pemlen = 0;
        REQUIRE(peer.c->to_pem(peer.c, 0, &pem, &pemlen) == 0);
        std::unique_ptr<char, decltype(&free)> pem_guard(pem, free);
        CHECK(pemlen > 0);
    }

    SECTION("client presents no certificate") {
        engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));
        auto t = make();
        t->attach(clt_eng, srv_eng);

        // client certs are optional: the handshake completes anyway
        REQUIRE(do_handshake(clt_eng, srv_eng));

        cert_holder peer;
        CHECK(srv_eng->get_peer_cert(srv_eng, &peer.c) == TLS_ERR);
        CHECK(peer.c == nullptr);
    }
}

TEST_CASE("client engine peer certificate", "[engine][server]") {
    auto make = GENERATE(as<transport_factory>{}, make_mem, make_socketpair, make_socket);

    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    srv.set_identity();

    tls_ctx_holder clt(test_ca);

    engine_holder srv_eng(srv.tls->new_server_engine(srv.tls));
    engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));
    if (clt_eng->get_peer_cert == nullptr) {
        SKIP("get_peer_cert is not implemented");
    }

    // no handshake yet, no peer certificate
    cert_holder peer;
    CHECK(clt_eng->get_peer_cert(clt_eng, &peer.c) == TLS_ERR);
    CHECK(peer.c == nullptr);

    auto t = make();
    t->attach(clt_eng, srv_eng);
    REQUIRE(do_handshake(clt_eng, srv_eng));

    // the client gets the server's certificate
    REQUIRE(clt_eng->get_peer_cert(clt_eng, &peer.c) == 0);
    REQUIRE(peer.c != nullptr);

    // get_text is optional
    if (peer.c->get_text != nullptr) {
        const char *text = peer.c->get_text(peer.c);
        REQUIRE(text != nullptr);
        CHECK_THAT(text, Catch::Matchers::ContainsSubstring("CN=localhost"));
    }

    char *pem = nullptr;
    size_t pemlen = 0;
    REQUIRE(peer.c->to_pem(peer.c, 0, &pem, &pemlen) == 0);
    std::unique_ptr<char, decltype(&free)> pem_guard(pem, free);
    CHECK(pemlen > 0);
}

TEST_CASE("server engine without CA requests no client cert", "[engine][server]") {
    auto make = GENERATE(as<transport_factory>{}, make_mem, make_socketpair, make_socket);

    // no CA bundle and no verify callback: there is nothing to verify a client
    // cert against, so the server must not ask for one
    tls_ctx_holder srv(nullptr);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    srv.set_identity();

    // the client still needs the CA to verify the server
    tls_ctx_holder clt(test_ca);
    clt.set_identity();

    engine_holder srv_eng(srv.tls->new_server_engine(srv.tls));
    engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));
    auto t = make();
    t->attach(clt_eng, srv_eng);

    REQUIRE(do_handshake(clt_eng, srv_eng));

    // the client has an identity, so an absent peer cert proves the server never
    // sent a CertificateRequest
    if (srv_eng->get_peer_cert != nullptr) {
        cert_holder peer;
        CHECK(srv_eng->get_peer_cert(srv_eng, &peer.c) == TLS_ERR);
        CHECK(peer.c == nullptr);
    }

    INFO("transport: " << t->name());
    check_transfer(clt_eng, srv_eng, "no client auth");
}

static int verify_calls = 0;
static int verify_result = 0;

static int counting_verify(const struct tlsuv_certificate_s *cert, void *ctx) {
    verify_calls++;
    return verify_result;
}

TEST_CASE("server engine client cert verify callback", "[engine][server]") {
    auto make = GENERATE(as<transport_factory>{}, make_mem, make_socketpair, make_socket);

    verify_calls = 0;

    // set_cert_verify mutates the shared SSL_CTX, so this needs its own context
    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    srv.set_identity();
    srv.tls->set_cert_verify(srv.tls, counting_verify, nullptr);

    tls_ctx_holder clt(test_ca);
    engine_holder srv_eng(srv.tls->new_server_engine(srv.tls));
    if (srv_eng->get_peer_cert == nullptr) {
        SKIP("get_peer_cert is not implemented");
    }
#if defined(TEST_applesec)
    SKIP("applesec server engine does not request client certificates");
#endif

    SECTION("callback accepts the client cert") {
        verify_result = 0;
        clt.set_identity();

        engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));
        auto t = make();
        t->attach(clt_eng, srv_eng);

        CHECK(do_handshake(clt_eng, srv_eng));
        CHECK(verify_calls == 1);
    }

    SECTION("callback rejects the client cert") {
        verify_result = -1;
        clt.set_identity();

        engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));
        auto t = make();
        t->attach(clt_eng, srv_eng);

        CHECK_FALSE(do_handshake(clt_eng, srv_eng));
        CHECK(verify_calls == 1);
    }

    SECTION("callback is not invoked without a client cert") {
        verify_result = -1; // would reject, but never gets asked

        engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));
        auto t = make();
        t->attach(clt_eng, srv_eng);

        CHECK(do_handshake(clt_eng, srv_eng));
        CHECK(verify_calls == 0);
    }
}

// every TLS_ERR / TLS_HS_ERROR comes with a reason in strerror()
TEST_CASE("engine reports an error on failure", "[engine][server]") {
    auto make = GENERATE(as<transport_factory>{}, make_mem, make_socketpair, make_socket);

    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    srv.set_identity();

    // the client does not trust the test CA (system trust store only)
    tls_ctx_holder clt(nullptr);

    engine_holder srv_eng(srv.tls->new_server_engine(srv.tls));
    engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));

#if defined(TEST_applesec)
    SECTION("write before handshake") {
        CHECK(clt_eng->write(clt_eng, "x", 1) == TLS_ERR);
        const char *err = clt_eng->strerror(clt_eng);
        REQUIRE(err != nullptr);
        CHECK(strlen(err) > 0);
    }
#endif

    SECTION("untrusted server certificate") {
        auto t = make();
        INFO("transport: " << t->name());
        t->attach(clt_eng, srv_eng);

        // pump like do_handshake(), but keep what handshake() returned: which side
        // fails first depends on the backend, and whichever returns TLS_HS_ERROR
        // must say why
        tls_handshake_state cs = TLS_HS_BEFORE, ss = TLS_HS_BEFORE;
        for (int i = 0; i < MAX_ITERATIONS && cs != TLS_HS_ERROR && ss != TLS_HS_ERROR; i++) {
            cs = clt_eng->handshake(clt_eng);
            ss = srv_eng->handshake(srv_eng);
            uv_sleep(1);
        }
        REQUIRE((cs == TLS_HS_ERROR || ss == TLS_HS_ERROR));

        for (auto [eng, st] : {std::pair{(tlsuv_engine_t) clt_eng, cs}, std::pair{(tlsuv_engine_t) srv_eng, ss}}) {
            if (st != TLS_HS_ERROR) continue;
            const char *err = eng->strerror(eng);
            REQUIRE(err != nullptr);
            CHECK(strlen(err) > 0);
        }
    }
}

TEST_CASE("server engine reset", "[engine][server]") {
    auto make = GENERATE(as<transport_factory>{}, make_socketpair, make_socket);

    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    srv.set_identity();

    tls_ctx_holder clt(test_ca);

    const char *protos[] = {"bar"};
    engine_holder srv_eng(srv.tls->new_server_engine(srv.tls));
    if (srv_eng->reset == nullptr) {
        SKIP("reset is not implemented");
    }
    srv_eng->set_protocols(srv_eng, protos, 1);

    for (int round = 0; round < 2; round++) {
        engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));
        clt_eng->set_protocols(clt_eng, protos, 1);

        auto t = make();
        t->attach(clt_eng, srv_eng);

        INFO("transport: " << t->name());

        REQUIRE(do_handshake(clt_eng, srv_eng));
        // accept state and the supported protocol list survive reset()
        CHECK_THAT(srv_eng->get_alpn(srv_eng), Catch::Matchers::Equals("bar"));
        check_transfer(clt_eng, srv_eng, "round " + std::to_string(round));

        REQUIRE(srv_eng->reset(srv_eng) == 0);
    }
}
