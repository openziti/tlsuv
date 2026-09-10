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

#define to_str_(x) #x
#define to_str(x) to_str_(x)

static const char *test_ca = to_str(TEST_SERVER_CA);
static const char *test_cert = to_str(TEST_SERVER_CERT);
static const char *test_key = to_str(TEST_SERVER_KEY);

// certs/server.crt is CN=localhost with SAN DNS:localhost + IP:127.0.0.1
static const char *test_host = "localhost";

// ---------------------------------------------------------------- transports

// A transport connects a client engine to a server engine. Each subclass covers
// one of the engine's two IO modes.
struct transport {
    virtual const char* name() = 0;
    virtual ~transport() = default;
    virtual void attach(tlsuv_engine_t clt, tlsuv_engine_t srv) = 0;
};

// in-memory: one queue per direction. Implements the io_read/io_write contract
// of engine_bio_read/engine_bio_write - byte count, TLS_AGAIN when it would
// block, 0 for EOF.
struct mem_pipe {
    std::deque<char> buf;
    size_t cap = 0; // 0 = unbounded
};

struct mem_endpoint {
    mem_pipe *in;
    mem_pipe *out;
};

static ssize_t mem_read(io_ctx c, char *out, size_t len) {
    auto *p = static_cast<mem_endpoint *>(c)->in;
    if (p->buf.empty()) return TLS_AGAIN;

    size_t n = std::min(len, p->buf.size());
    std::copy_n(p->buf.begin(), n, out);
    p->buf.erase(p->buf.begin(), p->buf.begin() + (long) n);
    return (ssize_t) n;
}

static ssize_t mem_write(io_ctx c, const char *in, size_t len) {
    auto *p = static_cast<mem_endpoint *>(c)->out;
    if (p->cap > 0) {
        if (p->buf.size() >= p->cap) return TLS_AGAIN;
        len = std::min(len, p->cap - p->buf.size());
    }
    p->buf.insert(p->buf.end(), in, in + len);
    return (ssize_t) len;
}

struct mem_transport : transport {
    mem_pipe c2s, s2c;
    mem_endpoint clt_ep{&s2c, &c2s};
    mem_endpoint srv_ep{&c2s, &s2c};

    explicit mem_transport(size_t cap = 0) {
        c2s.cap = cap;
        s2c.cap = cap;
    }

    void attach(tlsuv_engine_t clt, tlsuv_engine_t srv) override {
        clt->set_io(clt, &clt_ep, mem_read, mem_write);
        srv->set_io(srv, &srv_ep, mem_read, mem_write);
    }

    const char* name() override {
        return "mem_transport";
    }
};

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

static std::unique_ptr<transport> make_mem() { return std::make_unique<mem_transport>(); }
static std::unique_ptr<transport> make_socketpair() { return std::make_unique<uv_socketpair_transport>(); }
static std::unique_ptr<transport> make_socket() { return std::make_unique<socket_transport>(); }

// ------------------------------------------------------------------- drivers

static const int MAX_ITERATIONS = 1000;

// pump both sides until both handshakes complete
static bool do_handshake(tlsuv_engine_t clt, tlsuv_engine_t srv) {
    for (int i = 0; i < MAX_ITERATIONS; i++) {
        tls_handshake_state cs = clt->handshake(clt);
        tls_handshake_state ss = srv->handshake(srv);
        if (cs == TLS_HS_ERROR || ss == TLS_HS_ERROR) return false;
        if (cs == TLS_HS_COMPLETE && ss == TLS_HS_COMPLETE) return true;
    }
    return false;
}

static int read_some(tlsuv_engine_t e, char *buf, size_t cap, size_t *out) {
    *out = 0;
    for (int i = 0; i < MAX_ITERATIONS; i++) {
        int rc = e->read(e, buf, out, cap);
        if (rc != TLS_AGAIN) return rc;
    }
    return TLS_AGAIN;
}

// transfer `data` from one engine to the other and compare what arrives
static void check_transfer(tlsuv_engine_t from, tlsuv_engine_t to, const std::string &data) {
    size_t sent = 0;
    std::string received;
    std::vector<char> buf(16 * 1024);

    CHECK(to->handshake_state(to) == TLS_HS_COMPLETE);
    CHECK(from->handshake_state(from) == TLS_HS_COMPLETE);

    for (int i = 0; i < MAX_ITERATIONS && received.size() < data.size(); i++) {
        if (sent < data.size()) {
            int rc = from->write(from, data.data() + sent, data.size() - sent);
            if (rc > 0) {
                sent += (size_t) rc;
            } else {
                REQUIRE(rc == TLS_AGAIN);
            }
        }

        size_t n = 0;
        for (int j = 0; j < 10; j++) {
            int rc = to->read(to, buf.data(), &n, buf.size());
            REQUIRE((rc == TLS_OK || rc == TLS_MORE_AVAILABLE || rc == TLS_AGAIN));
            if (rc == TLS_AGAIN) {
                // allow transport to catch up
                uv_sleep(1);
                continue;
            }
            received.append(buf.data(), n);
            if (rc == TLS_OK) break;
        }
    }

    CHECK(sent == data.size());
    CHECK(received == data);
}

// ------------------------------------------------------------------ contexts

struct tls_ctx_holder {
    tls_context *tls = nullptr;
    tlsuv_private_key_t key = nullptr;
    tlsuv_certificate_t cert = nullptr;

    explicit tls_ctx_holder(const char *ca) {
        tls = default_tls_context(ca, ca ? strlen(ca) : 0);
    }

    ~tls_ctx_holder() {
        if (cert) cert->free(cert);
        if (key) key->free(key);
        if (tls) tls->free_ctx(tls);
    }

    // identity from tests/certs/server.{key,crt}: EKU is serverAuth *and*
    // clientAuth, so it works as either peer's identity
    void set_identity() {
        REQUIRE(tls->load_key(&key, test_key, strlen(test_key)) == 0);
        REQUIRE(tls->load_cert(&cert, test_cert, strlen(test_cert)) == 0);
        REQUIRE(tls->set_own_cert(tls, key, cert) == 0);
    }

    bool supports_server() const { return tls != nullptr && tls->new_server_engine != nullptr; }
};

struct engine_holder {
    tlsuv_engine_t e = nullptr;
    engine_holder() = default;
    explicit engine_holder(tlsuv_engine_t eng) : e(eng) {}
    engine_holder(const engine_holder &) = delete;
    engine_holder &operator=(const engine_holder &) = delete;
    ~engine_holder() { if (e) e->free(e); }
    tlsuv_engine_t operator->() const { return e; }
    operator tlsuv_engine_t() const { return e; }
};

#define SKIP_UNLESS_SERVER_SUPPORTED(holder)                                    \
    do {                                                                        \
        if (!(holder).supports_server()) {                                      \
            WARN("TLS server engines are not supported by this backend");       \
            return;                                                             \
        }                                                                       \
    } while (0)

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
        CHECK(clt_eng->close(clt_eng) == 0);

        char buf[128];
        size_t n = 0;
        CHECK(read_some(srv_eng, buf, sizeof(buf), &n) == TLS_EOF);
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

    SECTION("server list order wins") {
        // the client offers baz before bar, so a "bar" result can only come from
        // the server's own preference order
        const char *srv_protos[] = {"bar", "baz"};
        const char *clt_protos[] = {"foo", "baz", "bar"};
        srv_eng->set_protocols(srv_eng, srv_protos, 2);
        clt_eng->set_protocols(clt_eng, clt_protos, 3);

        auto t = make();
        t->attach(clt_eng, srv_eng);
        REQUIRE(do_handshake(clt_eng, srv_eng));

        CHECK_THAT(srv_eng->get_alpn(srv_eng), Catch::Matchers::Equals("bar"));
        CHECK_THAT(clt_eng->get_alpn(clt_eng), Catch::Matchers::Equals("bar"));
    }

    SECTION("no overlap completes without ALPN") {
        const char *srv_protos[] = {"bar"};
        const char *clt_protos[] = {"foo"};
        srv_eng->set_protocols(srv_eng, srv_protos, 1);
        clt_eng->set_protocols(clt_eng, clt_protos, 1);

        auto t = make();
        t->attach(clt_eng, srv_eng);
        REQUIRE(do_handshake(clt_eng, srv_eng));

        CHECK_THAT(srv_eng->get_alpn(srv_eng), Catch::Matchers::Equals(""));
        CHECK_THAT(clt_eng->get_alpn(clt_eng), Catch::Matchers::Equals(""));
    }

    SECTION("server offers none") {
        const char *clt_protos[] = {"foo"};
        clt_eng->set_protocols(clt_eng, clt_protos, 1);

        auto t = make();
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

    SECTION("client presents a certificate") {
        clt.set_identity();

        engine_holder srv_eng(srv.tls->new_server_engine(srv.tls));
        if (srv_eng->get_peer_cert == nullptr) {
            SKIP("get_peer_cert is not implemented");
        }
        engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));

        auto t = make();
        t->attach(clt_eng, srv_eng);
        REQUIRE(do_handshake(clt_eng, srv_eng));

        REQUIRE(srv_eng->get_peer_cert != nullptr);
        tlsuv_certificate_t peer = nullptr;
        REQUIRE(srv_eng->get_peer_cert(srv_eng, &peer) == 0);
        REQUIRE(peer != nullptr);

        const char *text = peer->get_text(peer);
        REQUIRE(text != nullptr);
        CHECK_THAT(text, Catch::Matchers::ContainsSubstring("CN=localhost"));

        char *pem = nullptr;
        size_t pemlen = 0;
        CHECK(peer->to_pem(peer, 0, &pem, &pemlen) == 0);
        CHECK(pemlen > 0);
        free(pem);

        peer->free(peer);
    }

    SECTION("client presents no certificate") {
        engine_holder srv_eng(srv.tls->new_server_engine(srv.tls));
        if (srv_eng->get_peer_cert == nullptr) {
            SKIP("get_peer_cert is not implemented");
        }

        engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));
        auto t = make();
        t->attach(clt_eng, srv_eng);

        // client certs are optional: the handshake completes anyway
        REQUIRE(do_handshake(clt_eng, srv_eng));

        tlsuv_certificate_t peer = nullptr;
        CHECK(srv_eng->get_peer_cert(srv_eng, &peer) == TLS_ERR);
        CHECK(peer == nullptr);
    }
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
        tlsuv_certificate_t peer = nullptr;
        CHECK(srv_eng->get_peer_cert(srv_eng, &peer) == TLS_ERR);
        CHECK(peer == nullptr);
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

TEST_CASE("server engine over a blocking in-memory transport", "[engine][server]") {
    // small write cap so io_write returns TLS_AGAIN mid-handshake and mid-write,
    // exercising the BIO retry-write path the socket transport rarely hits
    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    srv.set_identity();

    tls_ctx_holder clt(test_ca);

    engine_holder srv_eng(srv.tls->new_server_engine(srv.tls));
    engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));

    mem_transport t(512);
    t.attach(clt_eng, srv_eng);

    REQUIRE(do_handshake(clt_eng, srv_eng));

    std::string big;
    for (int i = 0; i < 1024; i++) big += "0123456789"; // 10KB
    check_transfer(clt_eng, srv_eng, big);
}
