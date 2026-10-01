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
        // async engines (applesec) make progress on their own threads between calls
        uv_sleep(1);
    }
    return false;
}

static int read_some(tlsuv_engine_t e, char *buf, size_t cap, size_t *out) {
    *out = 0;
    for (int i = 0; i < MAX_ITERATIONS; i++) {
        int rc = e->read(e, buf, out, cap);
        if (rc != TLS_AGAIN) return rc;
        uv_sleep(1);
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
        } else if (from->setup_async) {
            // async engines produce ciphertext after write() returns and push it out
            // when called again (tlsuv_stream_t/tls_link do this on each wakeup)
            from->write(from, nullptr, 0);
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
        tls = default_tls_context();
        // the destructor does not run when the constructor throws
        bool ready = false;
        DEFER { if (!ready) tls->free_ctx(tls); };
        if (ca) {
            REQUIRE(tls->set_ca_bundle(tls, ca, strlen(ca)) == 0);
        }
        ready = true;
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

// frees the certificate even when a REQUIRE throws
struct cert_holder {
    tlsuv_certificate_t c = nullptr;
    cert_holder() = default;
    cert_holder(const cert_holder &) = delete;
    cert_holder &operator=(const cert_holder &) = delete;
    ~cert_holder() { if (c) c->free(c); }
};

#define SKIP_UNLESS_SERVER_SUPPORTED(holder)                                  \
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

TEST_CASE("require_fips engines complete a handshake", "[engine][server]") {
    bool restrict_server = GENERATE(true, false);
    bool restrict_client = GENERATE(true, false);
    INFO("restrict_server=" << restrict_server << " restrict_client=" << restrict_client);

    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    REQUIRE(srv.tls->require_fips != nullptr);
    // restricting *before* configuring the context must stick
    if (restrict_server) srv.tls->require_fips(srv.tls);
    srv.set_identity();

    tls_ctx_holder clt(test_ca);
    if (restrict_client) clt.tls->require_fips(clt.tls);

    engine_holder srv_eng(srv.tls->new_server_engine(srv.tls));
    engine_holder clt_eng(clt.tls->new_engine(clt.tls, test_host));
    REQUIRE(srv_eng.e != nullptr);
    REQUIRE(clt_eng.e != nullptr);

    auto t = make_mem();
    t->attach(clt_eng, srv_eng);

    REQUIRE(do_handshake(clt_eng, srv_eng));
    check_transfer(clt_eng, srv_eng, "hello server");
    check_transfer(srv_eng, clt_eng, "hello client");
}

#if defined(TEST_OPENSSL_PEER)
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <vector>

namespace {
// What the raw server offers. null/0 means "library default".
struct peer_policy {
    const char *name;
    int max_version;
    const char *ciphers; // TLS 1.2 cipher list
    const char *groups;
    bool needs_suite_control;  // rejection relies on suite restriction (all backends)
    bool needs_group_control;  // rejection relies on group restriction
    bool needs_kex_control;    // rejection relies on removing static-RSA key exchange
    int min_version = 0;       // 0 = library default
};

// Does this backend enforce the restriction the policy relies on?
// win32crypto (Schannel) can only disable CBC, ChaCha20, SHA-1 and DH; applesec only
// restricts suites (see README matrix).
bool backend_enforces(const peer_policy &p) {
#if defined(TEST_openssl) || defined(TEST_boringssl) || defined(TEST_mbedtls)
    return true;
#elif defined(TEST_applesec)
    return !p.needs_group_control;
#else // win32crypto
    return !p.needs_group_control && !p.needs_kex_control;
#endif
}

// The TLS peer the engine under test talks to: a plain OpenSSL/BoringSSL server (or, with
// as_client, client) whose protocol versions, suites and groups come from a peer_policy.
struct raw_peer {
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
    BIO *rbio = nullptr; // bytes from the engine
    BIO *wbio = nullptr; // bytes to the engine
    bool client;
    bool failed = false;
    // false when the library cannot do what the policy asks (e.g. TLS 1.0 compiled out)
    bool configured = true;

    explicit raw_peer(const peer_policy &p, bool as_client = false) : client(as_client) {
        ctx = SSL_CTX_new(as_client ? TLS_client_method() : TLS_server_method());
        REQUIRE(ctx != nullptr);
        if (!as_client) {
            REQUIRE(SSL_CTX_use_certificate_chain_file(ctx, test_cert) == 1);
            REQUIRE(SSL_CTX_use_PrivateKey_file(ctx, test_key, SSL_FILETYPE_PEM) == 1);
        }
        if (p.min_version) configured &= SSL_CTX_set_min_proto_version(ctx, p.min_version) == 1;
        if (p.max_version) configured &= SSL_CTX_set_max_proto_version(ctx, p.max_version) == 1;
        if (p.ciphers) configured &= SSL_CTX_set_cipher_list(ctx, p.ciphers) == 1;
        if (p.groups) configured &= SSL_CTX_set1_groups_list(ctx, p.groups) == 1;

        ssl = SSL_new(ctx);
        rbio = BIO_new(BIO_s_mem());
        wbio = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl, rbio, wbio); // ssl owns both BIOs
        if (as_client) {
            SSL_set_connect_state(ssl);
        } else {
            SSL_set_accept_state(ssl);
        }
    }

    raw_peer(const raw_peer &) = delete;
    raw_peer &operator=(const raw_peer &) = delete;

    ~raw_peer() {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }

    // Feeds what the other side wrote into this peer, runs its handshake one step, and
    // flushes what it produced (including a failure alert) back out.
    // Returns true once this peer's handshake is complete.
    bool pump(mem_pipe &incoming, mem_pipe &outgoing) {
        if (!incoming.buf.empty()) {
            std::vector<char> in(incoming.buf.begin(), incoming.buf.end());
            incoming.buf.clear();
            BIO_write(rbio, in.data(), (int) in.size());
        }

        int rc = SSL_is_init_finished(ssl) ? 1 : (client ? SSL_connect(ssl) : SSL_accept(ssl));
        if (rc <= 0) {
            int err = SSL_get_error(ssl, rc);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) failed = true;
        }

        char out[4096];
        int n;
        while ((n = BIO_read(wbio, out, sizeof(out))) > 0) {
            outgoing.buf.insert(outgoing.buf.end(), out, out + n);
        }
        return rc == 1;
    }
};

// Runs a tlsuv engine (client or server) against the raw peer over two memory pipes.
// True when both sides completed the handshake.
bool handshake_with_raw_peer(tlsuv_engine_t eng, raw_peer &peer) {
    REQUIRE(peer.configured);
    mem_pipe to_peer, to_engine;
    mem_endpoint eng_ep{&to_engine, &to_peer};
    eng->set_io(eng, &eng_ep, mem_read, mem_write);

    bool peer_done = false;
    for (int i = 0; i < MAX_ITERATIONS; i++) {
        tls_handshake_state es = eng->handshake(eng);
        peer_done = peer.pump(to_peer, to_engine) || peer_done;
        if (es == TLS_HS_ERROR || peer.failed) return false;
        if (es == TLS_HS_COMPLETE && peer_done) return true;
        uv_sleep(1); // async engines (applesec) progress on their own threads
    }
    return false;
}

const std::vector<peer_policy> approved_peers = {
    {"TLS 1.2 ECDHE-RSA AES-GCM", TLS1_2_VERSION,
     "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256", nullptr, false, false, false},
    {"library defaults (TLS 1.3)", 0, nullptr, nullptr, false, false, false},
};

const std::vector<peer_policy> rejected_peers = {
    {"TLS 1.2 ChaCha20 only", TLS1_2_VERSION, "ECDHE-RSA-CHACHA20-POLY1305", nullptr, true, false, false},
    {"TLS 1.2 AES-CBC only", TLS1_2_VERSION, "ECDHE-RSA-AES128-SHA", nullptr, true, false, false},
    {"TLS 1.2 static-RSA key exchange only", TLS1_2_VERSION, "AES128-GCM-SHA256", nullptr, true, false, true},
    {"X25519 only", 0, nullptr, "X25519", true, true, false},
};
} // namespace

TEST_CASE("require_fips client completes a handshake with approved peers", "[engine][server]") {
    auto policy = GENERATE_COPY(from_range(approved_peers));
    INFO("peer: " << policy.name);

    tls_ctx_holder clt(test_ca);
    REQUIRE(clt.tls->require_fips != nullptr);
    clt.tls->require_fips(clt.tls);
    engine_holder eng(clt.tls->new_engine(clt.tls, test_host));
    REQUIRE(eng.e != nullptr);

    raw_peer peer(policy);
    REQUIRE(handshake_with_raw_peer(eng, peer));

    // what the peer actually negotiated, from the server's side of the wire
    const SSL_CIPHER *cipher = SSL_get_current_cipher(peer.ssl);
    REQUIRE(cipher != nullptr);
    INFO("negotiated: " << SSL_CIPHER_get_name(cipher));
    CHECK_THAT(SSL_CIPHER_get_name(cipher), Catch::Matchers::ContainsSubstring("GCM"));
}

TEST_CASE("require_fips client rejects peers offering only non-approved algorithms",
          "[engine][server]") {
    auto policy = GENERATE_COPY(from_range(rejected_peers));
    INFO("peer: " << policy.name);

    if (!backend_enforces(policy)) {
        SKIP("this backend cannot restrict what this peer relies on (see README matrix)");
    }

    // control: an unrestricted client must get through, or the rejection below proves nothing
    {
        tls_ctx_holder plain(test_ca);
        engine_holder eng(plain.tls->new_engine(plain.tls, test_host));
        REQUIRE(eng.e != nullptr);
        raw_peer peer(policy);
        bool ok = handshake_with_raw_peer(eng, peer);
#if defined(TEST_win32crypto)
        // which legacy suites Schannel accepts depends on the Windows version
        if (!ok) SKIP("Schannel does not accept this peer even unrestricted");
#else
        REQUIRE(ok);
#endif
    }

    tls_ctx_holder fips(test_ca);
    REQUIRE(fips.tls->require_fips != nullptr);
    fips.tls->require_fips(fips.tls);
    engine_holder eng(fips.tls->new_engine(fips.tls, test_host));
    REQUIRE(eng.e != nullptr);
    raw_peer peer(policy);
    CHECK_FALSE(handshake_with_raw_peer(eng, peer));
}

namespace {
// Protocol floor: TLS 1.0/1.1-only peers. OpenSSL 3's default security level refuses
// these, so lower it; BoringSSL has no security levels.
#if defined(OPENSSL_IS_BORINGSSL)
#define LEGACY_CIPHERS "ECDHE-RSA-AES128-SHA"
#else
#define LEGACY_CIPHERS "ECDHE-RSA-AES128-SHA:@SECLEVEL=0"
#endif

const std::vector<peer_policy> legacy_peers = {
    {"TLS 1.1 only", TLS1_1_VERSION, LEGACY_CIPHERS, nullptr, false, false, false, TLS1_VERSION},
    {"TLS 1.0 only", TLS1_VERSION, LEGACY_CIPHERS, nullptr, false, false, false, TLS1_VERSION},
};

// control: the raw library really speaks this version as server and as client, so a
// refusal below is the engine's doing and not a broken peer
bool legacy_peer_usable(const peer_policy &p) {
    raw_peer srv(p), clt(p, true);
    if (!srv.configured || !clt.configured) return false;

    mem_pipe to_srv, to_clt;
    bool srv_done = false, clt_done = false;
    for (int i = 0; i < 100 && !(srv_done && clt_done); i++) {
        clt_done = clt.pump(to_clt, to_srv) || clt_done;
        srv_done = srv.pump(to_srv, to_clt) || srv_done;
    }
    return srv_done && clt_done;
}
} // namespace

TEST_CASE("client engines refuse TLS versions below 1.2", "[engine][server]") {
    auto policy = GENERATE_COPY(from_range(legacy_peers));
    bool restricted = GENERATE(false, true);
    INFO("peer: " << policy.name << " restricted=" << restricted);
    if (!legacy_peer_usable(policy)) SKIP("the OpenSSL build under test cannot speak this version");

    tls_ctx_holder clt(test_ca);
    if (restricted) {
        REQUIRE(clt.tls->require_fips != nullptr);
        clt.tls->require_fips(clt.tls);
    }
    engine_holder eng(clt.tls->new_engine(clt.tls, test_host));
    REQUIRE(eng.e != nullptr);

    raw_peer peer(policy);
    CHECK_FALSE(handshake_with_raw_peer(eng, peer));
}

TEST_CASE("server engines refuse TLS versions below 1.2", "[engine][server]") {
    auto policy = GENERATE_COPY(from_range(legacy_peers));
    bool restricted = GENERATE(false, true);
    INFO("peer: " << policy.name << " restricted=" << restricted);

    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    if (!legacy_peer_usable(policy)) SKIP("the OpenSSL build under test cannot speak this version");
    if (restricted) {
        REQUIRE(srv.tls->require_fips != nullptr);
        srv.tls->require_fips(srv.tls);
    }
    srv.set_identity();
    engine_holder eng(srv.tls->new_server_engine(srv.tls));
    REQUIRE(eng.e != nullptr);

    raw_peer peer(policy, /*as_client=*/true);
    CHECK_FALSE(handshake_with_raw_peer(eng, peer));
}
#endif // TEST_OPENSSL_PEER

