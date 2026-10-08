// Copyright (c) 2026. NetFoundry Inc.
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

#include <algorithm>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <catch2/catch_all.hpp>
#include <tlsuv/listener.h>
#include <tlsuv/tlsuv.h>
#include <uv.h>

#include "fixtures.h"

#if _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close_socket closesocket
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#define close_socket close
#endif

#define to_str_(x) #x
#define to_str(x) to_str_(x)
static const char *l_ca = to_str(TEST_SERVER_CA);
static const char *l_cert = to_str(TEST_SERVER_CERT);
static const char *l_key = to_str(TEST_SERVER_KEY);
static const char *l_unrelated_ca = R"(-----BEGIN CERTIFICATE-----
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

TEST_CASE("listener new/size/delete", "[listener]") {
    CHECK(tlsuv_listener_size() == sizeof(tlsuv_listener_t));
    tlsuv_listener_t *l = tlsuv_listener_new();
    REQUIRE(l != nullptr);
    tlsuv_listener_set_data(l, l);
    CHECK(tlsuv_listener_get_data(l) == l);
    tlsuv_listener_delete(l);
}

namespace {

#if !_WIN32
// Like any libuv program, ignore SIGPIPE: peers close sockets mid-handshake on purpose here, and on Linux
// (no SO_NOSIGPIPE) a write to such a socket would otherwise kill the process.
struct ignore_sigpipe {
    ignore_sigpipe() { signal(SIGPIPE, SIG_IGN); }
} ignore_sigpipe_once;
#endif

// context with a CA bundle and (optionally) the test server identity
struct ctx_holder {
    tls_context *tls;
    tlsuv_private_key_t key = nullptr;
    tlsuv_certificate_t cert = nullptr;

    ctx_holder(const char *ca, bool identity) : tls(default_tls_context()) {
        if (ca) REQUIRE(tls->set_ca_bundle(tls, ca, strlen(ca)) == 0);
        if (identity) {
            REQUIRE(tls->load_key(&key, l_key, strlen(l_key)) == 0);
            REQUIRE(tls->load_cert(&cert, l_cert, strlen(l_cert)) == 0);
            REQUIRE(tls->set_own_cert(tls, key, cert) == 0);
        }
    }
    ctx_holder(const ctx_holder &) = delete;
    ~ctx_holder() {
        if (cert) cert->free(cert);
        if (key) key->free(key);
        tls->free_ctx(tls);
    }
};

#define SKIP_UNLESS_SERVER(h)                                                    \
    do {                                                                         \
        if (!(h).tls->new_server_engine) {                                       \
            WARN("no server engine in this TLS backend");                        \
            return;                                                              \
        }                                                                        \
    } while (0)

uv_buf_t copy_buf(const char *p, size_t n) {
    char *b = (char *) malloc(n);
    memcpy(b, p, n);
    return uv_buf_init(b, (unsigned) n);
}

void alloc_buf(uv_handle_t *, size_t n, uv_buf_t *b) {
    b->base = (char *) malloc(n);
    b->len = (unsigned) n;
}

void write_str(tlsuv_stream_t *s, const std::string &msg) {
    auto *req = (uv_write_t *) malloc(sizeof(uv_write_t));
    uv_buf_t buf = copy_buf(msg.data(), msg.size());
    req->data = buf.base;
    REQUIRE(tlsuv_stream_write(req, s, &buf, [](uv_write_t *r, int) {
        free(r->data);
        free(r);
    }) == 0);
}

// accepted stream; `s` must stay the first member, the listener hands out a tlsuv_stream_t*
struct accepted {
    tlsuv_stream_t s;
    bool closing = false;
};

struct srv_fixture;
srv_fixture *g_fixture = nullptr; // handshake_cb does not receive the listener

// One listener on 127.0.0.1:<ephemeral> plus bookkeeping for accepted streams.
struct srv_fixture {
    UvLoopTest t;
    ctx_holder srv_ctx;
    tlsuv_listener_t l;
    bool inited = false;
    sockaddr_in addr{};
    int port = 0;

    std::vector<accepted *> streams;
    int accepted_cnt = 0, handshakes = 0, hs_ok = 0, closed = 0;
    int last_hs_status = 0;
    int errors = 0, last_error = 0;
    sockaddr_storage last_peer{};
    bool refuse = false;
    bool stream_on_error = false; // return a stream from accept_cb(status != 0) too
    void *data_marker = nullptr;
    std::function<void()> on_accept; // test hook, runs inside accept_cb
    bool echo = false;
    std::function<void(tlsuv_stream_t *, int)> on_hs; // test hook, runs inside handshake_cb

    // no CA bundle on the server context: with one, server engines request and require a client certificate
    explicit srv_fixture(bool identity = true) : srv_ctx(nullptr, identity) {
        g_fixture = this;
        // fails without a server engine (e.g. mbedtls); tests then skip before using the listener
        inited = tlsuv_listener_init(t.loop, &l, srv_ctx.tls) == 0;
        tlsuv_listener_set_data(&l, this);
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    }
    ~srv_fixture() {
        // tests that return early (e.g. no server engine in this backend) never reach shutdown()
        if (inited && !l.closing) {
            tlsuv_listener_close(&l, nullptr);
            t.drain();
        }
        g_fixture = nullptr;
    }

    void bind_listen() {
        REQUIRE(tlsuv_listener_bind(&l, (sockaddr *) &addr, 0) == 0);
        sockaddr_in got{};
        int len = sizeof(got);
        REQUIRE(tlsuv_listener_getsockname(&l, (sockaddr *) &got, &len) == 0);
        port = ntohs(got.sin_port);
        REQUIRE(port != 0);
        REQUIRE(tlsuv_listener_start_listen(&l, 16, accept_cb, hs_cb) == 0);
    }

    static tlsuv_stream_t *accept_cb(tlsuv_listener_t *lst, const sockaddr *peer, int status) {
        auto *f = (srv_fixture *) tlsuv_listener_get_data(lst);
        if (status != 0) {
            f->errors++;
            f->last_error = status;
            if (!f->stream_on_error) return nullptr;
            auto *a = new accepted{};
            f->streams.push_back(a);
            return &a->s;
        }
        f->accepted_cnt++;
        memcpy(&f->last_peer, peer, sizeof(sockaddr_in));
        if (f->refuse) return nullptr;
        auto *a = new accepted{};
        a->s.data = f->data_marker; // must survive tlsuv_stream_init()
        if (f->on_accept) f->on_accept();
        f->streams.push_back(a);
        return &a->s;
    }

    static void hs_cb(tlsuv_stream_t *s, int status) {
        srv_fixture *f = g_fixture;
        f->handshakes++;
        f->last_hs_status = status;
        if (status == 0) {
            f->hs_ok++;
            if (f->echo) f->start_echo(s);
        }
        if (f->on_hs) f->on_hs(s, status);
    }

    void start_echo(tlsuv_stream_t *s) {
        tlsuv_stream_read_start(s, alloc_buf, [](uv_stream_t *st, ssize_t n, const uv_buf_t *b) {
            auto *clt = (tlsuv_stream_t *) st;
            if (n > 0) write_str(clt, std::string(b->base, n));
            else if (n < 0) g_fixture->close_stream(clt);
            free(b->base);
        });
    }

    void close_stream(tlsuv_stream_t *s) {
        auto *a = (accepted *) s;
        if (a->closing) return;
        a->closing = true;
        tlsuv_stream_close(s, [](uv_handle_t *) { g_fixture->closed++; });
    }

    // close everything still open, run the loop dry, release memory
    void shutdown() {
        for (auto *a : streams) close_stream(&a->s);
        if (inited && !l.closing) tlsuv_listener_close(&l, nullptr);
        t.drain();
        for (auto *a : streams) {
            tlsuv_stream_free(&a->s);
            delete a;
        }
        streams.clear();
    }
};

struct client {
    tlsuv_stream_t s;
    uv_connect_t cr{};
    int conn_status = 1000; // set by the connect cb
    bool connected = false;
    bool closing = false, closed = false;
    std::string received;
    std::string alpn; // negotiated protocol, captured when the connect completes

    client(uv_loop_t *loop, tls_context *tls) {
        tlsuv_stream_init(loop, &s, tls);
        s.data = this;
    }
    void connect(int port) {
        // a literal address: no name resolution, which would need the libuv threadpool
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        addrinfo ai{};
        ai.ai_family = AF_INET;
        ai.ai_socktype = SOCK_STREAM;
        ai.ai_protocol = IPPROTO_TCP;
        ai.ai_addrlen = sizeof(sa);
        ai.ai_addr = (sockaddr *) &sa;
        // the name is used for SNI and certificate verification (the test certificate has an IP SAN)
        tlsuv_stream_set_hostname(&s, "127.0.0.1");
        REQUIRE(tlsuv_stream_connect_addr(&cr, &s, &ai, [](uv_connect_t *r, int st) {
            auto *c = (client *) r->handle->data;
            c->conn_status = st;
            c->connected = st == 0;
            if (st == 0) {
                const char *p = tlsuv_stream_get_protocol(&c->s);
                if (p) c->alpn = p;
                c->read(); // read_start needs an established stream
            }
        }) == 0);
    }
    void read() {
        tlsuv_stream_read_start(&s, alloc_buf, [](uv_stream_t *st, ssize_t n, const uv_buf_t *b) {
            auto *c = (client *) st->data;
            if (n > 0) c->received.append(b->base, n);
            free(b->base);
        });
    }
    void write(const std::string &msg) { write_str(&s, msg); }
    void close() {
        if (closing) return;
        closing = true;
        tlsuv_stream_close(&s, [](uv_handle_t *h) { ((client *) h->data)->closed = true; });
    }
    ~client() { tlsuv_stream_free(&s); }
};

} // namespace

TEST_CASE("listener accepts and echoes", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    ctx_holder cc(l_ca, false);
    client c(f.t.loop, cc.tls);
    DEFER { c.close(); f.shutdown(); };

    f.echo = true;
    f.bind_listen();
    c.connect(f.port);
    f.t.run(WHILE(!c.connected));
    REQUIRE(c.connected);
    c.write("hello");
    f.t.run(WHILE(c.received.size() < 5));
    CHECK(c.received == "hello");
    CHECK(f.hs_ok == 1);
    auto *peer = (sockaddr_in *) &f.last_peer;
    CHECK(peer->sin_family == AF_INET);
    CHECK(ntohl(peer->sin_addr.s_addr) == 0x7f000001);
}

TEST_CASE("listener negotiates ALPN", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    ctx_holder cc(l_ca, false);
    client c(f.t.loop, cc.tls);
    DEFER { c.close(); f.shutdown(); };

    const char *srv_protos[] = {"h2", "http/1.1"};
    REQUIRE(tlsuv_listener_set_protocols(&f.l, 2, srv_protos) == 0);
    const char *clt_protos[] = {"http/1.1"};
    tlsuv_stream_set_protocols(&c.s, 1, clt_protos);

    std::string srv_proto;
    f.on_hs = [&](tlsuv_stream_t *s, int st) {
        if (st == 0 && tlsuv_stream_get_protocol(s)) srv_proto = tlsuv_stream_get_protocol(s);
    };
    f.bind_listen();
    c.connect(f.port);
    f.t.run(WHILE(!c.connected || f.handshakes == 0));
    REQUIRE(c.connected);
    CHECK(srv_proto == "http/1.1");
    CHECK(c.alpn == "http/1.1");
}

TEST_CASE("listener: accept_cb refuses", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    // a raw TCP client: what is checked is that the listener closes the connection, not how a TLS client
    // engine reacts to it (some backends take long to report it)
    uv_os_sock_t raw = socket(AF_INET, SOCK_STREAM, 0);
    DEFER { close_socket(raw); f.shutdown(); };

    f.refuse = true;
    f.bind_listen();
    sockaddr_in a = f.addr;
    a.sin_port = htons(f.port);
    REQUIRE(connect(raw, (sockaddr *) &a, sizeof(a)) == 0);

    f.t.run(WHILE(f.accepted_cnt == 0));
    CHECK(f.accepted_cnt == 1);
    CHECK(f.handshakes == 0);
    CHECK(f.streams.empty());

    char b;
    CHECK(recv(raw, &b, 1, 0) == 0); // the server closed it: EOF
}

TEST_CASE("listener: no server certificate", "[listener][server]") {
    srv_fixture f(false); // context without set_own_cert
    SKIP_UNLESS_SERVER(f.srv_ctx);
    ctx_holder cc(l_ca, false);
    client c(f.t.loop, cc.tls);
    DEFER { c.close(); f.shutdown(); };

    f.on_hs = [&](tlsuv_stream_t *s, int) { f.close_stream(s); };
    f.bind_listen(); // must still succeed
    c.connect(f.port);
    f.t.run(WHILE(f.handshakes == 0 || c.conn_status == 1000));
    CHECK(f.last_hs_status == UV_EINVAL);
    CHECK(c.conn_status != 0);
}

TEST_CASE("listener: handshake failure leaves stream closable", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    ctx_holder cc(l_unrelated_ca, false); // client does not trust the server
    client c(f.t.loop, cc.tls);
    DEFER { c.close(); f.shutdown(); };

    f.on_hs = [&](tlsuv_stream_t *s, int) { f.close_stream(s); };
    f.bind_listen();
    c.connect(f.port);
    f.t.run(WHILE(f.handshakes == 0 || c.conn_status == 1000));
    CHECK(c.conn_status != 0);
    // the server may report success or failure here: a TLS 1.3 server can complete its side before it learns
    // that the client rejected its certificate. Either way it is called once and the stream is closable.
    f.t.run(WHILE(f.closed < 1));
    CHECK(f.handshakes == 1); // still exactly once after close
}

TEST_CASE("listener: stalled handshake closed by app", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    uv_os_sock_t raw = socket(AF_INET, SOCK_STREAM, 0);
    DEFER { close_socket(raw); f.shutdown(); };
    f.bind_listen();

    // raw TCP client that never speaks TLS
    sockaddr_in a = f.addr;
    a.sin_port = htons(f.port);
    REQUIRE(connect(raw, (sockaddr *) &a, sizeof(a)) == 0);

    f.t.run(WHILE(f.accepted_cnt == 0));
    REQUIRE(f.streams.size() == 1);
    CHECK(f.handshakes == 0);

    f.close_stream(&f.streams[0]->s); // the "timeout" decision belongs to the app
    f.t.run(WHILE(f.handshakes == 0 || f.closed == 0));
    CHECK(f.handshakes == 1);
    CHECK(f.last_hs_status == UV_ECANCELED);
}

TEST_CASE("listener: closing listener keeps in-flight handshakes", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    ctx_holder cc(l_ca, false);
    client c(f.t.loop, cc.tls);
    DEFER { c.close(); f.shutdown(); };

    f.echo = true;
    f.bind_listen();
    c.connect(f.port);
    f.t.run(WHILE(f.accepted_cnt == 0));
    REQUIRE(tlsuv_listener_close(&f.l, nullptr) == 0); // handshake still in progress
    f.t.run(WHILE(!c.connected));
    REQUIRE(c.connected);
    c.write("ping");
    f.t.run(WHILE(c.received.size() < 4));
    CHECK(c.received == "ping");
    CHECK(f.hs_ok == 1);
}

TEST_CASE("listener: many concurrent clients", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    ctx_holder cc(l_ca, false);
    constexpr int N = 8;
    std::vector<std::unique_ptr<client>> cs;
    DEFER {
        for (auto &c : cs) c->close();
        f.shutdown();
    };

    f.bind_listen();
    for (int i = 0; i < N; i++) {
        cs.emplace_back(new client(f.t.loop, cc.tls));
        cs.back()->connect(f.port);
    }
    f.t.run(WHILE(f.handshakes < N));
    CHECK(f.hs_ok == N);
}

TEST_CASE("listener: argument errors", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    DEFER { f.shutdown(); };
    auto acb = srv_fixture::accept_cb;
    auto hcb = srv_fixture::hs_cb;

    CHECK(tlsuv_listener_start_listen(&f.l, 8, acb, hcb) == UV_EINVAL); // not bound
    REQUIRE(tlsuv_listener_bind(&f.l, (sockaddr *) &f.addr, 0) == 0);
    CHECK(tlsuv_listener_bind(&f.l, (sockaddr *) &f.addr, 0) == UV_EALREADY);
    CHECK(tlsuv_listener_start_listen(&f.l, 8, nullptr, hcb) == UV_EINVAL);
    CHECK(tlsuv_listener_start_listen(&f.l, 8, acb, nullptr) == UV_EINVAL);
    REQUIRE(tlsuv_listener_start_listen(&f.l, 8, acb, hcb) == 0);
    CHECK(tlsuv_listener_start_listen(&f.l, 8, acb, hcb) == UV_EALREADY);

    REQUIRE(tlsuv_listener_close(&f.l, nullptr) == 0);
    CHECK(tlsuv_listener_start_listen(&f.l, 8, acb, hcb) == UV_EINVAL);
    CHECK(tlsuv_listener_bind(&f.l, (sockaddr *) &f.addr, 0) == UV_EINVAL);
    CHECK(tlsuv_listener_stop_listen(&f.l) == UV_EINVAL);
}

TEST_CASE("listener: init fails without a server engine", "[listener][server]") {
    ctx_holder h(l_ca, false);
    h.tls->new_server_engine = nullptr; // simulate a backend without server support (e.g. mbedtls)
    UvLoopTest t;
    tlsuv_listener_t l;
    CHECK(tlsuv_listener_init(t.loop, &l, h.tls) == UV_ENOTSUP);
}

TEST_CASE("listener: bind to address in use", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    tlsuv_listener_t other;
    DEFER { tlsuv_listener_close(&other, nullptr); f.shutdown(); };
    f.bind_listen(); // listening on an ephemeral port

    tlsuv_listener_init(f.t.loop, &other, f.srv_ctx.tls);
    sockaddr_in a = f.addr;
    a.sin_port = htons(f.port);
    // other platforms may report a different code than EADDRINUSE, so only require failure
    CHECK(tlsuv_listener_bind(&other, (sockaddr *) &a, 0) != 0);
}

TEST_CASE("listener: stop_listen queues, start_listen resumes", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    ctx_holder cc(l_ca, false);
    client c(f.t.loop, cc.tls);
    DEFER { c.close(); f.shutdown(); };

    f.bind_listen();
    REQUIRE(tlsuv_listener_stop_listen(&f.l) == 0);

    c.connect(f.port);
    f.t.run(1); // no accept while stopped
    CHECK(f.accepted_cnt == 0);

    REQUIRE(tlsuv_listener_start_listen(&f.l, 16, srv_fixture::accept_cb, srv_fixture::hs_cb) == 0);
    f.t.run(WHILE(!c.connected || f.hs_ok < 1));
    CHECK(c.connected);
    CHECK(f.accepted_cnt == 1);
    CHECK(f.hs_ok == 1);
}

TEST_CASE("listener: init requires a TLS context", "[listener]") {
    UvLoopTest t;
    tlsuv_listener_t l;
    // a server context needs its own certificate, so there is no usable default
    CHECK(tlsuv_listener_init(t.loop, &l, nullptr) == UV_EINVAL);
}

TEST_CASE("listener: stream data set in accept_cb is preserved", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    ctx_holder cc(l_ca, false);
    client c(f.t.loop, cc.tls);
    DEFER { c.close(); f.shutdown(); };

    int marker = 0;
    f.data_marker = &marker;
    void *seen = nullptr;
    f.on_hs = [&](tlsuv_stream_t *s, int) { seen = tlsuv_stream_get_data(s); };
    f.bind_listen();
    c.connect(f.port);
    f.t.run(WHILE(f.handshakes == 0));
    CHECK(seen == &marker);
}

TEST_CASE("listener: stop_listen from accept_cb", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    ctx_holder cc(l_ca, false);
    client c1(f.t.loop, cc.tls);
    client c2(f.t.loop, cc.tls);
    DEFER { c1.close(); c2.close(); f.shutdown(); };

    f.on_accept = [&] { REQUIRE(tlsuv_listener_stop_listen(&f.l) == 0); };
    f.bind_listen();
    // both connections are queued before the loop runs, so one wake sees both
    c1.connect(f.port);
    c2.connect(f.port);

    // wait for the first connection's handshake instead of for a fixed time (slow under valgrind). If the
    // listener had not stopped, the second connection would have been accepted in the same wake as the first.
    f.t.run(WHILE(f.hs_ok < 1 || !(c1.connected || c2.connected)));
    CHECK(f.accepted_cnt == 1); // the second stays in the kernel backlog
    CHECK(f.hs_ok == 1);        // the stream accepted before the stop still completes
    CHECK(c1.connected != c2.connected);

    f.on_accept = nullptr;
    REQUIRE(tlsuv_listener_start_listen(&f.l, 16, srv_fixture::accept_cb, srv_fixture::hs_cb) == 0);
    f.t.run(WHILE(!c1.connected || !c2.connected || f.hs_ok < 2));
    CHECK(f.accepted_cnt == 2);
    CHECK(f.hs_ok == 2);
}

#if !_WIN32
TEST_CASE("listener: fd exhaustion sheds the backlog and is reported", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    SECTION("app returns NULL for the error") { f.stream_on_error = false; }
    SECTION("app returns a stream for the error") { f.stream_on_error = true; }
    std::vector<int> hogs;
    uv_os_sock_t raw = socket(AF_INET, SOCK_STREAM, 0);
    uv_os_sock_t raw2 = socket(AF_INET, SOCK_STREAM, 0);
    DEFER {
        for (int fd : hogs) close(fd);
        close_socket(raw);
        close_socket(raw2);
        f.shutdown();
    };

    f.bind_listen();
    // a connection waiting in the backlog; the connect completes without accept()
    sockaddr_in a = f.addr;
    a.sin_port = htons(f.port);
    REQUIRE(connect(raw, (sockaddr *) &a, sizeof(a)) == 0);

    // While the process has no descriptors left, only do raw work and record plain values: Catch2 and the
    // sanitizer runtimes need descriptors of their own (e.g. pipes), and abort the process without them.
    int fd;
    while ((fd = open("/dev/null", O_RDONLY)) >= 0) hogs.push_back(fd);
    const int open_errno = errno;

    // accept() fails; the listener sheds the queued connection with its spare descriptor and tells the app
    f.t.run(WHILE(f.errors == 0));
    const int accepted_after_error = f.accepted_cnt;
    const int error_status = f.last_error;

    // backlog is empty now: no spinning, no repeated reports
    f.t.run(1);
    const int errors_after_wait = f.errors;
    const int handshakes = f.handshakes, hs_status = f.last_hs_status, hs_ok = f.hs_ok;
    const size_t streams = f.streams.size();

    // the shed connection was closed by the server
    char c;
    const ssize_t recv_rc = recv(raw, &c, 1, 0);

    // descriptors are available again
    for (int h : hogs) close(h);
    hogs.clear();

    REQUIRE((open_errno == EMFILE || open_errno == ENFILE));
    CHECK((error_status == UV_EMFILE || error_status == UV_ENFILE));
    CHECK(accepted_after_error == 0);
    CHECK(errors_after_wait == 1);
    CHECK(recv_rc == 0);
    if (f.stream_on_error) {
        // the stream the app returned gets handshake_cb with the same error and is the app's to close
        CHECK(handshakes == 1);
        CHECK(hs_status == error_status);
        CHECK(hs_ok == 0);
        REQUIRE(streams == 1);
        f.close_stream(&f.streams[0]->s);
        f.t.run(WHILE(f.closed == 0));
    } else {
        CHECK(handshakes == 0);
    }

    // the listener never stopped, so new connections are accepted
    REQUIRE(connect(raw2, (sockaddr *) &a, sizeof(a)) == 0);
    f.t.run(WHILE(f.accepted_cnt == 0));
    CHECK(f.accepted_cnt == 1);
    CHECK(f.errors == 1);
}
#endif

TEST_CASE("listener: init preserves data", "[listener]") {
    ctx_holder h(l_ca, false);
    if (!h.tls->new_server_engine) {
        WARN("no server engine in this TLS backend");
        return;
    }
    UvLoopTest t;
    int marker = 0;
    tlsuv_listener_t l;
    uv_handle_set_data((uv_handle_t *) &l, &marker); // like libuv, init leaves `data` as the caller set it
    REQUIRE(tlsuv_listener_init(t.loop, &l, h.tls) == 0);
    CHECK(tlsuv_listener_get_data(&l) == &marker);
    CHECK(uv_handle_get_data((uv_handle_t *) &l) == &marker);
    CHECK(uv_handle_get_loop((uv_handle_t *) &l) == t.loop);
    tlsuv_listener_close(&l, nullptr);
    t.drain();
}

TEST_CASE("listener: is a uv handle once bound", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    auto *h = (uv_handle_t *) &f.l;

    // the poll handle is only set up by bind(); before that only data and loop are valid
    CHECK(uv_handle_get_data(h) == &f);
    CHECK(uv_handle_get_loop(h) == f.t.loop);

    REQUIRE(tlsuv_listener_bind(&f.l, (sockaddr *) &f.addr, 0) == 0);
    CHECK(uv_handle_get_data(h) == &f); // the handle init must leave it alone
    CHECK(uv_handle_get_loop(h) == f.t.loop);
    CHECK(uv_handle_get_type(h) == UV_POLL);
    CHECK(!uv_is_active(h));
    CHECK(!uv_is_closing(h));

    bool seen = false;
    auto find = [&] {
        struct arg_s { uv_handle_t *h; bool *seen; } arg{h, &seen};
        uv_walk(f.t.loop, [](uv_handle_t *w, void *a) {
            auto *p = (arg_s *) a;
            if (w == p->h) *p->seen = true;
        }, &arg);
    };
    find();
    CHECK(seen);

    sockaddr_in got{};
    int len = sizeof(got);
    REQUIRE(tlsuv_listener_getsockname(&f.l, (sockaddr *) &got, &len) == 0);
    f.port = ntohs(got.sin_port);
    REQUIRE(tlsuv_listener_start_listen(&f.l, 16, srv_fixture::accept_cb, srv_fixture::hs_cb) == 0);
    CHECK(uv_is_active(h));
    REQUIRE(tlsuv_listener_stop_listen(&f.l) == 0);
    CHECK(!uv_is_active(h));
    REQUIRE(tlsuv_listener_start_listen(&f.l, 16, srv_fixture::accept_cb, srv_fixture::hs_cb) == 0);
    CHECK(uv_is_active(h));

    // a listening, referenced listener keeps the loop alive; an unreferenced one does not
    CHECK(uv_loop_alive(f.t.loop));
    uv_unref(h);
    CHECK(!uv_has_ref(h));
    CHECK(!uv_loop_alive(f.t.loop));
    uv_ref(h);
    CHECK(uv_loop_alive(f.t.loop));

    // the close callback gets the same handle
    static uv_handle_t *closed_h;
    closed_h = nullptr;
    REQUIRE(tlsuv_listener_close(&f.l, [](uv_handle_t *c) { closed_h = c; }) == 0);
    CHECK(uv_is_closing(h));
    f.t.drain();
    CHECK(closed_h == h);
}

TEST_CASE("listener: close while bound but not listening", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);
    REQUIRE(tlsuv_listener_bind(&f.l, (sockaddr *) &f.addr, 0) == 0);

    static int closed;
    closed = 0;
    REQUIRE(tlsuv_listener_close(&f.l, [](uv_handle_t *) { closed++; }) == 0);
    CHECK(closed == 0); // deferred to the loop
    f.t.drain();
    CHECK(closed == 1);
}

TEST_CASE("listener: close before bind", "[listener][server]") {
    srv_fixture f;
    SKIP_UNLESS_SERVER(f.srv_ctx);

    static int closed;
    closed = 0;
    REQUIRE(tlsuv_listener_close(&f.l, [](uv_handle_t *) { closed++; }) == 0);
    CHECK(closed == 0);
    f.t.drain();
    CHECK(closed == 1);
}
