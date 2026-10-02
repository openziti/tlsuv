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

// Tests of tls_context->require_fips() and fips_status(): the restricted algorithm
// policy for client and server engines, checked against in-process raw OpenSSL
// peers where the build has one (TEST_OPENSSL_PEER).

#include <catch2/catch_all.hpp>

#include <tlsuv/tls_engine.h>
#include <uv.h>

#include <cstring>
#include <string>

#include "engine_fixtures.h"

TEST_CASE (
"fips status"
,
"[engine][fips]"
)
 {
    tls_context *tls = default_tls_context();

    // every backend implements this one, so a compliance check can never be
    // skipped by accident
    REQUIRE(tls->fips_status != nullptr);

    // NULL/0 buffer is always legal
    auto rc = tls->fips_status(tls, nullptr, 0);

#if defined(TEST_mbedtls)
    CHECK (rc== TLS_FIPS_UNSUPPORTED);
#else
    CHECK(rc != TLS_FIPS_UNSUPPORTED);
#endif

    char mod[128];
    memset(mod, 'x', sizeof(mod));
    CHECK(tls->fips_status(tls, mod, sizeof(mod)) == rc);
    if (rc == TLS_FIPS_ENABLED) {
        INFO("FIPS module: " << mod);
        CHECK(strlen(mod) > 0);
    } else {
        CHECK(mod[0] == 0);
    }

#if defined(TEST_openssl) || defined(TEST_win32crypto)
    // version() reports FIPS as free text; the two must not disagree
    CHECK ((strstr(tls->version(), "FIPS") != nullptr) == (rc== TLS_FIPS_ENABLED));
#endif

    tls->free_ctx(tls);
}

TEST_CASE("require fips", "[engine][fips]") {
    tls_context *tls = default_tls_context();

    // mandatory on every backend, like fips_status
    REQUIRE(tls->require_fips != nullptr);

    auto expected = tls->fips_status(tls, nullptr, 0);
    CHECK(tls->require_fips(tls) == expected);
    // idempotent
    CHECK(tls->require_fips(tls) == expected);
    // reporting is unaffected
    CHECK(tls->fips_status(tls, nullptr, 0) == expected);

    // the restricted context still creates engines
    auto eng = tls->new_engine(tls, "localhost");
    REQUIRE(eng != nullptr);
    eng->free(eng);

    tls->free_ctx(tls);
}

TEST_CASE("require_fips engines complete a handshake", "[engine][server][fips]") {
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
    // handshake messages this peer sent and received, by type (4 = NewSessionTicket,
    // 24 = KeyUpdate), including TLS 1.3 post-handshake messages
    int hs_sent[256] = {};
    int hs_received[256] = {};

    static void on_msg(int write_p, int, int content_type, const void *buf, size_t len, SSL *, void *arg) {
        if (content_type != SSL3_RT_HANDSHAKE || len == 0) return;
        auto *self = static_cast<raw_peer *>(arg);
        unsigned char type = *static_cast<const unsigned char *>(buf);
        (write_p ? self->hs_sent : self->hs_received)[type]++;
    }

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
        SSL_set_msg_callback(ssl, on_msg);
        SSL_set_msg_callback_arg(ssl, this);
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
        feed(incoming);

        int rc = SSL_is_init_finished(ssl) ? 1 : (client ? SSL_connect(ssl) : SSL_accept(ssl));
        if (rc <= 0) {
            int err = SSL_get_error(ssl, rc);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) failed = true;
        }

        flush(outgoing);
        return rc == 1;
    }

    // After the handshake: writes application data (preceded by anything pending, such
    // as a KeyUpdate) and flushes the records out.
    bool send(const std::string &data, mem_pipe &outgoing) {
        int n = SSL_write(ssl, data.data(), (int) data.size());
        flush(outgoing);
        return n == (int) data.size();
    }

    // After the handshake: feeds what the other side wrote and returns the application
    // data it carried; post-handshake messages are processed, and any answer flushed out.
    std::string receive(mem_pipe &incoming, mem_pipe &outgoing) {
        feed(incoming);
        std::string got;
        char buf[4096];
        for (;;) {
            int n = SSL_read(ssl, buf, sizeof(buf));
            if (n > 0) {
                got.append(buf, (size_t) n);
                continue;
            }
            int err = SSL_get_error(ssl, n);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) failed = true;
            break;
        }
        flush(outgoing);
        return got;
    }

private:
    void feed(mem_pipe &incoming) {
        if (!incoming.buf.empty()) {
            std::vector<char> in(incoming.buf.begin(), incoming.buf.end());
            incoming.buf.clear();
            BIO_write(rbio, in.data(), (int) in.size());
        }
    }

    void flush(mem_pipe &outgoing) {
        char out[4096];
        int n;
        while ((n = BIO_read(wbio, out, sizeof(out))) > 0) {
            outgoing.buf.insert(outgoing.buf.end(), out, out + n);
        }
    }
};

// The memory pipes between an engine and a raw_peer: they must outlive the handshake
// when the test goes on to exchange data.
struct raw_link {
    mem_pipe to_peer, to_engine;
    mem_endpoint eng_ep{&to_engine, &to_peer};
};

// Runs a tlsuv engine (client or server) against the raw peer over two memory pipes.
// True when both sides completed the handshake, false when either side failed it;
// a handshake that does neither fails the test.
bool handshake_with_raw_peer(tlsuv_engine_t eng, raw_peer &peer, raw_link &link) {
    REQUIRE(peer.configured);
    eng->set_io(eng, &link.eng_ep, mem_read, mem_write);

    bool peer_done = false;
    for (int i = 0; i < MAX_ITERATIONS; i++) {
        tls_handshake_state es = eng->handshake(eng);
        peer_done = peer.pump(link.to_peer, link.to_engine) || peer_done;
        if (es == TLS_HS_ERROR || peer.failed) return false;
        if (es == TLS_HS_COMPLETE && peer_done) return true;
        uv_sleep(1); // async engines (applesec) progress on their own threads
    }
    // a refusal must be reported by the engine or the peer; running out of
    // iterations means the handshake hung, which no test here expects
    FAIL("handshake neither completed nor failed");
    return false;
}

bool handshake_with_raw_peer(tlsuv_engine_t eng, raw_peer &peer) {
    raw_link link;
    return handshake_with_raw_peer(eng, peer, link);
}

// Control handshakes: an unrestricted engine must get through, or the rejection that
// follows proves nothing. Schannel and Network.framework only accept the legacy suites
// the OS version still allows, so there the peer may legitimately be refused.
#if defined(TEST_win32crypto) || defined(TEST_applesec)
#define CHECK_CONTROL_ACCEPTED(ok) \
    do { \
        if (!(ok)) SKIP("peer not accepted even unrestricted"); \
    } while (0)
#else
#define CHECK_CONTROL_ACCEPTED(ok) REQUIRE(ok)
#endif

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

TEST_CASE("require_fips client completes a handshake with approved peers", "[engine][server][fips]") {
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
          "[engine][server][fips]") {
    auto policy = GENERATE_COPY(from_range(rejected_peers));
    INFO("peer: " << policy.name);

    if (!backend_enforces(policy)) {
        SKIP("this backend cannot restrict what this peer relies on (see README matrix)");
    }

    // control: an unrestricted client must get through
    {
        tls_ctx_holder plain(test_ca);
        engine_holder eng(plain.tls->new_engine(plain.tls, test_host));
        REQUIRE(eng.e != nullptr);
        raw_peer peer(policy);
        CHECK_CONTROL_ACCEPTED(handshake_with_raw_peer(eng, peer));
    }

    tls_ctx_holder fips(test_ca);
    REQUIRE(fips.tls->require_fips != nullptr);
    fips.tls->require_fips(fips.tls);
    engine_holder eng(fips.tls->new_engine(fips.tls, test_host));
    REQUIRE(eng.e != nullptr);
    raw_peer peer(policy);
    CHECK_FALSE(handshake_with_raw_peer(eng, peer));
}

TEST_CASE("require_fips server engine completes a handshake with approved clients",
          "[engine][server][fips]") {
    auto policy = GENERATE_COPY(from_range(approved_peers));
    INFO("peer: " << policy.name);

    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    REQUIRE(srv.tls->require_fips != nullptr);
    srv.tls->require_fips(srv.tls);
    srv.set_identity();
    engine_holder eng(srv.tls->new_server_engine(srv.tls));
    REQUIRE(eng.e != nullptr);

    raw_peer peer(policy, /*as_client=*/true);
    REQUIRE(handshake_with_raw_peer(eng, peer));

    const SSL_CIPHER *cipher = SSL_get_current_cipher(peer.ssl);
    REQUIRE(cipher != nullptr);
    INFO("negotiated: " << SSL_CIPHER_get_name(cipher));
    CHECK_THAT(SSL_CIPHER_get_name(cipher), Catch::Matchers::ContainsSubstring("GCM"));
}

TEST_CASE("require_fips server engine rejects clients offering only non-approved algorithms",
          "[engine][server][fips]") {
    auto policy = GENERATE_COPY(from_range(rejected_peers));
    INFO("peer: " << policy.name);

    if (!backend_enforces(policy)) {
        SKIP("this backend cannot restrict what this peer relies on (see README matrix)");
    }

    // control: an unrestricted server must get through
    {
        tls_ctx_holder plain(test_ca);
        SKIP_UNLESS_SERVER_SUPPORTED(plain);
        plain.set_identity();
        engine_holder eng(plain.tls->new_server_engine(plain.tls));
        REQUIRE(eng.e != nullptr);
        raw_peer peer(policy, /*as_client=*/true);
        CHECK_CONTROL_ACCEPTED(handshake_with_raw_peer(eng, peer));
    }

    tls_ctx_holder fips(test_ca);
    REQUIRE(fips.tls->require_fips != nullptr);
    fips.tls->require_fips(fips.tls);
    fips.set_identity();
    engine_holder eng(fips.tls->new_server_engine(fips.tls));
    REQUIRE(eng.e != nullptr);
    raw_peer peer(policy, /*as_client=*/true);
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

TEST_CASE("client engines refuse TLS versions below 1.2", "[engine][server][fips]") {
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

TEST_CASE("server engines refuse TLS versions below 1.2", "[engine][server][fips]") {
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

namespace {
// TLS 1.3 post-handshake messages: a TLS 1.3 server sends NewSessionTickets right after
// the handshake, and either side may send a KeyUpdate. Engines must process them and go
// on decrypting the application data that follows.
const peer_policy tls13_peer = {"TLS 1.3 only", TLS1_3_VERSION, nullptr, nullptr,
                                false, false, false, TLS1_3_VERSION};

const int HS_NEW_SESSION_TICKET = 4;
const int HS_KEY_UPDATE = 24;

// Reads from the engine until `want` bytes arrived (or the iterations run out).
std::string engine_receive(tlsuv_engine_t eng, size_t want) {
    std::string got;
    std::vector<char> buf(16 * 1024);
    for (int i = 0; i < MAX_ITERATIONS && got.size() < want; i++) {
        if (eng->setup_async) {
            // async engines push out what they produced (e.g. a KeyUpdate answer) on write
            eng->write(eng, nullptr, 0);
        }
        size_t n = 0;
        int rc = eng->read(eng, buf.data(), &n, buf.size());
        REQUIRE((rc == TLS_OK || rc == TLS_MORE_AVAILABLE || rc == TLS_AGAIN));
        // win32crypto may return decrypted data together with TLS_AGAIN (a partial
        // record follows it)
        got.append(buf.data(), n);
        if (rc == TLS_AGAIN) uv_sleep(1);
    }
    return got;
}

// Writes `data` through the engine and returns what the raw peer read of it.
std::string engine_to_peer(tlsuv_engine_t eng, raw_peer &peer, raw_link &link, const std::string &data) {
    size_t sent = 0;
    std::string got;
    for (int i = 0; i < MAX_ITERATIONS && got.size() < data.size(); i++) {
        if (sent < data.size()) {
            int rc = eng->write(eng, data.data() + sent, data.size() - sent);
            if (rc > 0) {
                sent += (size_t) rc;
            } else {
                REQUIRE(rc == TLS_AGAIN);
            }
        } else if (eng->setup_async) {
            eng->write(eng, nullptr, 0);
        }
        got += peer.receive(link.to_peer, link.to_engine);
        REQUIRE_FALSE(peer.failed);
        if (got.size() < data.size()) uv_sleep(1);
    }
    return got;
}

// Completes the handshake with a TLS 1.3-only peer. On win32crypto the unrestricted
// engines use the legacy SCHANNEL_CRED credentials, with which Schannel may not offer
// TLS 1.3 (only the restricted SCH_CREDENTIALS ones reliably do), so there a refused
// unrestricted handshake skips the case instead of failing it.
#if defined(TEST_win32crypto)
#define REQUIRE_TLS13_HANDSHAKE(eng, peer, link, restricted) \
    do { \
        bool ok_ = handshake_with_raw_peer(eng, peer, link); \
        if (!ok_ && !(restricted)) SKIP("unrestricted Schannel credentials do not negotiate TLS 1.3 here"); \
        REQUIRE(ok_); \
        REQUIRE(SSL_version((peer).ssl) == TLS1_3_VERSION); \
    } while (0)
#else
#define REQUIRE_TLS13_HANDSHAKE(eng, peer, link, restricted) \
    do { \
        (void) (restricted); \
        REQUIRE(handshake_with_raw_peer(eng, peer, link)); \
        REQUIRE(SSL_version((peer).ssl) == TLS1_3_VERSION); \
    } while (0)
#endif

void restrict_if(tls_ctx_holder &h, bool restricted) {
    if (restricted) {
        REQUIRE(h.tls->require_fips != nullptr);
        h.tls->require_fips(h.tls);
    }
}
} // namespace

TEST_CASE("client engine reads application data after TLS 1.3 post-handshake messages",
          "[engine][server][fips]") {
    bool restricted = GENERATE(false, true);
    INFO("restricted=" << restricted);

    tls_ctx_holder clt(test_ca);
    restrict_if(clt, restricted);
    engine_holder eng(clt.tls->new_engine(clt.tls, test_host));
    REQUIRE(eng.e != nullptr);

    raw_peer peer(tls13_peer);
    raw_link link;
    REQUIRE_TLS13_HANDSHAKE(eng, peer, link, restricted);

    // the tickets went out with the server's last flight, so they precede the data
    REQUIRE(peer.send("hello", link.to_engine));
    CHECK(peer.hs_sent[HS_NEW_SESSION_TICKET] > 0);
    CHECK(engine_receive(eng, 5) == "hello");
    CHECK(engine_to_peer(eng, peer, link, "ping") == "ping");
}

// BoringSSL has no API to send a KeyUpdate
#if !defined(OPENSSL_IS_BORINGSSL)
TEST_CASE("client engine answers a TLS 1.3 KeyUpdate", "[engine][server][fips]") {
    bool restricted = GENERATE(false, true);
    INFO("restricted=" << restricted);
#if defined(TEST_mbedtls)
    // mbedtls_ssl_read() fails a received KeyUpdate with MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE
    SKIP("mbedTLS 3.6 does not support receiving a TLS 1.3 KeyUpdate");
#endif

    tls_ctx_holder clt(test_ca);
    restrict_if(clt, restricted);
    engine_holder eng(clt.tls->new_engine(clt.tls, test_host));
    REQUIRE(eng.e != nullptr);

    raw_peer peer(tls13_peer);
    raw_link link;
    REQUIRE_TLS13_HANDSHAKE(eng, peer, link, restricted);

    // the KeyUpdate goes out ahead of "hello"
    REQUIRE(SSL_key_update(peer.ssl, SSL_KEY_UPDATE_REQUESTED) == 1);
    REQUIRE(peer.send("hello", link.to_engine));
    CHECK(peer.hs_sent[HS_KEY_UPDATE] == 1);
    CHECK(engine_receive(eng, 5) == "hello");

    // RFC 8446 4.6.3: the engine must answer with its own KeyUpdate before its next
    // application data, and "ping" must decrypt under its new keys
    CHECK(engine_to_peer(eng, peer, link, "ping") == "ping");
    CHECK(peer.hs_received[HS_KEY_UPDATE] >= 1);
}

TEST_CASE("server engine answers a TLS 1.3 KeyUpdate", "[engine][server][fips]") {
    bool restricted = GENERATE(false, true);
    INFO("restricted=" << restricted);

    tls_ctx_holder srv(test_ca);
    SKIP_UNLESS_SERVER_SUPPORTED(srv);
    restrict_if(srv, restricted);
    srv.set_identity();
    engine_holder eng(srv.tls->new_server_engine(srv.tls));
    REQUIRE(eng.e != nullptr);

    raw_peer peer(tls13_peer, /*as_client=*/true);
    raw_link link;
    REQUIRE_TLS13_HANDSHAKE(eng, peer, link, restricted);

    REQUIRE(SSL_key_update(peer.ssl, SSL_KEY_UPDATE_REQUESTED) == 1);
    REQUIRE(peer.send("hello", link.to_engine));
    CHECK(peer.hs_sent[HS_KEY_UPDATE] == 1);
    CHECK(engine_receive(eng, 5) == "hello");

    CHECK(engine_to_peer(eng, peer, link, "ping") == "ping");
    CHECK(peer.hs_received[HS_KEY_UPDATE] >= 1);
}
#endif // !OPENSSL_IS_BORINGSSL
#endif // TEST_OPENSSL_PEER
