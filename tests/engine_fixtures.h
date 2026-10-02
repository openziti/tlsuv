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

// Fixtures shared by the server-engine tests (server_tests.cpp) and the FIPS tests
// (fips_tests.cpp): the test certificates, the in-memory transport, the handshake
// and data-transfer drivers, and RAII holders for contexts and engines.

#ifndef TLSUV_ENGINE_FIXTURES_H
#define TLSUV_ENGINE_FIXTURES_H

#include <catch2/catch_all.hpp>

#include <tlsuv/tls_engine.h>
#include "fixtures.h"
#include <uv.h>

#include <algorithm>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#define to_str_(x) #x
#define to_str(x) to_str_(x)

inline const char *test_ca = to_str(TEST_SERVER_CA);
inline const char *test_cert = to_str(TEST_SERVER_CERT);
inline const char *test_key = to_str(TEST_SERVER_KEY);

// certs/server.crt is CN=localhost with SAN DNS:localhost + IP:127.0.0.1
inline const char *test_host = "localhost";

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

inline ssize_t mem_read(io_ctx c, char *out, size_t len) {
    auto *p = static_cast<mem_endpoint *>(c)->in;
    if (p->buf.empty()) return TLS_AGAIN;

    size_t n = std::min(len, p->buf.size());
    std::copy_n(p->buf.begin(), n, out);
    p->buf.erase(p->buf.begin(), p->buf.begin() + (long) n);
    return (ssize_t) n;
}

inline ssize_t mem_write(io_ctx c, const char *in, size_t len) {
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

inline std::unique_ptr<transport> make_mem() { return std::make_unique<mem_transport>(); }

// ------------------------------------------------------------------- drivers

static const int MAX_ITERATIONS = 1000;

// pump both sides until both handshakes complete
inline bool do_handshake(tlsuv_engine_t clt, tlsuv_engine_t srv) {
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

// transfer `data` from one engine to the other and compare what arrives
inline void check_transfer(tlsuv_engine_t from, tlsuv_engine_t to, const std::string &data) {
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

#define SKIP_UNLESS_SERVER_SUPPORTED(holder)                                  \
    do {                                                                        \
        if (!(holder).supports_server()) {                                      \
            WARN("TLS server engines are not supported by this backend");       \
            return;                                                             \
        }                                                                       \
    } while (0)

#endif // TLSUV_ENGINE_FIXTURES_H
