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

// tests for HTTP and websocket clients running over a caller-supplied source link (tlsuv_src_t)

#include <catch2/catch_all.hpp>
#include "fixtures.h"
#include "http_capture.h"

#include <string>
#include <vector>

#include <tlsuv/http.h>
#include <tlsuv/src_t.h>
#include <tlsuv/websocket.h>
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
    DEFER {
        tlsuv_http_close(&clt, nullptr);
        test.drain();
    };
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
}

// request body callbacks in the order they ran, an empty chunk shows as "<empty>"
static std::vector<std::string> chunk_cb_order;
static void ordered_chunk_cb(tlsuv_http_req_t *, char *chunk, ssize_t status) {
    chunk_cb_order.push_back(status != 0 ? "<error>" : (chunk && *chunk ? chunk : "<empty>"));
}

// an empty chunk has nothing to write, its callback still has to run after those of the chunks before it,
// which are only done once the source link has written them
TEST_CASE("empty body chunk over custom src", "[http]") {
    auto scheme = GENERATE(as<std::string>{}, "http", "https");
    INFO("scheme: " << scheme);
    UvLoopTest test;

    tcp_src src{};
    src.loop = test.loop;
    src.connect = tcp_src_connect;
    src.release = tcp_src_release;
    src.cancel = [](tlsuv_src_t *) {};

    tlsuv_http_t clt{};
    tlsuv_http_init_with_src(test.loop, &clt, testServerURL(scheme).c_str(), (tlsuv_src_t *) &src);
    tlsuv_http_set_ssl(&clt, testServerTLS());

    resp_capture resp(resp_body_cb);
    DEFER {
        tlsuv_http_close(&clt, nullptr);
        test.drain();
    };
    tlsuv_http_req_t *req = tlsuv_http_req(&clt, "POST", "/post", resp_capture_cb, &resp);
    tlsuv_http_req_header(req, "Transfer-Encoding", "chunked");

    chunk_cb_order.clear();
    tlsuv_http_req_data(req, "abc", 3, ordered_chunk_cb);
    tlsuv_http_req_data(req, "", 0, ordered_chunk_cb);
    tlsuv_http_req_data(req, "def", 3, ordered_chunk_cb);
    tlsuv_http_req_end(req);

    test.run(UNTIL(resp.resp_body_end_called));

    REQUIRE(resp.code == HTTP_STATUS_OK);
    CHECK(chunk_cb_order == std::vector<std::string>{"abc", "<empty>", "def"});
}

TEST_CASE("close http over custom src after a failed connect", "[http]") {
    UvLoopTest test;

    tcp_src src{};
    src.loop = test.loop;
    src.connect = tcp_src_connect;
    src.release = tcp_src_release;
    src.cancel = [](tlsuv_src_t *) {};

    // nothing listens on port 1: the src connect fails, so the http links are never made
    tlsuv_http_t clt{};
    tlsuv_http_init_with_src(test.loop, &clt, "https://127.0.0.1:1", (tlsuv_src_t *) &src);
    tlsuv_http_set_ssl(&clt, testServerTLS());

    resp_capture resp(resp_body_cb);
    DEFER {
        tlsuv_http_close(&clt, nullptr);
        // the client releases a src only after closing its links, so close the failed one here
        tcp_src_release((tlsuv_src_t *) &src);
        test.drain();
    };
    tlsuv_http_req(&clt, "GET", "/json", resp_capture_cb, &resp);

    test.run(UNTIL(resp.code != -666));
    CHECK(resp.code == UV_ECONNREFUSED);
}

// websocket echo endpoints of the local test server (tests/test_server)
#define WS_TEST_URL "ws://localhost:8080/ws/echo"
#define WSS_TEST_URL "wss://localhost:8443/ws/echo"

// a websocket over a tcp_src, and what its callbacks reported
struct ws_src_run {
    UvLoopTest test;
    tcp_src src{};
    tlsuv_websocket_t ws{};
    uv_connect_t conn_req{};

    std::vector<int> connect_status; // one entry per call of the connect callback
    std::vector<std::string> received;
    std::vector<ssize_t> read_errors;
    bool close_on_connect_error = true;
    bool closing = false;
    bool closed = false;

    ws_src_run() {
        src.loop = test.loop;
        src.connect = tcp_src_connect;
        src.release = tcp_src_release;
        // the websocket client calls cancel, not release, when it is done with its connection
        src.cancel = tcp_src_release;
        tlsuv_websocket_init_with_src(test.loop, &ws, (tlsuv_src_t *) &src);
        ws.data = this;
        conn_req.data = this;
    }

    int connect(const char *url) {
        return tlsuv_websocket_connect(&conn_req, &ws, url, on_connect, on_data);
    }

    void close() {
        if (closing) return;
        closing = true;
        tlsuv_websocket_close(&ws, [](uv_handle_t *h) {
            ((ws_src_run *) ((tlsuv_websocket_t *) h)->data)->closed = true;
        });
    }

    // run until the websocket is closed, and its source connection with it
    void wait_closed() {
        test.run(UNTIL(closed));
        test.drain();
    }

    static void on_connect(uv_connect_t *req, int status) {
        auto run = (ws_src_run *) req->data;
        run->connect_status.push_back(status);
        if (status != 0) {
            if (run->close_on_connect_error) run->close();
            return;
        }
        static char msg[] = "hello over src";
        uv_buf_t buf = uv_buf_init(msg, sizeof(msg) - 1);
        auto wr = new uv_write_t;
        tlsuv_websocket_write(wr, &run->ws, &buf, [](uv_write_t *w, int) { delete w; });
    }

    static void on_data(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
        auto run = (ws_src_run *) ((tlsuv_websocket_t *) s)->data;
        if (nread < 0) {
            run->read_errors.push_back(nread);
            return;
        }
        run->received.emplace_back(buf->base, nread);
        run->close();
    }
};

static void check_echo_over_src(const char *url, tls_context *tls) {
    ws_src_run run;
    if (tls) tlsuv_websocket_set_tls(&run.ws, tls);

    REQUIRE(run.connect(url) == 0);
    run.wait_closed();

    CHECK(run.connect_status == std::vector<int>{0});
    CHECK(run.received == std::vector<std::string>{"hello over src"});
    CHECK(run.read_errors.empty());
}

TEST_CASE("ws over custom src", "[websocket]") {
    check_echo_over_src(WS_TEST_URL, nullptr);
}

TEST_CASE("wss over custom src", "[websocket]") {
    check_echo_over_src(WSS_TEST_URL, testServerTLS());
}

// the connect callback reports a failed handshake once, and nothing else is reported for a websocket that never connected
TEST_CASE("wss over custom src with an untrusted certificate", "[websocket]") {
    ws_src_run run;
    // the application does not close from its connect callback
    run.close_on_connect_error = false;

    // the default TLS context does not trust the test CA
    REQUIRE(run.connect(WSS_TEST_URL) == 0);
    run.test.run(UNTIL(!run.connect_status.empty()));
    // give what the server still sends (and its close) time to arrive
    run.test.run(1);
    run.close();
    run.wait_closed();

    CHECK(run.connect_status == std::vector<int>{UV_ECONNABORTED});
    CHECK(run.read_errors.empty());
}

TEST_CASE("close websocket over custom src after a failed connect", "[websocket]") {
    ws_src_run run;

    // nothing listens on port 1: the src connect fails, so the websocket links are never made
    REQUIRE(run.connect("wss://127.0.0.1:1/") == 0);
    run.wait_closed();

    CHECK(run.connect_status == std::vector<int>{UV_ECONNREFUSED});
}

// closes the client from the final body callback of its request, as tlsuv_http_close() documents
struct close_at_eof {
    tlsuv_http_t clt{};
    int eof_count = 0;
    bool closed = false;
};

static void close_at_eof_body_cb(tlsuv_http_req_t *req, char *, ssize_t len) {
    if (len != UV_EOF) return;
    auto ctx = (close_at_eof *) req->data;
    ctx->eof_count++;
    tlsuv_http_close(&ctx->clt, [](tlsuv_http_t *h) { ((close_at_eof *) h->data)->closed = true; });
}

static void close_at_eof_resp_cb(tlsuv_http_resp_t *resp, void *) {
    resp->body_cb = close_at_eof_body_cb;
}

TEST_CASE("close http client from the final body callback", "[http]") {
    auto scheme = GENERATE(as<std::string>{}, "http", "https");
    auto use_src = GENERATE(false, true);
    // the second takes many reads (and TLS records) to arrive
    auto path = GENERATE(as<std::string>{}, "/json", "/bytes/300000");
    INFO("scheme: " << scheme << ", custom src: " << use_src << ", path: " << path);
    UvLoopTest test;

    tcp_src src{};
    src.loop = test.loop;
    src.connect = tcp_src_connect;
    src.release = tcp_src_release;
    src.cancel = [](tlsuv_src_t *) {};

    close_at_eof ctx;
    ctx.clt.data = &ctx;
    tlsuv_http_init_with_src(test.loop, &ctx.clt, testServerURL(scheme).c_str(), use_src ? (tlsuv_src_t *) &src : nullptr);
    tlsuv_http_set_ssl(&ctx.clt, testServerTLS());
    tlsuv_http_req(&ctx.clt, "GET", path.c_str(), close_at_eof_resp_cb, &ctx);

    test.run();

    CHECK(ctx.eof_count == 1);
    CHECK(ctx.closed);
}
