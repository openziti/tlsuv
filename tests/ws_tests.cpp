/*
Copyright 2020 NetFoundry, Inc.

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

#include <catch2/catch_all.hpp>
#include "canned_server.h"
#include "fixtures.h"
#include "http_capture.h"
#include <cstring>
#include <tlsuv/tlsuv.h>
#include <tlsuv/websocket.h>
#include <tlsuv/connector.h>
#include <uv.h>

static void test_timeout(uv_timer_t *t) {
    printf("timeout stopping loop\n");
    uv_stop(t->loop);
}

using namespace std;
class websocket_test {
public:
    explicit websocket_test(int count):
            expected_count(count),
            ws(nullptr),
            conn_status(0)
    {}

    tlsuv_websocket_t *ws;
    int conn_status = -1;
    int write_status = -1;
    bool close_cb_called = false;
    vector<string> resp;
    int expected_count;
    bool close_cb_called_in_close = false; // the close callback ran before tlsuv_websocket_close() returned
};

static void on_ws_write(uv_write_t *req, int status) {
    auto t = static_cast<websocket_test *>(req->data);
    CHECK(status == 0);
    t->write_status = status;
    delete req;
}

static void on_close_cb(uv_handle_t *h) {
    auto ws = (tlsuv_websocket_t *)h;
    auto test = (websocket_test*)ws->data;
    test->close_cb_called = true;
    free(ws);
}

static void on_connect(uv_connect_t *req, int status) {
    auto *t = static_cast<websocket_test *>(req->data);
    tlsuv_websocket_t *ws = t->ws;
    t->conn_status = status;

    if (status == 0) {
        auto wr = new uv_write_t;
        wr->data = t;
        const char* msg = "this is a test";
        uv_buf_t b = uv_buf_init((char*)msg, strlen(msg));
        CHECK(tlsuv_websocket_write(wr, ws, &b, on_ws_write) == 0);
    } else {
        printf("connect failed: status %s\n", uv_err_name(status));
        tlsuv_websocket_close(ws, on_close_cb);
    }
}

static void on_ws_data(uv_stream_t *s, ssize_t nread, const uv_buf_t* buf) {
    auto *ws = reinterpret_cast<tlsuv_websocket_t *>(s);
    auto *t = static_cast<websocket_test *>(ws->data);
    if (nread > 0) {
        string text(buf->base, nread);
        printf("received '%s'\n", text.data());
        t->resp.push_back(text);
    }

    if (t->resp.size() >= t->expected_count) {
        tlsuv_websocket_close(ws, on_close_cb);
    }
}

TEST_CASE("websocket fail tests", "[websocket]") {
    UvLoopTest lt;
    auto clt = (tlsuv_websocket_t *)malloc(sizeof(tlsuv_websocket_t));
    websocket_test test(0);

    tlsuv_websocket_init(lt.loop, clt);
    test.ws = clt;
    clt->data = &test;

    uv_connect_t r;
    r.data = &test;

    WHEN("invalid URL") {
        int rc = tlsuv_websocket_connect(&r, clt, "not a real URL", on_connect, on_ws_data);
        lt.run();
        CHECK(test.conn_status == 0);
        CHECK(rc == UV_EINVAL);

        tlsuv_websocket_close(clt, on_close_cb);
        lt.run();
        CHECK(test.close_cb_called);
    }

    WHEN("resolve failure ") {
        int rc = tlsuv_websocket_connect(&r, clt, "ws://not.a.real.host", on_connect, on_ws_data);
        lt.run();
        INFO("rc = " << rc);
        CHECK((rc == UV_EAI_NONAME || test.conn_status == UV_EAI_NONAME));
        CHECK(test.close_cb_called);
    }
}

// websocket echo endpoint of the local test server (tests/test_server)
#define WS_TEST_URL "ws://localhost:8080/ws/echo"
#define WSS_TEST_URL "wss://localhost:8443/ws/echo"

// the application frees the websocket in its close callback (and not before)
static void start_freeing_websocket(UvLoopTest &lt, websocket_test &test, uv_connect_t &r) {
    auto clt = (tlsuv_websocket_t *) malloc(sizeof(tlsuv_websocket_t));
    tlsuv_websocket_init(lt.loop, clt);
    test.ws = clt;
    test.conn_status = 1; // neither a success nor a failure
    clt->data = &test;
    r.data = &test;
}

static void check_freed_from_failed_connect(const char *reply) {
    UvLoopTest lt;
    canned_server server(lt.loop, reply, "");
    DEFER { server.close(); lt.drain(); };

    websocket_test test(0);
    uv_connect_t r;
    start_freeing_websocket(lt, test, r);

    // on_connect closes the websocket on a failure, and its close callback frees it
    REQUIRE(tlsuv_websocket_connect(&r, test.ws, server.url().c_str(), on_connect, on_ws_data) == 0);
    lt.run(UNTIL(test.close_cb_called));

    CHECK(test.conn_status < 0);
}

TEST_CASE("free websocket from the connect callback after a refused upgrade", "[websocket]") {
    check_freed_from_failed_connect("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
}

TEST_CASE("free websocket from the connect callback after a reply that is not HTTP", "[websocket]") {
    check_freed_from_failed_connect("this is not an HTTP reply\r\n\r\n");
}

// the Host header of the upgrade request for `url`, which nothing listens on
static std::string upgrade_host_header(const char *url) {
    UvLoopTest lt;
    websocket_test test(0);
    uv_connect_t r;
    start_freeing_websocket(lt, test, r);

    REQUIRE(tlsuv_websocket_connect(&r, test.ws, url, on_connect, on_ws_data) == 0);
    // the request is made before the connection is, and the failed connect closes the websocket
    std::string host = header_value(&test.ws->req->req_headers, "Host");
    lt.run(UNTIL(test.close_cb_called));
    return host;
}

// the Host header is the host and the port the way the URL writes them: an IPv6 literal is bracketed
TEST_CASE("websocket host header", "[websocket]") {
    CHECK(upgrade_host_header("ws://127.0.0.1:1/ws") == "127.0.0.1:1");
    CHECK(upgrade_host_header("ws://[::1]:1/ws") == "[::1]:1");
    CHECK(upgrade_host_header("ws://[::1]:1") == "[::1]:1");
    // no port in the URL, no port in the header
    CHECK(upgrade_host_header("ws://no-such-host.invalid/ws") == "no-such-host.invalid");
}

static void close_on_connect(uv_connect_t *req, int status) {
    auto t = static_cast<websocket_test *>(req->data);
    t->conn_status = status;
    tlsuv_websocket_close(t->ws, on_close_cb);
}

TEST_CASE("free websocket from the connect callback after a successful connect", "[websocket]") {
    UvLoopTest lt;
    websocket_test test(0);
    uv_connect_t r;
    start_freeing_websocket(lt, test, r);

    REQUIRE(tlsuv_websocket_connect(&r, test.ws, WS_TEST_URL, close_on_connect, on_ws_data) == 0);
    lt.run(UNTIL(test.close_cb_called));

    CHECK(test.conn_status == 0);
}

// the app frees the websocket in the close callback and not before, so the websocket is still
// there when the connect callback that closed it returns: the close callback comes later
TEST_CASE("websocket close callback runs after close returns", "[websocket]") {
    UvLoopTest lt;
    canned_server server(lt.loop,
                         "HTTP/1.1 101 Switching Protocols\r\n"
                         "Upgrade: websocket\r\n"
                         "Connection: Upgrade\r\n\r\n", "");
    DEFER { server.close(); lt.drain(); };

    websocket_test test(0);
    uv_connect_t r;
    start_freeing_websocket(lt, test, r);

    REQUIRE(tlsuv_websocket_connect(&r, test.ws, server.url().c_str(), [](uv_connect_t *req, int status) {
        auto t = static_cast<websocket_test *>(req->data);
        t->conn_status = status;
        tlsuv_websocket_close(t->ws, on_close_cb);
        t->close_cb_called_in_close = t->close_cb_called;
    }, on_ws_data) == 0);
    lt.run(UNTIL(test.close_cb_called));

    CHECK(test.conn_status == 0);
    CHECK_FALSE(test.close_cb_called_in_close);
}

static bool data_cb_called;

TEST_CASE("free websocket from the connect callback with a frame behind the upgrade reply", "[websocket]") {
    // the first frame comes in the same read as the reply: once the app has closed the websocket
    // in its connect callback, that frame is not processed
    UvLoopTest lt;
    canned_server server(lt.loop,
                         "HTTP/1.1 101 Switching Protocols\r\n"
                         "Upgrade: websocket\r\n"
                         "Connection: Upgrade\r\n\r\n"
                         "\x81\x03" "abc", "");
    DEFER { server.close(); lt.drain(); };

    websocket_test test(0);
    uv_connect_t r;
    start_freeing_websocket(lt, test, r);
    data_cb_called = false;

    // the data callback does not look at the websocket, which has been freed by then
    REQUIRE(tlsuv_websocket_connect(&r, test.ws, server.url().c_str(), close_on_connect,
                                    [](uv_stream_t *, ssize_t, const uv_buf_t *) { data_cb_called = true; }) == 0);
    lt.run(UNTIL(test.close_cb_called));

    CHECK(test.conn_status == 0);
    CHECK_FALSE(data_cb_called);
}

TEST_CASE("websocket echo tests", "[websocket]") {
    UvLoopTest lt;

    auto clt = (tlsuv_websocket_t *)malloc(sizeof (tlsuv_websocket_t));
    websocket_test test(1);

    tlsuv_websocket_init(lt.loop, clt);
    test.ws = clt;
    clt->data = &test;

    uv_connect_t r;
    r.data = &test;

    WHEN("ws echo test") {
        int rc = tlsuv_websocket_connect(&r, clt, WS_TEST_URL, on_connect, on_ws_data);
        lt.run();
        CHECK(rc == 0);
        CHECK(test.conn_status == 0);
        CHECK(test.write_status == 0);
        CHECK(test.close_cb_called);
        REQUIRE(test.resp.size() == 1);
        CHECK_THAT(test.resp[0],Catch::Matchers::Matches("this is a test"));
    }

    WHEN("wss echo test") {
        tlsuv_websocket_set_tls(clt, testServerTLS());
        int rc = tlsuv_websocket_connect(&r, clt, WSS_TEST_URL, on_connect, on_ws_data);
        lt.run();
        CHECK(rc == 0);
        CHECK(test.conn_status == 0);
        CHECK(test.write_status == 0);
        CHECK(test.close_cb_called);
        REQUIRE(test.resp.size() == 1);
        CHECK_THAT(test.resp[0],Catch::Matchers::Matches("this is a test"));
    }

    WHEN("wss echo test with proxy") {
        auto proxy = tlsuv_new_proxy_connector(tlsuv_PROXY_HTTP, "127.0.0.1", "13128");
        tlsuv_websocket_set_connector(clt, proxy);
        tlsuv_websocket_set_tls(clt, testServerTLS());
        int rc = tlsuv_websocket_connect(&r, clt, WSS_TEST_URL, on_connect, on_ws_data);
        lt.run();
        CHECK(rc == 0);
        CHECK(test.conn_status == 0);
        CHECK(test.write_status == 0);
        CHECK(test.close_cb_called);
        REQUIRE(test.resp.size() == 1);
        CHECK_THAT(test.resp[0],Catch::Matchers::Matches("this is a test"));
        proxy->free((void*)proxy);
    }
}

// Frames straight off the wire.
// The tests hand ws_process_read() what a transport read, so they need no server, and see
// exactly what the websocket passes to the application and what it sends back to the peer.
extern "C" {
#include "alloc.h"
void ws_process_read(tlsuv_websocket_t *ws, ssize_t nread, const uv_buf_t *buf);
}

static std::string bytes(std::initializer_list<int> l) {
    std::string s;
    for (int b: l) s.push_back((char) b);
    return s;
}

struct frame_peer {
    tlsuv_websocket_t ws{};
    std::vector<std::string> sent; // what the websocket wrote to the transport
    std::vector<std::pair<ssize_t, std::string>> got; // what the read callback of the application saw

    frame_peer() {
        ws.connected = true; // past the upgrade
        ws.data = this;
        ws.tr = this;
        ws.read_cb = [](uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
            auto p = static_cast<frame_peer *>(s->data);
            p->got.emplace_back(nread, nread > 0 ? std::string(buf->base, nread) : std::string());
        };
        ws.tr_write = [](uv_write_t *req, void *tr, uv_buf_t *bufs, int n, uv_write_cb) -> int {
            auto p = static_cast<frame_peer *>(tr);
            for (int i = 0; i < n; i++) p->sent.emplace_back(bufs[i].base, bufs[i].len);
            // as the transport's write callback does for a write that the application did not ask for
            tlsuv__free(req->data);
            tlsuv__free(req);
            return 0;
        };
    }

    // `frame` is all that the read brought, in a read buffer of `buf_len` bytes.
    // The rest of the buffer holds what an earlier read left in it.
    void feed(const std::string &frame, size_t buf_len = 256) {
        REQUIRE(buf_len >= frame.size());
        auto base = static_cast<char *>(tlsuv__malloc(buf_len));
        memset(base, 'S', buf_len);
        memcpy(base, frame.data(), frame.size());
        uv_buf_t buf = uv_buf_init(base, (unsigned) buf_len);
        ws_process_read(&ws, (ssize_t) frame.size(), &buf); // takes the buffer
    }

    // the payload of the pong that the websocket sent: it masks what it sends
    static std::string pong_payload(const std::string &frame) {
        REQUIRE(frame.size() >= 6);
        CHECK((uint8_t) frame[0] == 0x8a);
        CHECK(((uint8_t) frame[1] & 0x80) != 0);
        size_t len = (uint8_t) frame[1] & 0x7f;
        REQUIRE(frame.size() == 6 + len);
        std::string out(len, 0);
        for (size_t i = 0; i < len; i++) out[i] = (char) (frame[6 + i] ^ frame[2 + i % 4]);
        return out;
    }
};

TEST_CASE("websocket frame: a complete frame is delivered", "[websocket][frame]") {
    frame_peer p;

    WHEN("text frame") {
        p.feed(bytes({0x81, 3, 'a', 'b', 'c'}));
        REQUIRE(p.got.size() == 1);
        CHECK(p.got[0].first == 3);
        CHECK(p.got[0].second == "abc");
    }

    WHEN("frame ends where the read ends") {
        // the buffer is not any bigger than the frame
        p.feed(bytes({0x82, 3, 'a', 'b', 'c'}), 5);
        REQUIRE(p.got.size() == 1);
        CHECK(p.got[0].second == "abc");
    }

    WHEN("binary frame with a 16 bit length") {
        std::string payload(300, 'x');
        for (size_t i = 0; i < payload.size(); i++) payload[i] = (char) ('a' + i % 26);
        std::string frame = bytes({0x82, 126, 0x01, 0x2c}) + payload;
        p.feed(frame, frame.size());
        REQUIRE(p.got.size() == 1);
        CHECK(p.got[0].first == 300);
        CHECK(p.got[0].second == payload);
    }

    WHEN("frame with a 64 bit length") {
        p.feed(bytes({0x82, 127, 0, 0, 0, 0, 0, 0, 0, 4, 'w', 'x', 'y', 'z'}));
        REQUIRE(p.got.size() == 1);
        CHECK(p.got[0].second == "wxyz");
    }

    WHEN("masked frame") {
        p.feed(bytes({0x81, 0x83, 1, 2, 3, 4, 'a' ^ 1, 'b' ^ 2, 'c' ^ 3}));
        REQUIRE(p.got.size() == 1);
        CHECK(p.got[0].first == 3);
        CHECK(p.got[0].second == "abc");
    }

    WHEN("close frame") {
        p.feed(bytes({0x88, 0}));
        REQUIRE(p.got.size() == 1);
        CHECK(p.got[0].first == UV_EOF);
    }

    CHECK(p.sent.empty());
    CHECK_FALSE(p.ws.closed);
}

TEST_CASE("websocket frame: a ping is answered with its own payload", "[websocket][frame]") {
    frame_peer p;
    std::string payload;

    WHEN("no payload") {
    }
    WHEN("some payload") {
        payload = "hello";
    }
    WHEN("the largest payload") {
        payload = std::string(125, 'p');
    }

    p.feed(bytes({0x89, (int) payload.size()}) + payload, 2 + payload.size());

    CHECK(p.got.empty());
    REQUIRE(p.sent.size() == 1);
    CHECK(frame_peer::pong_payload(p.sent[0]) == payload);
}

// The lengths in a frame are the peer's word. A frame whose header promises more than the read
// brought, or whose header the read did not bring in full, is a protocol error: nothing of it
// reaches the application, and nothing goes back to the peer.
TEST_CASE("websocket frame: a frame that is not all there is rejected", "[websocket][frame]") {
    frame_peer p;
    size_t buf_len = 256;
    std::string frame;

    WHEN("ping declares a payload that did not come") {
        // what is in the buffer after the frame must not come back in a pong
        frame = bytes({0x89, 125});
    }
    WHEN("ping declares a payload past the end of the buffer") {
        // nothing after the frame in the buffer: the payload is not in the buffer at all
        frame = bytes({0x89, 125});
        buf_len = frame.size();
    }
    WHEN("ping declares more payload than came") {
        frame = bytes({0x89, 100, 'a', 'b'});
    }
    WHEN("masked ping declares more payload than came") {
        frame = bytes({0x89, 0x85, 1, 2, 3, 4, 'a', 'b'});
    }
    WHEN("text frame declares more than came, 7 bit length") {
        frame = bytes({0x81, 100, 'a'});
    }
    WHEN("text frame declares more than came, 16 bit length") {
        buf_len = 8192;
        frame = bytes({0x81, 126, 0x10, 0x00, 'a', 'b', 'c', 'd'});
    }
    WHEN("text frame declares more than came, 64 bit length") {
        frame = bytes({0x81, 127, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 'a'});
    }
    WHEN("64 bit length that is only right in its low 32 bits") {
        frame = bytes({0x81, 127, 0, 0, 0, 1, 0, 0, 0, 2, 'a', 'b'});
    }
    WHEN("read ends in the first byte of the header") {
        frame = bytes({0x81});
    }
    WHEN("read ends in the 16 bit length") {
        frame = bytes({0x81, 126, 0x00});
    }
    WHEN("read ends in the 64 bit length") {
        frame = bytes({0x81, 127, 0, 0, 0});
    }
    WHEN("read ends in the mask") {
        frame = bytes({0x81, 0x83, 1, 2});
    }

    p.feed(frame, buf_len);

    REQUIRE(p.got.size() == 1);
    CHECK(p.got[0].first == UV_EPROTO);
    CHECK(p.got[0].second.empty());
    CHECK(p.sent.empty());
    CHECK(p.ws.closed);
}

// The application is told once. Until it closes the websocket the transport may keep reading,
// and what comes next is not a frame boundary: it is the middle of the frame that was rejected.
TEST_CASE("websocket frame: reads after a protocol error are dropped", "[websocket][frame]") {
    frame_peer p;
    p.feed(bytes({0x81, 100, 'a'})); // declares more than came
    REQUIRE(p.got.size() == 1);
    REQUIRE(p.got[0].first == UV_EPROTO);
    REQUIRE(p.ws.closed);

    WHEN("the rest of the rejected frame comes") {
        // the payload that did not fit in the first read, which parses as a text frame of 3 bytes
        p.feed(bytes({0x81, 3, 'x', 'y', 'z'}));
    }
    WHEN("a ping comes") {
        p.feed(bytes({0x89, 2, 'h', 'i'}));
    }
    WHEN("a close comes") {
        p.feed(bytes({0x88, 0}));
    }
    WHEN("a frame that is not all there is comes") {
        p.feed(bytes({0x81, 100, 'a'}));
    }

    CHECK(p.got.size() == 1); // still only the error
    CHECK(p.sent.empty());
}

// What the application saw: a call for each data frame, in order.
static void check_data(const frame_peer &p, const std::vector<std::string> &payloads) {
    REQUIRE(p.got.size() == payloads.size());
    for (size_t i = 0; i < payloads.size(); i++) {
        CAPTURE(i);
        CHECK(p.got[i].first == (ssize_t) payloads[i].size());
        CHECK(p.got[i].second == payloads[i]);
    }
}

// A read holds whatever the transport had: a message and the ping behind it, or many messages.
TEST_CASE("websocket frame: every frame in a read is processed", "[websocket][frame]") {
    frame_peer p;
    std::string frames;
    std::vector<std::string> data; // what the application is to see
    std::vector<std::string> pongs; // what the peer is to get back

    WHEN("two data frames") {
        frames = bytes({0x81, 3, 'a', 'b', 'c'}) + bytes({0x82, 3, 'd', 'e', 'f'});
        data = {"abc", "def"};
    }
    WHEN("a data frame and a ping behind it") {
        frames = bytes({0x81, 3, 'a', 'b', 'c'}) + bytes({0x89, 2, 'h', 'i'});
        data = {"abc"};
        pongs = {"hi"};
    }
    WHEN("a ping and a data frame behind it") {
        frames = bytes({0x89, 2, 'h', 'i'}) + bytes({0x81, 3, 'a', 'b', 'c'});
        data = {"abc"};
        pongs = {"hi"};
    }
    WHEN("a ping between two data frames") {
        frames = bytes({0x81, 3, 'a', 'b', 'c'}) + bytes({0x89, 2, 'h', 'i'}) + bytes({0x81, 3, 'd', 'e', 'f'});
        data = {"abc", "def"};
        pongs = {"hi"};
    }
    WHEN("masked data frames") {
        frames = bytes({0x81, 0x83, 1, 2, 3, 4, 'a' ^ 1, 'b' ^ 2, 'c' ^ 3}) +
                 bytes({0x82, 0x83, 5, 6, 7, 8, 'd' ^ 5, 'e' ^ 6, 'f' ^ 7});
        data = {"abc", "def"};
    }
    WHEN("a masked and an unmasked data frame") {
        frames = bytes({0x81, 0x83, 1, 2, 3, 4, 'a' ^ 1, 'b' ^ 2, 'c' ^ 3}) + bytes({0x82, 3, 'd', 'e', 'f'});
        data = {"abc", "def"};
    }
    WHEN("frames of each length form") {
        std::string medium(300, 'x');
        for (size_t i = 0; i < medium.size(); i++) medium[i] = (char) ('a' + i % 26);
        frames = bytes({0x82, 1, 'x'}) + bytes({0x82, 126, 0x01, 0x2c}) + medium +
                 bytes({0x82, 127, 0, 0, 0, 0, 0, 0, 0, 4, 'w', 'x', 'y', 'z'});
        data = {"x", medium, "wxyz"};
    }
    WHEN("frames that the websocket has nothing to do with between data frames") {
        // a pong, and an opcode that is not defined
        frames = bytes({0x81, 3, 'a', 'b', 'c'}) + bytes({0x8a, 0}) + bytes({0x83, 2, 'z', 'z'}) +
                 bytes({0x81, 3, 'd', 'e', 'f'});
        data = {"abc", "def"};
    }
    WHEN("a hundred small frames") {
        for (int i = 0; i < 100; i++) {
            char c = (char) ('a' + i % 26);
            frames += bytes({0x81, 1, c});
            data.emplace_back(1, c);
        }
    }

    // the read ends where the last frame does: the buffer is not any bigger than the frames
    p.feed(frames, frames.size());

    check_data(p, data);
    REQUIRE(p.sent.size() == pongs.size());
    for (size_t i = 0; i < pongs.size(); i++) {
        CHECK(frame_peer::pong_payload(p.sent[i]) == pongs[i]);
    }
    CHECK_FALSE(p.ws.closed);
}

// Frames after the one that fails are not looked at, and the ones before it have been delivered.
TEST_CASE("websocket frame: a read that ends in the middle of a later frame", "[websocket][frame]") {
    frame_peer p;
    std::string frames;
    std::vector<std::string> data;
    std::vector<std::string> pongs;

    WHEN("a data frame, then one that declares more than came") {
        frames = bytes({0x81, 3, 'a', 'b', 'c'}) + bytes({0x81, 100, 'd'});
        data = {"abc"};
    }
    WHEN("a ping, then a data frame that declares more than came") {
        frames = bytes({0x89, 2, 'h', 'i'}) + bytes({0x81, 100, 'd'});
        pongs = {"hi"};
    }
    WHEN("a data frame, then the first byte of a header") {
        frames = bytes({0x81, 3, 'a', 'b', 'c'}) + bytes({0x81});
        data = {"abc"};
    }
    WHEN("two data frames, then a header cut in its 16 bit length") {
        frames = bytes({0x81, 1, 'a'}) + bytes({0x81, 1, 'b'}) + bytes({0x81, 126, 0x00});
        data = {"a", "b"};
    }

    p.feed(frames);

    REQUIRE(p.got.size() == data.size() + 1);
    for (size_t i = 0; i < data.size(); i++) {
        CHECK(p.got[i].first == (ssize_t) data[i].size());
        CHECK(p.got[i].second == data[i]);
    }
    CHECK(p.got.back().first == UV_EPROTO);
    REQUIRE(p.sent.size() == pongs.size());
    for (size_t i = 0; i < pongs.size(); i++) {
        CHECK(frame_peer::pong_payload(p.sent[i]) == pongs[i]);
    }
    CHECK(p.ws.closed);
}

TEST_CASE("websocket frame: the rest of a read after a close frame is dropped", "[websocket][frame]") {
    frame_peer p;

    WHEN("a data frame behind it") {
        p.feed(bytes({0x88, 0}) + bytes({0x81, 3, 'a', 'b', 'c'}));
    }
    WHEN("a ping behind it") {
        p.feed(bytes({0x88, 0}) + bytes({0x89, 2, 'h', 'i'}));
    }
    WHEN("a frame that is not all there is behind it") {
        p.feed(bytes({0x88, 0}) + bytes({0x81, 100, 'a'}));
    }

    REQUIRE(p.got.size() == 1);
    CHECK(p.got[0].first == UV_EOF);
    CHECK(p.sent.empty());
}

// The application may close the websocket from any callback. The frames behind that one are for
// a websocket that is closed.
TEST_CASE("websocket frame: the application closes the websocket from a callback", "[websocket][frame]") {
    frame_peer p;
    // closing sets the flag; the close itself is deferred, so the websocket is still there
    p.ws.read_cb = [](uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
        auto peer = static_cast<frame_peer *>(s->data);
        peer->got.emplace_back(nread, nread > 0 ? std::string(buf->base, nread) : std::string());
        peer->ws.closed = true;
    };

    WHEN("a data frame behind it") {
        p.feed(bytes({0x81, 3, 'a', 'b', 'c'}) + bytes({0x81, 3, 'd', 'e', 'f'}));
    }
    WHEN("a ping behind it") {
        p.feed(bytes({0x81, 3, 'a', 'b', 'c'}) + bytes({0x89, 2, 'h', 'i'}));
    }
    WHEN("a frame that is not all there is behind it") {
        p.feed(bytes({0x81, 3, 'a', 'b', 'c'}) + bytes({0x81, 100, 'd'}));
    }

    check_data(p, {"abc"});
    CHECK(p.sent.empty());
}
