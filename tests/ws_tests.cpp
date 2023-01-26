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

#include "catch.hpp"
#include "fixtures.h"
#include <cstring>
#include <tlsuv/tlsuv.h>
#include <tlsuv/websocket.h>
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

    um_websocket_t *ws;
    int conn_status = -1;
    int write_status = -1;
    bool close_cb_called = false;
    vector<string> resp;
    int expected_count;
};

static void on_ws_write(uv_write_t *req, int status) {
    auto t = static_cast<websocket_test *>(req->data);
    CHECK(status == 0);
    t->write_status = status;
    delete req;
}

static void on_close_cb(uv_handle_t *h) {
    auto ws = (um_websocket_t*)h;
    auto test = (websocket_test*)ws->data;
    test->close_cb_called = true;
}

static void on_connect(uv_connect_t *req, int status) {
    auto *t = static_cast<websocket_test *>(req->data);
    um_websocket_t *ws = t->ws;
    t->conn_status = status;

    if (status == 0) {
        auto wr = new uv_write_t;
        wr->data = t;
        const char* msg = "this is a test";
        uv_buf_t b = uv_buf_init((char*)msg, strlen(msg));
        CHECK(um_websocket_write(wr, ws, &b, on_ws_write) == 0);
    } else {
        printf("connect failed: status %s\n", uv_err_name(status));
        um_websocket_close(ws, on_close_cb);
    }
}

static void on_ws_data(uv_stream_t *s, ssize_t nread, const uv_buf_t* buf) {
    auto *ws = reinterpret_cast<um_websocket_t *>(s);
    auto *t = static_cast<websocket_test *>(ws->data);
    if (nread > 0) {
        string text(buf->base, nread);
        printf("received '%s'\n", text.data());
        t->resp.push_back(text);
    }

    if (t->resp.size() >= t->expected_count) {
        um_websocket_close(ws, on_close_cb);
    }
}

TEST_CASE("websocket fail tests", "[websocket]") {
    UvLoopTest lt;
    um_websocket_t clt;
    websocket_test test(0);

    WHEN("invalid URL") {
        um_websocket_init(lt.loop, &clt);
        test.ws = &clt;
        clt.data = &test;

        uv_connect_t r;
        r.data = &test;
        int rc = um_websocket_connect(&r, &clt, "not a real URL", on_connect, on_ws_data);
        lt.run();
        CHECK(test.conn_status == 0);
        CHECK(rc == UV_EINVAL);
    }

    WHEN("resolve failure ") {
        um_websocket_init(lt.loop, &clt);
        test.ws = &clt;
        clt.data = &test;

        uv_connect_t r;
        r.data = &test;
        int rc = um_websocket_connect(&r, &clt, "ws://not.a.real.host", on_connect, on_ws_data);
        lt.run();
        CHECK((rc == UV_EAI_NONAME || test.conn_status == UV_EAI_NONAME));
    }
    um_websocket_close(&clt, on_close_cb);
}

#define WS_TEST_HOST "echo.websocket.events"

TEST_CASE("websocket echo tests", "[websocket]") {
    UvLoopTest lt;

    um_websocket_t clt;
    websocket_test test(2);

    WHEN("ws echo test") {
        um_websocket_init(lt.loop, &clt);
        test.ws = &clt;
        clt.data = &test;

        uv_connect_t r;
        r.data = &test;
        int rc = um_websocket_connect(&r, &clt, "ws://" WS_TEST_HOST, on_connect, on_ws_data);
        lt.run();
        CHECK(rc == 0);
        CHECK(test.conn_status == 0);
        CHECK(test.write_status == 0);
        CHECK(test.close_cb_called);
        REQUIRE(test.resp.size() == 2);
        CHECK_THAT(test.resp[1],Catch::Matches("this is a test"));
    }

    WHEN("wss echo test") {
        um_websocket_init(lt.loop, &clt);
        test.ws = &clt;
        clt.data = &test;

        uv_connect_t r;
        r.data = &test;
        int rc = um_websocket_connect(&r, &clt, "wss://" WS_TEST_HOST, on_connect, on_ws_data);
        lt.run();
        CHECK(rc == 0);
        CHECK(test.conn_status == 0);
        CHECK(test.write_status == 0);
        CHECK(test.close_cb_called);
        REQUIRE(test.resp.size() == 2);
        CHECK_THAT(test.resp[1],Catch::Matches("this is a test"));
    }

    um_websocket_close(&clt, on_close_cb);
}