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

#include <uv.h>
#include <uv_mbed/um_http.h>
#include <uv_mbed/um_websocket.h>
#include <cstring>
#include <uv_mbed/uv_mbed.h>
#include "catch.hpp"

static void test_timeout(uv_timer_t *t) {
    printf("timeout stopping loop\n");
    uv_stop(t->loop);
}

using namespace std;
class websocket_test {
public:
    websocket_test(): ws(nullptr), conn_status(0)
    {}

    um_websocket_t *ws;
    int conn_status = -1;
    vector<string> resp;
};

static void on_ws_write(uv_write_t *req, int status) {

}

static void on_close_cb(uv_handle_t *h) {

}

static void on_connect(uv_connect_t *req, int status) {
    auto *t = static_cast<websocket_test *>(req->data);
    um_websocket_t *ws = t->ws;
    t->conn_status = status;

    if (status == 0) {
        uv_write_t req;
        req.data = t;
        const char* msg = "this is a test";
        uv_buf_t b = uv_buf_init((char*)msg, strlen(msg));
        CHECK(um_websocket_write(&req, ws, &b, on_ws_write) == 0);
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

    um_websocket_close(ws, on_close_cb);
}


TEST_CASE("websocket tests", "[websocket]") {
    uv_loop_t *loop = uv_loop_new();
    auto *timer = static_cast<uv_timer_t *>(malloc(sizeof(uv_timer_t)));
    uv_timer_init(loop, timer);
    uv_unref((uv_handle_t *) timer);
    uv_timer_start(timer, test_timeout, 15000, 0);
    um_websocket_t clt;
    websocket_test test;

    WHEN("invalid URL") {
        um_websocket_init(loop, &clt);
        test.ws = &clt;
        clt.data = &test;

        uv_connect_t r;
        r.data = &test;
        int rc = um_websocket_connect(&r, &clt, "not a real URL", on_connect, on_ws_data);
        uv_run(loop, UV_RUN_DEFAULT);
        CHECK(test.conn_status == 0);
        CHECK(rc == UV_EINVAL);
    }

    WHEN("resolve failure ") {
        um_websocket_init(loop, &clt);
        test.ws = &clt;
        clt.data = &test;

        uv_connect_t r;
        r.data = &test;
        int rc = um_websocket_connect(&r, &clt, "ws://not.a.real.host", on_connect, on_ws_data);
        uv_run(loop, UV_RUN_DEFAULT);
        CHECK((rc == UV_EAI_NONAME || test.conn_status == UV_EAI_NONAME));
    }

    uint8_t attempt = 1;
    int rc = -1;
    int s = -1;
    WHEN("ws echo test") {
        do {
            uv_timer_start(timer, test_timeout, 15000, 0);
            um_websocket_init(loop, &clt);
            test.ws = &clt;
            clt.data = &test;

            uv_connect_t r;
            r.data = &test;
            rc = um_websocket_connect(&r, &clt, "ws://echo.websocket.org", on_connect, on_ws_data);
            s = uv_run(loop, UV_RUN_DEFAULT);
            um_websocket_close(&clt, on_close_cb);
        } while (s != 0 && attempt++ < 5);
        CHECK(rc == 0);
        CHECK(test.conn_status == 0);
        REQUIRE(test.resp.size() == 1);
        CHECK_THAT(test.resp[0],Catch::Matches("this is a test"));
    }

    attempt = 1;
    rc = -1;
    WHEN("wss echo test") {
        do {
            uv_timer_start(timer, test_timeout, 15000, 0);
            um_websocket_init(loop, &clt);
            test.ws = &clt;
            clt.data = &test;

            uv_connect_t r;
            r.data = &test;
            rc = um_websocket_connect(&r, &clt, "wss://echo.websocket.org", on_connect, on_ws_data);
            s = uv_run(loop, UV_RUN_DEFAULT);
            um_websocket_close(&clt, on_close_cb);
        } while (s != 0 && attempt++ < 5);
        CHECK(rc == 0);
        CHECK(test.conn_status == 0);
        REQUIRE(test.resp.size() == 1);
        CHECK_THAT(test.resp[0],Catch::Matches("this is a test"));
    }
    uv_loop_close(loop);
    free(loop);
}
