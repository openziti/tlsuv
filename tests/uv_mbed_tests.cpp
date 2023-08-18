/*
Copyright 2019-2021 NetFoundry, Inc.

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

#include <cstring>
#include <tlsuv/tlsuv.h>
#include <uv.h>

#include "fixtures.h"
#include "catch.hpp"

TEST_CASE("uv-mbed connect fail", "[uv-mbed]") {
    UvLoopTest test;

    tlsuv_stream_t mbed;
    tls_context *tls = default_tls_context(nullptr, 0);
    tlsuv_stream_init(test.loop, &mbed, tls);

    uv_connect_t cr;
    int conn_cb_called = 0;
    cr.data = &conn_cb_called;

    auto cb = [](uv_connect_t *r, int status) {
        int *countp = (int*)r->data;
        *countp = *countp + 1;
        printf("conn cb called status = %d(%s)\n", status, status != 0 ? uv_strerror(status) : "");

    };
    int rc = 0;

    WHEN("connect fail") {
        rc = tlsuv_stream_connect(&cr, &mbed, "127.0.0.1", 62443, cb);
        test.run();
        CHECK(((rc == 0 && conn_cb_called == 1) || (rc != 0 && conn_cb_called == 0)));
    }
    WHEN("resolve fail") {
        rc = tlsuv_stream_connect(&cr, &mbed, "foo.bar.baz", 443, cb);
        test.run();
        CHECK(((rc == 0 && conn_cb_called == 1) || (rc != 0 && conn_cb_called == 0)));
    }

    tlsuv_stream_free(&mbed);
    tls->free_ctx(tls);
}

TEST_CASE("cancel connect", "[uv-mbed]") {
    UvLoopTest test;

    tlsuv_stream_t mbed;
    tls_context *tls = default_tls_context(nullptr, 0);
    tlsuv_stream_init(test.loop, &mbed, tls);

    struct test_ctx {
        int connect_result;
        bool close_called;
    } test_ctx;

    test_ctx.connect_result = 0;
    test_ctx.close_called = false;

    mbed.data = &test_ctx;

    uv_connect_t cr;
    cr.data = &test_ctx;
    int rc = tlsuv_stream_connect(&cr, &mbed, "1.1.1.1", 5555, [](uv_connect_t *r, int status) {
        auto ctx = (struct test_ctx *) r->data;
        ctx->connect_result = status;
    });

    uv_timer_t t;
    uv_timer_init(test.loop, &t);
    t.data = &mbed;
    auto timer_cb = [](uv_timer_t* t){
        auto *c = static_cast<tlsuv_stream_t *>(t->data);
        uv_close_cb closeCb = [](uv_handle_t *h) {
            auto mbed = (tlsuv_stream_t *) h;
            auto ctx = (struct test_ctx*)mbed->data;
            ctx->close_called = true;
        };
        tlsuv_stream_close(c, closeCb);
        uv_close(reinterpret_cast<uv_handle_t *>(t), nullptr);
    };
    uv_timer_start(&t, timer_cb, 1000, 0);

    test.run();

    CHECK(rc == 0);
    CHECK(test_ctx.close_called);
    CHECK(test_ctx.connect_result == UV_ECANCELED);

    tlsuv_stream_free(&mbed);
    tls->free_ctx(tls);
}

static void test_alloc(uv_handle_t *s, size_t req, uv_buf_t* b) {
    b->base = static_cast<char *>(calloc(1, req));
    b->len = req;
}

TEST_CASE("read/write","[uv-mbed]") {
    UvLoopTest test;

    const char* proto[] = {
        "foo",
        "bar",
        "http/1.1"
    };
    tlsuv_stream_t mbed;
    tls_context *tls = default_tls_context(nullptr, 0);
    tlsuv_stream_init(test.loop, &mbed, tls);
    tlsuv_stream_set_protocols(&mbed, 3, proto);

    struct test_ctx {
        int connect_result;
        bool close_called;
    } test_ctx;

    test_ctx.connect_result = 0;
    test_ctx.close_called = false;

    mbed.data = &test_ctx;

    uv_connect_t cr;
    cr.data = &test_ctx;
    int rc = tlsuv_stream_connect(&cr, &mbed, "1.1.1.1", 443, [](uv_connect_t *r, int status) {
        REQUIRE(status == 0);
        auto c = (tlsuv_stream_t *) r->handle;

        auto proto = tlsuv_stream_get_protocol(c);
        REQUIRE(proto != nullptr);
        CHECK_THAT(proto, Catch::Equals("http/1.1"));

        tlsuv_stream_read(c, test_alloc, [](uv_stream_t *s, ssize_t status, const uv_buf_t *b) {
            auto c = (tlsuv_stream_t *) s;
            auto ctx = (struct test_ctx *) c->data;
            if (status == UV_EOF) {
                tlsuv_stream_close(c, nullptr);
            } else {
                REQUIRE(status > 0);
                REQUIRE_THAT(b->base, Catch::StartsWith("HTTP/1.1 200 OK"));
                fprintf(stderr, "%.*s\n", (int) status, b->base);
            }
            free(b->base);
        });

        auto *wr = static_cast<uv_write_t *>(calloc(1, sizeof(uv_write_t)));
        const char *msg = R"(GET /dns-query?name=openziti.org&type=A HTTP/1.1
Accept-Encoding: gzip, deflate
Connection: close
Host: 1.1.1.1
User-Agent: HTTPie/1.0.2
accept: application/dns-json

)";
        uv_buf_t buf = uv_buf_init((char *) msg, strlen(msg));
        tlsuv_stream_write(wr, c, &buf, [](uv_write_t *wr, int rc) {
            REQUIRE(rc == 0);
            free(wr);
        });
    });

    test.run();

    CHECK(rc == 0);

    tlsuv_stream_free(&mbed);

    tls->free_ctx(tls);
}