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

#include <uv.h>
#include <uv_mbed/uv_mbed.h>
#include <cstring>
#include "catch.hpp"

TEST_CASE("uv-mbed connect fail", "[uv-mbed]") {
    uv_loop_t *l = uv_loop_new();
    uv_mbed_t mbed;
    tls_context *tls = default_tls_context(nullptr, 0);
    uv_mbed_init(l, &mbed, tls);

    uv_connect_t cr;
    int conn_cb_called = 0;
    cr.data = &conn_cb_called;

    auto cb = [](uv_connect_t *r, int status) {
        int *countp = (int*)r->data;
        *countp = *countp + 1;
        printf("conn cb called status = %d(%s)\n", status, status != 0 ? uv_strerror(status) : "");
    };
    int rc = 0;

    auto cleanup = [=, &mbed]() {
        uv_mbed_free(&mbed);
        uv_loop_close(l);
        uv_run(l, UV_RUN_DEFAULT);
        free(l);
        tls->api->free_ctx(tls);
    };

    WHEN("connect fail") {
        rc = uv_mbed_connect(&cr, &mbed, "127.0.0.1", 62443, cb);
        uv_run(l, UV_RUN_DEFAULT);
        CHECK(((rc == 0 && conn_cb_called == 1) || (rc != 0 && conn_cb_called == 0)));
        cleanup();
    }
    WHEN("resolve fail") {
        rc = uv_mbed_connect(&cr, &mbed, "foo.bar.baz", 443, cb);
        uv_run(l, UV_RUN_DEFAULT);
        CHECK(((rc == 0 && conn_cb_called == 1) || (rc != 0 && conn_cb_called == 0)));
        cleanup();
    }
}

TEST_CASE("cancel connect", "[uv-mbed]") {
    uv_loop_t *l = uv_loop_new();
    uv_mbed_t mbed;
    tls_context *tls = default_tls_context(nullptr, 0);
    uv_mbed_init(l, &mbed, tls);

    struct test_ctx {
        int connect_result;
        bool close_called;
    } test_ctx;

    test_ctx.connect_result = 0;
    test_ctx.close_called = false;

    mbed.data = &test_ctx;

    uv_connect_t cr;
    cr.data = &test_ctx;
    int rc = uv_mbed_connect(&cr, &mbed, "1.1.1.1", 5555, [](uv_connect_t *r, int status){
        auto ctx = (struct test_ctx*)r->data;
        ctx->connect_result = status;
    });

    uv_timer_t t;
    uv_timer_init(l, &t);
    t.data = &mbed;
    auto timer_cb = [](uv_timer_t* t){
        auto *c = static_cast<uv_mbed_t *>(t->data);
        uv_close_cb closeCb = [](uv_handle_t *h) {
            auto mbed = (uv_mbed_t*) h;
            auto ctx = (struct test_ctx*)mbed->data;
            ctx->close_called = true;
        };
        uv_mbed_close(c, closeCb);
        uv_close(reinterpret_cast<uv_handle_t *>(t), nullptr);
    };
    uv_timer_start(&t, timer_cb, 1000, 0);

    uv_run(l, UV_RUN_DEFAULT);

    CHECK(rc == 0);
    CHECK(test_ctx.close_called);
    CHECK(test_ctx.connect_result == UV_ECANCELED);

    tls->api->free_ctx(tls);
    uv_mbed_free(&mbed);
    uv_loop_delete(l);
}

static void test_alloc(uv_handle_t *s, size_t req, uv_buf_t* b) {
    b->base = static_cast<char *>(malloc(req));
    b->len = req;
}

TEST_CASE("read/write","[uv-mbed]") {
    uv_loop_t *l = uv_loop_new();
    uv_mbed_t mbed;
    tls_context *tls = default_tls_context(nullptr, 0);
    uv_mbed_init(l, &mbed, tls);

    struct test_ctx {
        int connect_result;
        bool close_called;
    } test_ctx;

    test_ctx.connect_result = 0;
    test_ctx.close_called = false;

    mbed.data = &test_ctx;

    uv_connect_t cr;
    cr.data = &test_ctx;
    int rc = uv_mbed_connect(&cr, &mbed, "1.1.1.1", 443, [](uv_connect_t *r, int status){
        REQUIRE(status == 0);
        auto c = (uv_mbed_t*)r->handle;

        uv_mbed_read(c, test_alloc, [](uv_stream_t *s, ssize_t status, const uv_buf_t*b){
            auto c = (uv_mbed_t*)s;
            auto ctx = (struct test_ctx*)c->data;
            if (status == UV_EOF) {
                uv_mbed_close(c, nullptr);
            } else  {
                REQUIRE(status > 0);
                REQUIRE_THAT(b->base, Catch::StartsWith("HTTP/1.1 200 OK"));
                fprintf(stderr, "%.*s\n", (int)status, b->base);
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
        uv_mbed_write(wr, c, &buf, [](uv_write_t *wr, int rc){
            REQUIRE(rc == 0);
            free(wr);
        });
    });

    uv_run(l, UV_RUN_DEFAULT);

    CHECK(rc == 0);

    uv_mbed_free(&mbed);
    tls->api->free_ctx(tls);

    uv_run(l, UV_RUN_DEFAULT);
    uv_loop_delete(l);

}