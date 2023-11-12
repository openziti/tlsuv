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

extern tls_context *testServerTLS();

TEST_CASE("stream connect fail", "[stream]") {
    UvLoopTest test;

    tlsuv_stream_t s;
    tls_context *tls = default_tls_context(nullptr, 0);
    tlsuv_stream_init(test.loop, &s, tls);

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
        rc = tlsuv_stream_connect(&cr, &s, "127.0.0.1", 62443, cb);
        test.run();
        CHECK(((rc == 0 && conn_cb_called == 1) || (rc != 0 && conn_cb_called == 0)));
    }
    WHEN("resolve fail") {
        rc = tlsuv_stream_connect(&cr, &s, "foo.bar.baz", 443, cb);
        test.run();
        CHECK(((rc == 0 && conn_cb_called == 1) || (rc != 0 && conn_cb_called == 0)));
    }
    tlsuv_stream_close(&s, (uv_close_cb)tlsuv_stream_free);

    tls->free_ctx(tls);
}

TEST_CASE("cancel connect", "[stream]") {
    UvLoopTest test;

    tlsuv_stream_t s;
    tls_context *tls = default_tls_context(nullptr, 0);
    tlsuv_stream_init(test.loop, &s, tls);

    struct test_ctx {
        int connect_result;
        bool connect_called;
        bool close_called;
    } test_ctx;

    test_ctx.connect_result = 0;
    test_ctx.connect_called = false;
    test_ctx.close_called = false;

    s.data = &test_ctx;

    uv_connect_t cr;
    cr.data = &test_ctx;
    int rc = tlsuv_stream_connect(&cr, &s, "1.1.1.1", 5555, [](uv_connect_t *r, int status) {
        auto ctx = (struct test_ctx *) r->data;
        ctx->connect_result = status;
        ctx->connect_called = true;
    });

    uv_timer_t t;
    uv_timer_init(test.loop, &t);
    t.data = &s;
    auto timer_cb = [](uv_timer_t* t){
        auto *c = static_cast<tlsuv_stream_t *>(t->data);
        uv_close_cb closeCb = [](uv_handle_t *h) {
            auto s = (tlsuv_stream_t *) h;
            auto ctx = (struct test_ctx*)s->data;
            ctx->close_called = true;
        };
        tlsuv_stream_close(c, closeCb);
        uv_close(reinterpret_cast<uv_handle_t *>(t), nullptr);
    };
    uv_timer_start(&t, timer_cb, 1000, 0);

    test.run();

    CHECK(rc == 0);
    CHECK(test_ctx.close_called);
    CHECK(test_ctx.connect_called);
    CHECK(test_ctx.connect_result == UV_ECANCELED);

    tlsuv_stream_free(&s);
    tls->free_ctx(tls);
}

static void test_alloc(uv_handle_t *s, size_t req, uv_buf_t* b) {
    b->base = static_cast<char *>(calloc(1, req));
    b->len = req;
}

TEST_CASE("read/write","[stream]") {
    UvLoopTest test;

    const char* proto[] = {
        "foo",
        "bar",
        "http/1.1"
    };
    tlsuv_stream_t s;
    tls_context *tls = default_tls_context(nullptr, 0);
    tlsuv_stream_init(test.loop, &s, tls);
    tlsuv_stream_set_protocols(&s, 3, proto);

    struct test_ctx {
        int connect_result;
        bool close_called;
    } test_ctx;

    test_ctx.connect_result = 0;
    test_ctx.close_called = false;

    s.data = &test_ctx;

    uv_connect_t cr;
    cr.data = &test_ctx;
    int rc = tlsuv_stream_connect(&cr, &s, "1.1.1.1", 443, [](uv_connect_t *r, int status) {
        REQUIRE(status == 0);
        auto c = (tlsuv_stream_t *) r->handle;

        auto proto = tlsuv_stream_get_protocol(c);
        REQUIRE(proto != nullptr);
        CHECK_THAT(proto, Catch::Equals("http/1.1"));

        tlsuv_stream_read_start(c, test_alloc, [](uv_stream_t *s, ssize_t status, const uv_buf_t *b) {
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

    tlsuv_stream_free(&s);

    tls->free_ctx(tls);
}

struct connect_args_s {
    tlsuv_stream_t *s;
    const char *hostname;
    int port;
    struct test_result *result;
};

struct sleep_args_s {
    int timeout;
};

struct write_args_s {
    tlsuv_stream_t *s;
    const char *data;
};

struct expected_result_s {
    struct test_result *result;
    const char *data;
    int count;
};

typedef struct step_s step_t;
typedef void (*step_fn)(uv_loop_t *, struct step_s *);
struct step_s {
    step_fn fn;

    union {
        connect_args_s connect_args;
        write_args_s write_args;
        sleep_args_s sleep_args;
        expected_result_s expected;
    };
};

static inline void start(uv_loop_t *l, step_t *s) {
    if (s && s->fn) {
        s->fn(l, s);
    }
}
static inline step_t *next_step(step_t *s) { return ++s; }

static inline void run_next(uv_loop_t *l, step_t *step) {
    start(l, next_step(step));
}

static void sleep_cb(uv_timer_t *t) {
    step_t *step = static_cast<step_t *>(t->data);
    uv_close(reinterpret_cast<uv_handle_t *>(t),
             reinterpret_cast<uv_close_cb>(free));
    printf("sleep step is done\n");
    run_next(t->loop, step);
}

static void sleep_step(uv_loop_t *l, step_t *step) {
    printf("running sleep step\n");
    uv_timer_t *t = (uv_timer_t *)calloc(1, sizeof(*t));
    uv_timer_init(l, t);
    t->data = step;
    uv_timer_start(t, sleep_cb, step->sleep_args.timeout, 0);
}

static void connect_cb(uv_connect_t *r, int status) {
    printf("connected: %d\n", status);
    step_t *s = (step_t *)r->data;
    auto stream = (tlsuv_stream_t *)r->handle;
    auto l = stream->loop;
    free(r);
    REQUIRE(status == 0);
    run_next(l, s);
}

static void connect_step(uv_loop_t *l, step_t *step) {
    tlsuv_stream_t *clt = step->connect_args.s;
    REQUIRE(tlsuv_stream_init(l, clt, testServerTLS()) == 0);
    clt->data = step->connect_args.result;
    uv_connect_t *r = (uv_connect_t *)calloc(1, sizeof(*r));
    r->data = step;
    REQUIRE(tlsuv_stream_connect(r, clt, step->connect_args.hostname, step->connect_args.port, connect_cb) == 0);
}

static void disconnect_cb(uv_handle_t *h) {
    auto s = (tlsuv_stream_t *)h;
    auto step = (step_t *)s->data;
    tlsuv_stream_free(s);
    run_next(s->loop, step);
}

static void disconnect_step(uv_loop_t *l, step_t *step) {
    auto s = step->connect_args.s;
    s->data = step;
    tlsuv_stream_close(step->connect_args.s, disconnect_cb);
}

static void write_cb(uv_write_t *r, int status) {
    auto stream = (tlsuv_stream_t *)r->handle;
    auto step = (step_t *)r->data;
    REQUIRE(status == 0);
    delete r;
    run_next(stream->loop, step);
}

static void write_step(uv_loop_t *l, step_t *step) {
    uv_write_t *r = new uv_write_t;
    auto buf = uv_buf_init((char *)step->write_args.data,
                           strlen(step->write_args.data));
    r->data = step;
    REQUIRE(tlsuv_stream_write(r, step->write_args.s, &buf, write_cb) == 0);
}

struct test_result {
    int read_count;
    std::string read_data;
    tlsuv_stream_t *stream;

  public:
    explicit test_result(tlsuv_stream_t *s)
        : stream(s), read_count(0), read_data("") {}
};

static void check_result(uv_loop_t *l, step_t *step) {
    printf("read: %s\n", step->expected.result->read_data.c_str());
    REQUIRE(step->expected.result->read_data == step->expected.data);
    CHECK(step->expected.result->read_count <= step->expected.count);
    run_next(l, step);
}

static void read_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    buf->base = (char *)malloc(size);
    buf->len = size;
}

static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    tlsuv_stream_t *clt = reinterpret_cast<tlsuv_stream_t *>(stream);
    test_result *result = static_cast<test_result *>(clt->data);

    REQUIRE(nread > 0);
    result->read_count++;
    result->read_data.append(buf->base, nread);

    free(buf->base);
}

static void start_read_step(uv_loop_t *l, step_t *step) {
    CHECK(tlsuv_stream_read_start(step->write_args.s, nullptr, nullptr) == UV_EINVAL);
    CHECK(tlsuv_stream_read_start(step->write_args.s, read_alloc, nullptr) == UV_EINVAL);
    CHECK(tlsuv_stream_read_start(step->write_args.s, read_alloc, read_cb) == 0);
    CHECK(tlsuv_stream_read_start(step->write_args.s, read_alloc, read_cb) == UV_EALREADY);
    run_next(l, step);
}

static void stop_read_step(uv_loop_t *l, step_t *step) {
    REQUIRE(tlsuv_stream_read_stop(step->write_args.s) == 0);
    run_next(l, step);
}

TEST_CASE("read start/stop", "[stream]") {
    UvLoopTest loopTest;
    tlsuv_stream_t s;
    test_result r(&s);

    step_t steps[] = {
        {
            .fn = connect_step,
            .connect_args = { .s = &s, .hostname = "localhost", .port = 7443, .result = &r },
        },
        { .fn = write_step, .write_args = { .s = &s, .data = "1",}},
        { .fn = write_step, .write_args = { .s = &s, .data = "2",}},
        { .fn = sleep_step, .sleep_args = { .timeout = 100, } },
        { .fn = check_result, .expected = { .result = &r, .data = "", .count = 0, }}, // not reading yet
        { .fn = start_read_step, .write_args = { .s = &s }},
        { .fn = sleep_step, .sleep_args = { .timeout = 100, } },
        { .fn = check_result, .expected = { .result = &r, .data = "12", .count = 1,}}, // should read echo from two writes
        { .fn = stop_read_step, .write_args = {.s = &s }},
        { .fn = write_step, .write_args = { .s = &s, .data = "3",}},
        { .fn = write_step, .write_args = { .s = &s, .data = "4",}},
        { .fn = sleep_step, .sleep_args = { .timeout = 100, } },
        { .fn = check_result, .expected = { .result = &r, .data = "12", .count = 1, }}, // not reading
        { .fn = start_read_step, .write_args = { .s = &s }},
        { .fn = write_step, .write_args = { .s = &s, .data = "5",}},
        { .fn = write_step, .write_args = { .s = &s, .data = "6",}},
        { .fn = sleep_step, .sleep_args = { .timeout = 100, } },
        { .fn = check_result, .expected = { .result = &r, .data = "123456", .count = 4,}}, // should read echo from writes 3,4,5,6
        { .fn = disconnect_step, .connect_args = { .s = &s } },
        { .fn = nullptr }
    };

    start(loopTest.loop, steps);
    loopTest.run();
}