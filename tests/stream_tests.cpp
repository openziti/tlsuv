// Copyright (c) 2024. NetFoundry Inc.
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

#include <cstring>
#include <string>
#include <tlsuv/tlsuv.h>
#include <uv.h>

#include "fixtures.h"

#if _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close_socket closesocket
#define poll WSAPoll
#else
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#define close_socket close
#endif
#include <catch2/catch_all.hpp>

#define to_str_(x) #x
#define to_str(x) to_str_(x)
static const char *test_server_CA = to_str(TEST_SERVER_CA);

class testServer {
public:
    tls_context* TLS() {
        return tls;
    }
    testServer() {
        tls = default_tls_context(test_server_CA, strlen(test_server_CA));
    }

    ~testServer() {
        tls->free_ctx(tls);
    }
private:
    tls_context* tls;
};

tls_context* testServerTLS() {
    static testServer srv;
    return srv.TLS();
}

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
    test.run();
    tls->free_ctx(tls);

}

TEST_CASE("proxy connect fail", "[stream]") {
    UvLoopTest test;
    auto proxy = tlsuv_new_proxy_connector(tlsuv_PROXY_HTTP, TEST_SERVER, "23128");

    auto s = new tlsuv_stream_t;
    tls_context *tls = default_tls_context(nullptr, 0);
    tlsuv_stream_init(test.loop, s, tls);
    tlsuv_stream_set_connector(s, proxy);

    struct test_ctx {
        int connect_result;
        int connect_called;
        int close_called;
    } test_ctx = {0,0,0};

    s->data = &test_ctx;

    uv_connect_t cr;
    cr.data = &test_ctx;
    int rc = tlsuv_stream_connect(&cr, s, "1.1.1.1", 443, [](uv_connect_t *r, int status) {
        auto ctx = (struct test_ctx *) r->data;
        ctx->connect_result = status;
        ctx->connect_called++;
        uv_close_cb closeCb = [](uv_handle_t *h) {
            auto s = (tlsuv_stream_t *) h;
            auto ctx = (struct test_ctx*)s->data;
            ctx->close_called++;
            tlsuv_stream_free(s);
            delete s;
        };
        tlsuv_stream_close((tlsuv_stream_t*)r->handle, closeCb);
    });

    test.run();

    CHECK(rc == 0);
    CHECK(test_ctx.close_called == 1);
    CHECK(test_ctx.connect_called == 1);
    CHECK(test_ctx.connect_result == UV_ECONNREFUSED);

    tls->free_ctx(tls);

    proxy->free(proxy);
}


TEST_CASE("proxy request fail", "[stream]") {
    UvLoopTest test;
    auto proxy = tlsuv_new_proxy_connector(tlsuv_PROXY_HTTP, TEST_SERVER, "13128");

    auto s = new tlsuv_stream_t;
    tls_context *tls = default_tls_context(nullptr, 0);
    tlsuv_stream_init(test.loop, s, tls);
    tlsuv_stream_set_connector(s, proxy);

    struct test_ctx {
        int connect_result;
        int connect_called;
        int close_called;
    } test_ctx = {0,0,0};

    s->data = &test_ctx;

    uv_connect_t cr;
    cr.data = &test_ctx;
    int rc = tlsuv_stream_connect(&cr, s, TEST_SERVER, 23128, [](uv_connect_t *r, int status) {
        auto ctx = (struct test_ctx *) r->data;
        ctx->connect_result = status;
        ctx->connect_called++;
        uv_close_cb closeCb = [](uv_handle_t *h) {
            auto s = (tlsuv_stream_t *) h;
            auto ctx = (struct test_ctx*)s->data;
            ctx->close_called++;
            tlsuv_stream_free(s);
            delete s;
        };
        tlsuv_stream_close((tlsuv_stream_t*)r->handle, closeCb);
    });

    test.run();

    CHECK(rc == 0);
    CHECK(test_ctx.close_called == 1);
    CHECK(test_ctx.connect_called == 1);
    CHECK(test_ctx.connect_result == UV_ECONNREFUSED);

    tls->free_ctx(tls);

    proxy->free(proxy);
}

TEST_CASE("cancel connect", "[stream]") {
    UvLoopTest test;

    int timeout = GENERATE(1, 10, 100, 1000);

    WHEN("timeout = " << timeout) {
        auto s = new tlsuv_stream_t;
        tls_context *tls = default_tls_context(nullptr, 0);
        tlsuv_stream_init(test.loop, s, tls);

        struct test_ctx {
            int connect_result;
            bool connect_called;
            bool close_called;
        } test_ctx{};

        s->data = &test_ctx;

        auto cr = static_cast<uv_connect_t*>(calloc(1, sizeof(uv_connect_t)));
        cr->data = &test_ctx;
        int rc = tlsuv_stream_connect(cr, s, "one.one.one.one", 5555, [](uv_connect_t *r, int status) {
            auto ctx = static_cast<struct test_ctx*>(r->data);
            ctx->connect_result = status;
            ctx->connect_called = true;
            free(r);
        });

        uv_timer_t t;
        uv_timer_init(test.loop, &t);
        t.data = s;
        auto timer_cb = [](uv_timer_t* t){
            auto *c = static_cast<tlsuv_stream_t *>(t->data);
            auto closeCb = [](uv_handle_t *h) {
                auto s = reinterpret_cast<tlsuv_stream_t*>(h);
                auto ctx = static_cast<struct test_ctx*>(s->data);
                ctx->close_called = true;
                tlsuv_stream_free(s);
                delete s;
            };
            tlsuv_stream_close(c, closeCb);
            uv_close(reinterpret_cast<uv_handle_t *>(t), nullptr);
        };
        uv_timer_start(&t, timer_cb, timeout, 0);
        test.run();

        CHECK(rc == 0);
        CHECK(test_ctx.close_called);
        CHECK(test_ctx.connect_called);
        INFO("connect result: " << uv_strerror(test_ctx.connect_result) << " " << uv_strerror(UV_ECANCELED));
        CHECK(test_ctx.connect_result == UV_ECANCELED);

        tls->free_ctx(tls);
    }
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
    } test_ctx{};

    s.data = &test_ctx;

    uv_connect_t cr;
    cr.data = &test_ctx;
    int rc = tlsuv_stream_connect(&cr, &s, "1.1.1.1", 443, [](uv_connect_t *r, int status) {
        REQUIRE(status == 0);
        auto c = reinterpret_cast<tlsuv_stream_t*>(r->handle);

        auto proto = tlsuv_stream_get_protocol(c);
        REQUIRE(proto != nullptr);
        CHECK_THAT(proto, Catch::Matchers::Equals("http/1.1"));

        tlsuv_stream_read_start(c, test_alloc, [](uv_stream_t *s, ssize_t status, const uv_buf_t *b) {
            auto c = reinterpret_cast<tlsuv_stream_t*>(s);
            if (status == UV_EOF) {
                tlsuv_stream_close(c, nullptr);
            } else if (status >= 0) {
                if (status > 0) {
                    REQUIRE_THAT(b->base, Catch::Matchers::StartsWith("HTTP/1.1 200 OK"));
                    fprintf(stderr, "%.*s\n", (int) status, b->base);
                }
            } else {
                FAIL("status: " << status << " " << uv_strerror(status));
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
        uv_buf_t buf = uv_buf_init(const_cast<char*>(msg), strlen(msg));
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


    REQUIRE(nread >= 0);

    if (nread > 0) {
        result->read_count++;
        result->read_data.append(buf->base, nread);
    }

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
            .connect_args = { .s = &s, .hostname = TEST_SERVER, .port = 7443, .result = &r },
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

// this test is designed to block echo server since it is not reading back
// eventually echo server will block on write and stop reading
// this will cause this stream to block writing
// the write requests will get either success of cancellation at the end of the test
TEST_CASE("large/partial writes", "[stream]") {
    tlsuv_stream_t s;
    UvLoopTest loopTest;
    uv_connect_t cr;
    cr.data = &s;

    struct connect_res {
        bool called;
        int err;
    } conn_res = { false, 0 };
    cr.data = &conn_res;

    struct write_res {
        int count;
        std::vector<int> results;
    } w_res = {0};

    tlsuv_stream_init(loopTest.loop, &s, testServerTLS());
    // after w_res: closing cancels queued writes, whose callbacks record into it
    DEFER {
        tlsuv_stream_close(&s, (uv_close_cb) tlsuv_stream_free); // UV_EALREADY if closed below
        loopTest.drain();
    };

    tlsuv_stream_connect(&cr, &s, TEST_SERVER, 7443, [](uv_connect_t *r, int status){
        auto res = (connect_res*) r->data;
        res->called = true;
        res->err = status;
    });

    loopTest.run(UNTIL(conn_res.called));
    REQUIRE(conn_res.err == 0);

#define MSG_SIZE (1024*1024)

    s.data = &w_res;
    for (int i = 0; i < 20; i++) {
        auto w = new uv_write_t;
        w->data = malloc(MSG_SIZE);

        auto buf = uv_buf_init((char*)w->data, MSG_SIZE);

        tlsuv_stream_write(w, &s, &buf, [](uv_write_t *w, int status){
            auto s = (tlsuv_stream_t *)w->handle;
            auto res = (write_res*) s->data;
            res->results.push_back(status);

            free(w->data);
            delete w;
        });
        w_res.count++;
    }

    // let it run to fill the 'wire'
    loopTest.run(1);

    tlsuv_stream_close(&s, [](uv_handle_t *h){
        tlsuv_stream_free((tlsuv_stream_t *)h);
    });

    // should get the same number of callbacks as write requests
    loopTest.run(UNTIL(w_res.count == w_res.results.size()));

    // each write req should either succeed or be cancelled by close
    auto successes = std::count(w_res.results.begin(), w_res.results.end(), 0);
    auto cancelled = std::count(w_res.results.begin(), w_res.results.end(), UV_ECANCELED);

    INFO("success=" << successes << ", cancelled=" << cancelled);
    CHECK(cancelled > 0);
    CHECK(successes + cancelled == w_res.results.size());
}

// the app reads into buffers much smaller than what the engine decrypts at once:
// process_inbound() stops after MAX_INBOUND_ITERATIONS reads per wakeup, with the
// rest still inside the engine and nothing left on the socket to signal it
TEST_CASE("small read buffers", "[stream]") {
    UvLoopTest test;
    tlsuv_stream_t s;
    tlsuv_stream_init(test.loop, &s, testServerTLS());

    struct echo_state {
        std::vector<char> sent;
        std::vector<char> got;
        size_t read_size;
        int connect_status = 1;
        int read_error = 0;
    } st;
    st.read_size = GENERATE(97, 1000);
    CAPTURE(st.read_size);
    for (size_t i = 0; i < 64 * 1024; i++) {
        st.sent.push_back((char) (i * 7 + i / 251));
    }
    s.data = &st;

    uv_connect_t cr;
    uv_write_t wr;
    // after st, cr and wr: closing cancels pending requests, whose callbacks use them
    DEFER {
        tlsuv_stream_close(&s, (uv_close_cb) tlsuv_stream_free);
        test.drain();
    };
    cr.data = &st;
    tlsuv_stream_connect(&cr, &s, TEST_SERVER, 7443, [](uv_connect_t *r, int status) {
        auto st = (echo_state *) r->data;
        st->connect_status = status;
    });
    test.run(UNTIL(st.connect_status != 1));
    REQUIRE(st.connect_status == 0);

    tlsuv_stream_read_start(&s,
        [](uv_handle_t *h, size_t, uv_buf_t *b) {
            auto st = (echo_state *) h->data;
            *b = uv_buf_init((char *) malloc(st->read_size), (unsigned int) st->read_size);
        },
        [](uv_stream_t *h, ssize_t n, const uv_buf_t *b) {
            auto st = (echo_state *) h->data;
            if (n > 0) {
                st->got.insert(st->got.end(), b->base, b->base + n);
            } else if (n < 0) {
                st->read_error = (int) n;
            }
            free(b->base);
        });

    uv_buf_t buf = uv_buf_init(st.sent.data(), (unsigned int) st.sent.size());
    REQUIRE(tlsuv_stream_write(&wr, &s, &buf, [](uv_write_t *, int status) {
        CHECK(status == 0);
    }) == 0);

    test.run(UNTIL(st.got.size() >= st.sent.size() || st.read_error != 0));
    CHECK(st.read_error == 0);
    REQUIRE(st.got.size() == st.sent.size());
    CHECK(st.got == st.sent);
}

// the app has no buffer (alloc_cb returns an empty one, read_cb gets UV_ENOBUFS)
// while the peer has already closed: reading must go on once it has buffers again,
// and deliver the rest of the data and the EOF
TEST_CASE("no buffer after peer close", "[stream]") {
    UvLoopTest test;
    tlsuv_stream_t s;
    tlsuv_stream_init(test.loop, &s, testServerTLS());

    struct state {
        int connect_status = 1;
        bool written = false;
        int empty_allocs = 3; // the idle read, then poll events that report the disconnect
        int enobufs = 0;
        std::string data;
        int end = 0; // UV_EOF, or the error that ended reading
    } st;
    s.data = &st;

    uv_connect_t cr;
    uv_write_t wr;
    std::string req = "GET /json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    // after st, cr, wr and req: closing cancels pending requests, whose callbacks use them
    DEFER {
        tlsuv_stream_close(&s, (uv_close_cb) tlsuv_stream_free);
        test.drain();
    };
    cr.data = &st;
    tlsuv_stream_connect(&cr, &s, TEST_SERVER, 8443, [](uv_connect_t *r, int status) {
        ((state *) r->data)->connect_status = status;
    });
    test.run(UNTIL(st.connect_status != 1));
    REQUIRE(st.connect_status == 0);

    // the server answers and closes before we start reading
    wr.data = &st;
    uv_buf_t buf = uv_buf_init(req.data(), (unsigned int) req.size());
    REQUIRE(tlsuv_stream_write(&wr, &s, &buf, [](uv_write_t *w, int status) {
        CHECK(status == 0);
        ((state *) w->data)->written = true;
    }) == 0);
    test.run(UNTIL(st.written));
    test.run(1); // let the request out, and the response and the close come in

    tlsuv_stream_read_start(&s,
        [](uv_handle_t *h, size_t suggested, uv_buf_t *b) {
            auto st = (state *) h->data;
            if (st->empty_allocs > 0) {
                st->empty_allocs--;
                *b = uv_buf_init(nullptr, 0);
            } else {
                *b = uv_buf_init((char *) malloc(suggested), (unsigned int) suggested);
            }
        },
        [](uv_stream_t *h, ssize_t n, const uv_buf_t *b) {
            auto st = (state *) h->data;
            if (n > 0) {
                st->data.append(b->base, n);
            } else if (n == UV_ENOBUFS) {
                st->enobufs++;
            } else if (n < 0) {
                st->end = (int) n;
            }
            free(b->base);
        });

    test.run(UNTIL(st.end != 0));
    CHECK(st.enobufs > 0);
    CHECK(st.end == UV_EOF);
    CHECK_THAT(st.data, Catch::Matchers::StartsWith("HTTP/1.1 200 OK"));
}

TEST_CASE_METHOD(UvLoopTest, "stream/global proxy", "[stream]") {
    auto const proxy_port = "13128";
    auto proxy = tlsuv_new_proxy_connector(tlsuv_PROXY_HTTP, TEST_SERVER, proxy_port);
    tlsuv_set_global_connector(proxy);

    setTimeout(300);
    tlsuv_stream_t s;
    CHECK(tlsuv_stream_init(loop, &s, testServerTLS()) == 0);
    CHECK(s.connector == proxy);
    struct res {
        bool conn_cb;
        int conn_status;
        char readbuf[128];
        std::string data;
        int read_status;
    } result = { false, 0, "", "", 0 };

    s.data = &result;

    uv_connect_t cr;
    // after result and cr; also puts the global connector back for the tests after this one
    DEFER {
        tlsuv_stream_close(&s, (uv_close_cb) tlsuv_stream_free);
        drain();
        tlsuv_set_global_connector(nullptr);
        proxy->free(proxy);
    };
    cr.data = &s;
    tlsuv_stream_connect(&cr, &s, TEST_SERVER, 7443, [](uv_connect_t *r, int status){
        auto clt = (tlsuv_stream_t*)r->data;
        auto result = (res*)clt->data;
        result->conn_cb = true;
        result->conn_status = status;
        fprintf(stderr, "result = %p\n", result);
    });

    run(UNTIL(result.conn_cb));

    INFO("check connected");
    fprintf(stderr, "result = %p\n", &result);

    REQUIRE(result.conn_status == 0);

    sockaddr_storage peer;
    int peer_len = sizeof(peer);
    CHECK(tlsuv_stream_peername(&s, (sockaddr*)&peer, &peer_len) == 0);
    int port = -1;
    if (peer.ss_family == AF_INET) {
        port = ntohs(((sockaddr_in*)&peer)->sin_port);
    } else if (peer.ss_family == AF_INET6) {
        port = ntohs(((sockaddr_in6*)&peer)->sin6_port);
    }
    INFO("check connected via proxy");
    CHECK(port == 13128);

    tlsuv_stream_read_start(&s,
                            [](uv_handle_t * s,size_t sug, uv_buf_t* buf){
                                auto clt = (tlsuv_stream_t *)s;
                                auto result = (res*)clt->data;
                                buf->base = result->readbuf;
                                buf->len = sizeof(result->readbuf);
                            },
                            [](uv_stream_t *s, ssize_t n, const uv_buf_t* buf){
                                auto clt = (tlsuv_stream_t *)s;
                                auto result = (res*)clt->data;
                                if (n < 0) {
                                    result->read_status = (int)n;
                                } else {
                                    result->data.append(buf->base, n);
                                }
                            });
    uv_buf_t write = uv_buf_init((char*)"12345", 5);
    CHECK(tlsuv_stream_try_write(&s, &write) == 5);

    while(result.data != "12345") {
        uv_run(loop, UV_RUN_ONCE);
    }
}


TEST_CASE("stream ALPN negotiation", "[stream]") {
    // 8443: Go net/http TLS server, advertises [h2, http/1.1] and picks by its own preference
    // 7443: TLS echo server, no ALPN configured
    struct alpn_case {
        const char *name;
        int port;
        std::vector<const char*> offer;
        const char *expected; // nullptr: nothing negotiated
    };
    auto tc = GENERATE(
            alpn_case{"http/1.1 among unknown", 8443, {"foo", "bar", "http/1.1"}, "http/1.1"},
            alpn_case{"h2 only", 8443, {"h2"}, "h2"},
            alpn_case{"server preference wins", 8443, {"http/1.1", "h2"}, "h2"},
            alpn_case{"nothing offered", 8443, {}, nullptr},
            alpn_case{"server without ALPN", 7443, {"foo", "http/1.1"}, nullptr}
    );
    INFO(tc.name);

    UvLoopTest test;
    tlsuv_stream_t s;
    tlsuv_stream_init(test.loop, &s, testServerTLS());
    if (!tc.offer.empty()) {
        tlsuv_stream_set_protocols(&s, (int) tc.offer.size(), tc.offer.data());
    }

    struct connect_res {
        bool called;
        int status;
        std::string proto;
        bool has_proto;
    } res{};

    uv_connect_t cr;
    // after res and cr, which the connect callback uses
    DEFER {
        tlsuv_stream_close(&s, (uv_close_cb) tlsuv_stream_free);
        test.drain();
    };
    cr.data = &res;
    REQUIRE(tlsuv_stream_connect(&cr, &s, TEST_SERVER, tc.port, [](uv_connect_t *r, int status) {
        auto res = (connect_res *) r->data;
        res->called = true;
        res->status = status;
        if (status == 0) {
            auto p = tlsuv_stream_get_protocol((tlsuv_stream_t *) r->handle);
            res->has_proto = p != nullptr && *p != '\0';
            if (res->has_proto) res->proto = p;
        }
    }) == 0);

    test.run(UNTIL(res.called));
    REQUIRE(res.status == 0);

    if (tc.expected) {
        REQUIRE(res.has_proto);
        CHECK_THAT(res.proto, Catch::Matchers::Equals(tc.expected));
    } else {
        // backends report "no ALPN" as either NULL or ""
        CHECK_FALSE(res.has_proto);
    }
}

// base64 body of a PEM, whitespace and armour stripped, for comparing encodings
static std::string pem_body(const std::string &pem) {
    std::string out;
    bool in_body = false;
    size_t pos = 0;
    while (pos < pem.size()) {
        size_t eol = pem.find('\n', pos);
        if (eol == std::string::npos) eol = pem.size();
        std::string line = pem.substr(pos, eol - pos);
        pos = eol + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.rfind("-----BEGIN", 0) == 0) { in_body = true; continue; }
        if (line.rfind("-----END", 0) == 0) break; // first certificate only
        if (in_body) out += line;
    }
    return out;
}

TEST_CASE("stream peer certificate", "[stream]") {
    UvLoopTest test;

    // the test server issues its own localhost certificate at startup, so compare
    // against the leaf the TLS stack handed to the verify callback in this handshake
    static std::string verified_leaf;
    verified_leaf.clear();
    tls_context *tls = default_tls_context(nullptr, 0);
    tls->set_cert_verify(tls, [](const struct tlsuv_certificate_s *cert, void *) -> int {
        char *pem = nullptr;
        size_t len = 0;
        if (cert->to_pem(cert, 0, &pem, &len) == 0) {
            verified_leaf = pem_body(std::string(pem, len));
            free(pem);
        }
        return 0;
    }, nullptr);

    // not every backend implements it (e.g. mbedtls)
    {
        tlsuv_engine_t eng = tls->new_engine(tls, "localhost");
        bool supported = eng->get_peer_cert != nullptr;
        if (supported) {
            tlsuv_certificate_t c = nullptr;
            INFO("before handshake");
            CHECK(eng->get_peer_cert(eng, &c) == TLS_ERR);
            CHECK(c == nullptr);
        }
        eng->free(eng);
        if (!supported) {
            tls->free_ctx(tls);
            SKIP("get_peer_cert is not implemented");
        }
    }

    tlsuv_stream_t s;
    tlsuv_stream_init(test.loop, &s, tls);

    struct connect_res {
        bool called;
        int status;
    } res{};
    uv_connect_t cr;
    tlsuv_certificate_t peer = nullptr;
    // after res and cr, which the connect callback uses; the stream goes before tls
    DEFER {
        if (peer) peer->free(peer);
        tlsuv_stream_close(&s, (uv_close_cb) tlsuv_stream_free);
        test.drain();
        tls->free_ctx(tls);
    };
    cr.data = &res;
    REQUIRE(tlsuv_stream_connect(&cr, &s, "localhost", 8443, [](uv_connect_t *r, int status) {
        auto res = (connect_res *) r->data;
        res->called = true;
        res->status = status;
    }) == 0);
    test.run(UNTIL(res.called));
    REQUIRE(res.status == 0);
    REQUIRE_FALSE(verified_leaf.empty());

    REQUIRE(s.tls_engine->get_peer_cert(s.tls_engine, &peer) == 0);
    REQUIRE(peer != nullptr);

    char *pem = nullptr;
    size_t pem_len = 0;
    REQUIRE(peer->to_pem(peer, 0, &pem, &pem_len) == 0);
    std::string leaf(pem, pem_len);
    free(pem);
    CHECK(pem_body(leaf) == verified_leaf);

    // the exported leaf is a usable certificate
    tlsuv_certificate_t reloaded = nullptr;
    CHECK(tls->load_cert(&reloaded, leaf.c_str(), leaf.size()) == 0);
    if (reloaded) reloaded->free(reloaded);

    struct tm exp{};
    CHECK(peer->get_expiration(peer, &exp) == 0);
}

// drive an engine directly over a blocking TCP socket (no tlsuv_stream_t)
static uv_os_sock_t connect_tcp(const char *host, const char *port) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *ai = nullptr;
    if (getaddrinfo(host, port, &hints, &ai) != 0) return (uv_os_sock_t) -1;
    uv_os_sock_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (connect(s, ai->ai_addr, (int) ai->ai_addrlen) != 0) {
        close_socket(s);
        s = (uv_os_sock_t) -1;
    }
    freeaddrinfo(ai);

    // engines expect a non-blocking socket (they read until it would block)
    if (s != (uv_os_sock_t) -1) {
#if _WIN32
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
#else
        fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
#endif
    }
    return s;
}

static void wait_readable(uv_os_sock_t s, int ms) {
    pollfd pfd{};
    pfd.fd = s;
    pfd.events = POLLIN;
    poll(&pfd, 1, ms);
}

static bool engine_handshake_sync(tlsuv_engine_t eng, uv_os_sock_t s) {
    // async engines make progress between calls, so keep calling with a short wait
    for (int i = 0; i < 200; i++) {
        tls_handshake_state st = eng->handshake(eng);
        if (st == TLS_HS_COMPLETE) return true;
        if (st == TLS_HS_ERROR) return false;
        wait_readable(s, 25);
    }
    return false;
}

static std::string engine_echo_sync(tlsuv_engine_t eng, uv_os_sock_t s, const std::string &msg) {
    size_t sent = 0;
    for (int i = 0; i < 200 && sent < msg.size(); i++) {
        int rc = eng->write(eng, msg.data() + sent, msg.size() - sent);
        if (rc > 0) {
            sent += rc;
        } else if (rc != TLS_AGAIN) {
            return "<write failed>";
        } else {
            wait_readable(s, 25);
        }
    }

    std::string got;
    char buf[1024];
    for (int i = 0; i < 200 && got.size() < msg.size(); i++) {
        size_t n = 0;
        int rc = eng->read(eng, buf, &n, sizeof(buf));
        got.append(buf, n);
        if (rc == TLS_EOF || rc == TLS_ERR) break;
        if (n == 0) wait_readable(s, 25);
    }
    return got;
}

// reset() must leave the engine able to run a new handshake on a new connection
TEST_CASE("engine reset and reuse", "[stream]") {
    UvLoopTest test; // initializes the socket library on windows
    tls_context *tls = testServerTLS();
    tlsuv_engine_t eng = tls->new_engine(tls, "localhost");
    uv_os_sock_t s = (uv_os_sock_t) -1;
    // an async engine's own threads keep its connection going until it is freed
    DEFER {
        eng->close(eng);
        eng->free(eng);
        if (s != (uv_os_sock_t) -1) close_socket(s);
    };
    REQUIRE(eng->reset != nullptr);

    for (int round = 0; round < 3; round++) {
        INFO("round " << round);
        if (round > 0) {
            REQUIRE(eng->reset(eng) == 0);
            close_socket(s);
            s = (uv_os_sock_t) -1;
        }

        s = connect_tcp(TEST_SERVER, "7443");
        REQUIRE(s != (uv_os_sock_t) -1);
        eng->set_io_fd(eng, (tlsuv_sock_t) s);

        REQUIRE(engine_handshake_sync(eng, s));
        std::string msg = "hello #" + std::to_string(round);
        CHECK(engine_echo_sync(eng, s, msg) == msg);
    }
}

TEST_CASE("connect to address", "[stream]") {
    UvLoopTest test;

    tlsuv_stream_t s;
    tlsuv_stream_init(test.loop, &s, testServerTLS());

    struct test_ctx {
        int connect_result;
        int connect_called;
        int close_called;
    } test_ctx = {2171,0,0};

    s.data = &test_ctx;

    uv_connect_t cr;
    cr.data = &test_ctx;


    uv_getaddrinfo_t res_req{};
    addrinfo hints = {
            .ai_family = AF_INET,
            .ai_socktype = SOCK_STREAM,
    };
    REQUIRE(uv_getaddrinfo(test.loop, &res_req, nullptr, TEST_SERVER, "7443", &hints) == 0);


    auto rc = tlsuv_stream_connect_addr(&cr, &s, res_req.addrinfo, [](uv_connect_t *r, int status) {
        auto ctx = (struct test_ctx *) r->data;
        ctx->connect_result = status;
        ctx->connect_called++;
    });

    CHECK(rc == 0);


    test.run(UNTIL(test_ctx.connect_called == 1));
    if (test_ctx.connect_result != 0) {
        UNSCOPED_INFO("connect result: " << uv_strerror(test_ctx.connect_result));
    }
    CHECK(test_ctx.connect_result == 0);

    tlsuv_stream_close(&s, [](uv_handle_t *h) {
        auto s = (tlsuv_stream_t *) h;
        auto ctx = (struct test_ctx *) s->data;
        ctx->close_called++;
        tlsuv_stream_free(s);
    });

    test.run();
    uv_freeaddrinfo(res_req.addrinfo);
}
