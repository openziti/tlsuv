
#ifndef UV_MBED_FIXTURES_H
#define UV_MBED_FIXTURES_H

#include <catch2/catch_all.hpp>
#include <functional>
#include "tlsuv/tls_engine.h"
#include <uv.h>


extern tls_context *testServerTLS();

template<typename T> T* t_alloc() {
    return (T*)calloc(1, sizeof(T));
}

// readable condition lambdas
#define UNTIL(c) [&](){ return !(c); }
#define WHILE(c) [&](){ return (c); }


#define TEST_SERVER "127.0.0.1"

struct UvLoopTest {
    uv_loop_t *loop;
    uv_timer_t timer{};
    uv_prepare_t check{};

    UvLoopTest(): UvLoopTest(15) {}

    explicit UvLoopTest(unsigned int to):
            loop(uv_loop_new()) {
        uv_timer_init(loop, &timer);
        uv_prepare_init(loop, &check);

        timer.data = this;
        uv_unref((uv_handle_t*)&timer);

        setTimeout(to);
    }

    void setTimeout(unsigned int secs) {
        uv_timer_stop(&timer);
        if (secs > 0) {
            INFO("starting test timer");
            REQUIRE(uv_timer_start(&timer,
                                   [](uv_timer_t *t){
                                       uv_print_active_handles(t->loop, stderr);
                                       uv_stop(t->loop);
                                       FAIL_CHECK("test exceeded allotted time");
                                   }, secs * 1000, 0) == 0);
        }
    }

    // run test loop until no more active handles or test timeout
    void run() const {
        uv_run(loop, UV_RUN_DEFAULT);
    }

    // run while the condition is met or until no active handles
    void run(std::function<bool()> cond) {
        struct checker_s {
            std::function<bool()>& condition;
        } checker{cond};
        check.data = &checker;
        uv_prepare_start(&check, [](uv_prepare_t *ch){
            auto c = (checker_s*)(ch->data);
            bool b = c->condition();
            if (!b) {
                ch->data = nullptr;
                uv_prepare_stop(ch);
                uv_stop(ch->loop);
            }
        });

        uv_run(loop, UV_RUN_DEFAULT);
        if (check.data) {
            FAIL_CHECK("check condition never became false");
        }
    }

    // run loop for the given number of seconds, take care not to exceed the test total timeout
    void run(int to) const {
        auto t = new uv_timer_t;
        uv_timer_init(loop, t);

        uv_timer_start(t, [](uv_timer_t* t){ uv_stop(t->loop); }, to * 1000, 0);

        uv_run(loop, UV_RUN_DEFAULT);

        uv_close((uv_handle_t*)t, [](uv_handle_t* h){
            delete (uv_timer_t*)h;
        });
    }

    // run until nothing is left to do, but for 2 seconds at most and never blocking:
    // for cleanup (DEFER), which may run after a failure left a handle stuck, and
    // after the test timeout has already fired
    void drain() const {
        const uint64_t deadline = uv_hrtime() + 2 * 1000 * 1000 * 1000ULL;
        while (uv_loop_alive(loop) && uv_hrtime() < deadline) {
            uv_run(loop, UV_RUN_NOWAIT);
            uv_sleep(1);
        }
    }

    ~UvLoopTest() {
        INFO("test teardown");
        uv_close((uv_handle_t*)&timer, nullptr);
        uv_close((uv_handle_t*)&check, nullptr);
        // let closing handles finish, but never block: a test that failed with a handle
        // still open (e.g. a REQUIRE before its stream was closed) would otherwise wait
        // on it forever. Async engines close from their own threads, so poll a while.
        const uint64_t deadline = uv_hrtime() + 2 * 1000 * 1000 * 1000ULL;
        int rc;
        for (;;) {
            uv_run(loop, UV_RUN_NOWAIT);
            rc = uv_loop_close(loop);
            if (rc == 0 || uv_hrtime() > deadline) break;
            uv_sleep(1);
        }

        INFO("should be no leaked handles");
        CHECK(rc == 0);
        if (rc != 0) {
            fprintf(stderr, "loop_close_failed: %d(%s)", rc, uv_strerror(rc));
            uv_print_all_handles(loop, stderr);
            fflush(stderr);
            // leaked on purpose: handles still open refer to it, and an async engine may
            // still post wakeups to it
            return;
        }
        free(loop);
    }
};

struct TlsDeleter {
     void  operator()(tls_context *tls) {
         if (tls) {
             tls->free_ctx(tls);
         }
     }
};

#define TLSUV_TEST_CAT_(a, b) a ## b
#define TLSUV_TEST_CAT(a, b) TLSUV_TEST_CAT_(a, b)

struct deferrer {
    template<class F>
    deferrer(F &&f): cb(std::forward<F>(f)) {}
    ~deferrer() { cb(); }
    std::function<void()> cb;
};

// runs the block at scope exit, also when a REQUIRE throws:
//   DEFER { tlsuv_http_close(&clt, nullptr); test.drain(); };
// Declare it after every object the block, or a callback it triggers, touches:
// locals are destroyed in reverse order, so those are then still alive.
#define DEFER deferrer TLSUV_TEST_CAT(deferred_, __COUNTER__) = [&]()

#endif //UV_MBED_FIXTURES_H
