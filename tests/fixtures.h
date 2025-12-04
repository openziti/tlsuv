
#ifndef UV_MBED_FIXTURES_H
#define UV_MBED_FIXTURES_H

#include <catch2/catch_all.hpp>
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

    ~UvLoopTest() {
        INFO("test teardown");
        uv_close((uv_handle_t*)&timer, nullptr);
        uv_close((uv_handle_t*)&check, nullptr);
        int attempt = 3;

        int rc;
        do {
            uv_run(loop, UV_RUN_ONCE);
            rc = uv_loop_close(loop);
        } while (rc != 0 && attempt-- > 0);

        INFO("should be no leaked handles");
        CHECK(rc == 0);
        if (rc != 0) {
            fprintf(stderr, "loop_close_failed: %d(%s)", rc, uv_strerror(rc));
            uv_print_all_handles(loop, stderr);
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

#endif //UV_MBED_FIXTURES_H
