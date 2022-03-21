
#ifndef UV_MBED_FIXTURES_H
#define UV_MBED_FIXTURES_H

#include "catch.hpp"
#include <uv.h>

template<typename T> T* t_alloc() {
    return (T*)calloc(1, sizeof(T));
}

struct UvLoopTest {
    unsigned int timeout;
    uv_loop_t *loop;
    uv_timer_t *timer;

    UvLoopTest(): UvLoopTest(15) {}

    UvLoopTest(unsigned int to): timeout(to), loop(t_alloc<uv_loop_t>()), timer(t_alloc<uv_timer_t>()){
        uv_loop_init(loop);
        uv_timer_init(loop, timer);
        timer->data = this;
    }

    static void test_to(uv_timer_t *t) {
        INFO("timeout stopping loop");
        uv_print_all_handles(t->loop, stderr);
        uv_stop(t->loop);
    }

    void run() {
        uv_timer_start(timer, test_to, timeout * 1000, 0);
        uv_unref((uv_handle_t *)timer);
        uv_run(loop, UV_RUN_DEFAULT);
    }

    ~UvLoopTest() {
        INFO("test teardown");

        uv_close((uv_handle_t*) timer, nullptr);
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
        free(timer);
        free(loop);
    }
};

#endif //UV_MBED_FIXTURES_H
