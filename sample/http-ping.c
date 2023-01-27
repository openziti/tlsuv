// Copyright (c) 2018-2023 NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <tlsuv/http.h>
#include <tlsuv/tlsuv.h>
#include <uv.h>

static struct opts {
    int keepalive;
    int timeout;
    int ping_count;
    int delay;
} opts = {
        .keepalive = 10000,
        .timeout = 1000,
        .delay = 2000,
        .ping_count = 3,
};

static void on_response(tlsuv_http_resp_t *resp, void* ctx) {
    printf("%d %s\n", resp->code, resp->status);
}

static void on_clt_close(tlsuv_http_t * http) {
    printf("HTTP is closed\n");
}

static void do_request(uv_timer_t *t) {
    tlsuv_http_t *http = t->data;

    tlsuv_http_req(http, "GET", "/json", on_response, NULL);
    if (--opts.ping_count <= 0) {
        uv_close((uv_handle_t *) t, NULL);
        tlsuv_http_close(http, on_clt_close);
    }
}

void logger(int level, const char *file, unsigned int line, const char *msg) {

    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);

    fprintf(stderr, "[%9ld.%03ld] %s:%d %s\n", spec.tv_sec, spec.tv_nsec/1000000, file, line, msg);
}

int main(int argc, char *argv[]) {
    tlsuv_set_debug(6, logger);
    uv_loop_t *l = uv_default_loop();
    tlsuv_http_t http;
    tlsuv_http_init(l, &http, "https://httpbin.org");
    tlsuv_http_idle_keepalive(&http, opts.keepalive);
    tlsuv_http_connect_timeout(&http, opts.timeout);

    uv_timer_t timer;
    uv_timer_init(l, &timer);
    timer.data = &http;

    uv_timer_start(&timer, do_request, 0, opts.delay);
    uv_run(l, UV_RUN_DEFAULT);
}
