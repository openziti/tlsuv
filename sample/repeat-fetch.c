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

/**
 * \file repeat-fetch.c
 * \brief demonstrates re-connecting usage of HTTP client
 */

#include "common.h"
#include <tlsuv/http.h>

int count = 5;
tlsuv_http_t time_clt;
uv_timer_t time_timer;

static void timer_cb(uv_timer_t *timer) {
    if (count-- > 0) {
        printf(">>> calling time service count left = %d\n\n", count);
        tlsuv_http_req_t *req = tlsuv_http_req(&time_clt, "GET", "/api/timezone/EST", resp_cb, NULL);
        req->resp.body_cb = body_cb;
    } else {
        uv_timer_stop(timer);
        tlsuv_http_close(&time_clt, NULL);
    }
}

int main(int argc, char **argv) {
    uv_loop_t *loop = uv_default_loop();

    tlsuv_http_init(loop, &time_clt, "https://worldtimeapi.org");
    uv_timer_init(loop, &time_timer);
    uv_timer_start(&time_timer, timer_cb, 1000, 5000);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
}


