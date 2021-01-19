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

    uv_connect_cb cb = [](uv_connect_t *r, int status) -> void {
        int *countp = (int*)r->data;
        *countp = *countp + 1;
        printf("conn cb called status = %d(%s)\n", status, status != 0 ? uv_strerror(status) : "");
    };
    int rc = 0;
    WHEN("connect fail") {
        rc = uv_mbed_connect(&cr, &mbed, "127.0.0.1", 62443, cb);
    }
    WHEN("resolve fail") {
        rc = uv_mbed_connect(&cr, &mbed, "foo.bar.baz", 443, cb);
    }

    printf ("conn rc = %d(%s)\n", rc, rc ? uv_strerror(rc) : "");
    uv_run(l, UV_RUN_DEFAULT);

    CHECK( ((rc == 0 && conn_cb_called == 1) || (rc != 0 && conn_cb_called == 0)) );
    uv_mbed_free(&mbed);
    uv_loop_close(l);
    uv_run(l, UV_RUN_DEFAULT);

    free(l);

    tls->api->free_ctx(tls);
}