/*
Copyright 2019-2020 NetFoundry, Inc.

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

#include <uv_mbed/um_http.h>
#include <string.h>
#include <uv_mbed/uv_mbed.h>
#include <getopt.h>
#include "common.h"

struct app_ctx {
    um_http_t clt;
    char *path;
    int count;
    int cycle;
};

static void do_request(uv_timer_t *t) {
    struct app_ctx *app = t->data;

    um_http_req_t *r = um_http_req(&app->clt, "GET", app->path, resp_cb, NULL);
    r->resp.body_cb = body_cb;

    if (app->count-- > 0) {
        uv_timer_start(t, do_request, app->cycle * 1000, 0);
    } else {
        uv_close((uv_handle_t *) t, NULL);
        um_http_close(&app->clt, NULL);
    }
}

int main(int argc, char **argv) {
    struct app_ctx app = {
            .cycle = 10,
    };

    tls_context *tls = NULL;
    char *CA = NULL;
    char *cert = NULL;
    char *key = NULL;

    extern char *optarg;
    extern int optind;
    int c, err;
    while((c = getopt(argc, argv, "C:c:k:r:t:d:")) != -1) {
        switch (c) {
            case 'C':
                if (optarg) {
                    CA = optarg;
                }
                break;
            case 'c':
                if (optarg) cert = optarg;
                break;
            case 'k':
                if (optarg) key = optarg;
                break;
            case 'r':
                if (optarg) app.count = atoi(optarg);
                break;

            case 't':
                if (optarg) app.cycle = atoi(optarg);
                break;
            case 'd':
                if (optarg) {
                    int level = atoi(optarg);
                    uv_mbed_set_debug(level, logger);
                }
                break;
        }
    }

    char *url = argv[optind];
    char *path = url;
    for (int i = 0; i<3; i++) {
        path = strchr(path + 1, '/');
    }
    app.path = path ? path : "/";

    uv_loop_t *loop = uv_default_loop();
    char *host_url = strndup(url, path - url);
    um_http_init(loop, &app.clt, host_url);
    um_http_idle_keepalive(&app.clt, -1);

    if (CA || (cert && key)) {
        tls = default_tls_context(CA, CA ? strlen(CA) + 1 : 0);

        if (cert && key) {
            tls->api->set_own_cert(tls->ctx, cert, strlen(cert), key, strlen(key));
        }
        um_http_set_ssl(&app.clt, tls);
    }

    uv_timer_t timer;
    uv_timer_init(loop, &timer);
    timer.data = &app;
    uv_timer_start(&timer, do_request, 0, 0);
    uv_run(loop, UV_RUN_DEFAULT);
}


