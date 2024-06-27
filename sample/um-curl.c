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

#include "common.h"
#include <getopt.h>
#include <string.h>
#include <tlsuv/http.h>
#include <tlsuv/tlsuv.h>

struct app_ctx {
    tlsuv_http_t clt;
    char *path;
    int count;
    int cycle;
};

static void do_request(uv_timer_t *t) {
    struct app_ctx *app = t->data;

    if (app->count-- > 0) {
        tlsuv_http_req_t *r = tlsuv_http_req(&app->clt, "GET", app->path, resp_cb, NULL);
        r->resp.body_cb = body_cb;

        uv_timer_start(t, do_request, app->cycle * 1000, 0);
    } else {
        uv_close((uv_handle_t *) t, NULL);
        tlsuv_http_close(&app->clt, NULL);
    }
}

int main(int argc, char **argv) {
    struct app_ctx app = {
            .cycle = 10,
            .count = 1,
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
                    tlsuv_set_debug(level, logger);
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
    char *host_url = calloc(1, path - url + 1);
    strncpy(host_url, url, path - url);
    tlsuv_http_init(loop, &app.clt, host_url);
    tlsuv_http_idle_keepalive(&app.clt, -1);

    tlsuv_private_key_t tlsKey = NULL;
    tlsuv_certificate_t tlsCert = NULL;
    if (CA || (cert && key)) {
        tls = default_tls_context(CA, CA ? strlen(CA) + 1 : 0);

        if (cert && key) {
            tls->load_key(&tlsKey, key, strlen(key));
            tls->load_cert(&tlsCert, cert, strlen(cert));
            tls->set_own_cert(tls, tlsKey, tlsCert);
        }
        tlsuv_http_set_ssl(&app.clt, tls);
    }

    uv_timer_t timer;
    uv_timer_init(loop, &timer);
    timer.data = &app;
    uv_timer_start(&timer, do_request, 0, 0);
    uv_run(loop, UV_RUN_DEFAULT);
}


