/*
Copyright 2019 NetFoundry, Inc.

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

void resp_cb(um_http_req_t *req, int code, um_header_list *headers) {
    if (code < 0) {
        fprintf(stderr, "ERROR: %d(%s)", code, uv_strerror(code));
        exit(code);
    }
    um_http_hdr *h;
    printf("Response (%d) >>>\nHeaders >>>\n", code);
    if (headers) {
        LIST_FOREACH(h, headers, _next) {
            printf("\t%s: %s\n", h->name, h->value);
        }
    }
}

void body_cb(um_http_req_t *req, const char *body, ssize_t len) {
    if (len == UV_EOF) {
        printf("====================\nRequest completed\n");
    }
    else if (len < 0) {
        fprintf(stderr, "error(%zd) %s", len, uv_strerror(len));
        exit(-1);
    }
    else {
        printf("%*.*s", (int) len, (int) len, body);
    }
}

int main(int argc, char **argv) {
    uv_mbed_set_debug(5, stdout);
    uv_loop_t *loop = uv_default_loop();

    um_http_t clt;
    um_http_init(loop, &clt, "https://httpbin.org");

    um_http_req_t *r = um_http_req(&clt, "POST", "/post");
    r->resp_cb = resp_cb;
    r->body_cb = body_cb;

    const char *msg = "this is a test";
    um_http_req_data(r, msg, strlen(msg), NULL);

    uv_run(loop, UV_RUN_DEFAULT);
}


