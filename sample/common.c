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

void logger(int level, const char *file, unsigned int line, const char *msg) {
#if _WIN32
        fprintf(stderr, "%s:%d %s\n", file, line, msg);
#else
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);

    fprintf(stderr, "[%9ld.%03ld] %s:%d %s\n", spec.tv_sec, spec.tv_nsec/1000000, file, line, msg);
#endif
}

void resp_cb(tlsuv_http_resp_t *resp, void *data) {
    if (resp->req->client->tls) {
            printf("Using %s\n", resp->req->client->tls->api->version());
    }
    if (resp->code < 0) {
        fprintf(stderr, "ERROR: %d(%s)", resp->code, uv_strerror(resp->code));
        return;
    }
    tlsuv_http_hdr *h;
    printf("Response (%d) >>>\nHeaders >>>\n", resp->code);
    LIST_FOREACH(h, &resp->headers, _next) {
        printf("\t%s: %s\n", h->name, h->value);
    }
    printf("\n");
}

void body_cb(tlsuv_http_req_t *req, const char *body, ssize_t len) {
    if (len == UV_EOF) {
        printf("\n\n====================\nRequest completed\n");
    }
    else if (len < 0) {
        fprintf(stderr, "error(%zd) %s", len, uv_strerror(len));
        //exit(-1);
    }
    else {
        printf("%*.*s", (int) len, (int) len, body);
    }
}
