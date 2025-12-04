// Copyright (c) NetFoundry Inc.
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

#ifndef UV_MBED_HTTP_REQ_H
#define UV_MBED_HTTP_REQ_H

#include <tlsuv/http.h>

#define SLASH "/"

void http_req_init(tlsuv_http_req_t* req, const char* method, const char* path);
int http_req_cancel_err(tlsuv_http_t* clt, tlsuv_http_req_t* req, int error, const char* msg);

void http_req_free(tlsuv_http_req_t * r);
ssize_t http_req_process(tlsuv_http_req_t* req, const char* buf, ssize_t len);
int http_req_finish(tlsuv_http_req_t * req);

// write request header
ssize_t http_req_write(tlsuv_http_req_t* req, char* buf, size_t maxlen);

void free_hdr_list(um_header_list * l);
void set_http_header(um_header_list* hl, const char* name, const char* value);
void set_http_headern(um_header_list* hl, const char* name, const char* value, size_t vallen);

struct body_chunk_s {
    char* chunk;
    size_t len;
    tlsuv_http_body_cb cb;

    tlsuv_http_req_t* req;

    struct body_chunk_s* next;
};

#endif //UV_MBED_HTTP_REQ_H