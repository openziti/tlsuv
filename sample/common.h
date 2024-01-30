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


#ifndef UV_MBED_COMMON_H
#define UV_MBED_COMMON_H

#include <tlsuv/http.h>

void resp_cb(tlsuv_http_resp_t *resp, void *data);
void body_cb(tlsuv_http_req_t *req, char *body, ssize_t len);
void logger(int level, const char *file, unsigned int line, const char *msg);
#endif //UV_MBED_COMMON_H
