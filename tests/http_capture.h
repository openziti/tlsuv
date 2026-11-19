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

// HTTP response capture shared by the HTTP test files (defined in http_tests.cpp)

#ifndef TLSUV_TESTS_HTTP_CAPTURE_H
#define TLSUV_TESTS_HTTP_CAPTURE_H

#include <cctype>
#include <map>
#include <string>
#include <tlsuv/http.h>

using std::map;
using std::string;

class resp_capture {
public:
    tlsuv_http_body_cb body_cb;

    explicit resp_capture(tlsuv_http_body_cb cb) : body_cb(cb), status("not set"), code(-666) {}

    resp_capture() : resp_capture(nullptr) {}

    string http_version;
    ssize_t code;
    string status;
    map<string, string> headers;

    string body;
    string req_body;

    int resp_body_end_called{};
    int req_body_cb_called{};

    uv_timeval64_t resp_start{};
    uv_timeval64_t resp_endtime{};
};

// value of a header in a header list (the name is matched ignoring case), "" if there is none
inline std::string header_value(um_header_list *hl, const std::string &name) {
    auto lower = [](std::string s) {
        for (auto &c: s) c = (char) std::tolower((unsigned char) c);
        return s;
    };
    tlsuv_http_hdr *h;
    LIST_FOREACH(h, hl, _next) {
        if (lower(h->name) == lower(name)) return h->value;
    }
    return {};
}

std::string testServerURL(const string& type);
void req_body_cb(tlsuv_http_req_t *req, char *chunk, ssize_t status);
void resp_body_cb(tlsuv_http_req_t *req, char *chunk, ssize_t len);
void resp_capture_cb(tlsuv_http_resp_t *resp, void *data);

#endif //TLSUV_TESTS_HTTP_CAPTURE_H
