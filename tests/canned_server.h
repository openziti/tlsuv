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

// a local server that plays one canned exchange, for the replies the test server never sends

#ifndef TLSUV_TESTS_CANNED_SERVER_H
#define TLSUV_TESTS_CANNED_SERVER_H

#include <catch2/catch_all.hpp>

#include <string>
#include <uv.h>

#if _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

// a server that answers the first request it reads with `reply`, sends `trailer` a moment later,
// and closes the connection
struct canned_server {
    struct conn {
        canned_server *srv;
        uv_tcp_t tcp{};
        uv_timer_t timer{};
        uv_write_t wr{};
        char request[4096];
        int open_handles = 2;

        void send(const std::string &data, uv_write_cb cb) {
            uv_buf_t buf = uv_buf_init(const_cast<char *>(data.data()), (unsigned) data.size());
            if (uv_write(&wr, (uv_stream_t *) &tcp, &buf, 1, cb) != 0) finish();
        }

        void finish() {
            if (uv_is_closing((uv_handle_t *) &tcp)) return;
            srv->done = true;
            for (auto h: {(uv_handle_t *) &tcp, (uv_handle_t *) &timer}) {
                uv_close(h, [](uv_handle_t *h) {
                    auto c = (conn *) h->data;
                    if (--c->open_handles == 0) delete c;
                });
            }
        }
    };

    uv_tcp_t listener{};
    std::string reply;
    std::string trailer;
    bool done = false; // the connection has been closed by the server

    canned_server(uv_loop_t *loop, std::string reply, std::string trailer) :
            reply(std::move(reply)), trailer(std::move(trailer)) {
        sockaddr_in addr{};
        uv_ip4_addr("127.0.0.1", 0, &addr);
        uv_tcp_init(loop, &listener);
        listener.data = this;
        REQUIRE(uv_tcp_bind(&listener, (const sockaddr *) &addr, 0) == 0);
        REQUIRE(uv_listen((uv_stream_t *) &listener, 1, on_accept) == 0);
    }

    std::string url() {
        sockaddr_storage bound{};
        int len = sizeof(bound);
        uv_tcp_getsockname(&listener, (sockaddr *) &bound, &len);
        return "ws://127.0.0.1:" + std::to_string(ntohs(((sockaddr_in *) &bound)->sin_port)) + "/";
    }

    void close() {
        if (!uv_is_closing((uv_handle_t *) &listener)) uv_close((uv_handle_t *) &listener, nullptr);
    }

    static void on_accept(uv_stream_t *l, int status) {
        auto c = new conn{};
        c->srv = (canned_server *) l->data;
        uv_tcp_init(l->loop, &c->tcp);
        uv_timer_init(l->loop, &c->timer);
        c->tcp.data = c->timer.data = c;
        if (status != 0 || uv_accept(l, (uv_stream_t *) &c->tcp) != 0) {
            c->finish();
            return;
        }
        uv_read_start((uv_stream_t *) &c->tcp,
                      [](uv_handle_t *h, size_t, uv_buf_t *buf) {
                          auto c = (conn *) h->data;
                          *buf = uv_buf_init(c->request, sizeof(c->request));
                      },
                      [](uv_stream_t *s, ssize_t nread, const uv_buf_t *) {
                          auto c = (conn *) s->data;
                          if (nread <= 0) {
                              if (nread < 0) c->finish();
                              return;
                          }
                          uv_read_stop(s);
                          c->send(c->srv->reply, [](uv_write_t *w, int) {
                              auto c = (conn *) w->handle->data;
                              if (c->srv->trailer.empty()) {
                                  c->finish();
                                  return;
                              }
                              uv_timer_start(&c->timer, [](uv_timer_t *t) {
                                  auto c = (conn *) t->data;
                                  c->send(c->srv->trailer, [](uv_write_t *w, int) {
                                      ((conn *) w->handle->data)->finish();
                                  });
                              }, 50, 0);
                          });
                      });
    }
};

#endif // TLSUV_TESTS_CANNED_SERVER_H
