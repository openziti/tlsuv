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

#include "../src/um_debug.h"
#include <tlsuv/tlsuv.h>
#include <tlsuv/websocket.h>


static void alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void ws_read_cb(uv_stream_t *h, ssize_t status, const uv_buf_t *buf) {
    tlsuv_websocket_t *ws = (tlsuv_websocket_t *) h;
    if (status < 0) {
        fprintf(stderr, "read status = %zd\n", status);
        exit((int)status);
    }

    printf("< %.*s\n", (int)status, buf->base);
}

static void connect_cb(uv_connect_t *req, int status) {
    tlsuv_websocket_t *ws = (tlsuv_websocket_t *) req->handle;
    if (status == 0) {
        printf("websocket connected\n");
    } else {
        fprintf(stderr, "failed to connect: %d\n", status);
        exit(1);
    }
}

static void ws_write_cb(uv_write_t *req, int status) {
    free(req->data);
    free(req);
}

static void in_read_cb(uv_stream_t *h, ssize_t nread, const uv_buf_t *buf) {
    tlsuv_websocket_t *ws = h->data;
    if (nread < 0) {
        if (nread != UV_EOF)
            UM_LOG(ERR, "unexpected input error: %zd(%s)", nread, uv_strerror(nread));
        tlsuv_websocket_close(ws, NULL);
    } else {
        uv_write_t *wr = malloc(sizeof(uv_write_t));
        wr->data = buf->base;
        uv_buf_t b;
        b.base = buf->base;
        b.len = nread;
        tlsuv_websocket_write(wr, ws, &b, ws_write_cb);
    }
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <websocket address>", argv[0]);
    }

    uv_loop_t *l = uv_default_loop();
//    uv_mbed_set_debug(TRACE, stdout);

    tlsuv_websocket_t ws;
    tlsuv_websocket_init(l, &ws);

    uv_pipe_t in;
    uv_pipe_init(l, &in, 0);
    uv_pipe_open(&in, 0);
    in.data = &ws;
    uv_read_start((uv_stream_t *) &in, alloc_cb, in_read_cb);

    uv_connect_t req;
    tlsuv_websocket_connect(&req, &ws, argv[1], connect_cb, ws_read_cb);

    uv_run(l, UV_RUN_DEFAULT);

    UM_LOG(INFO, "loop is done");
}
