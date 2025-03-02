// Copyright (c) 2024. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "tlsuv/websocket.h"

#include "alloc.h"
#include "http_req.h"
#include "portable_endian.h"
#include "um_debug.h"
#include "win32_compat.h"

#include <string.h>
#include <tlsuv/http.h>
static const char *DEFAULT_PATH = "/";

#define WS_FIN 0x80U
#define WS_OP_BITS 0xFU
#define WS_MASK 0x80U

enum OpCode {
    OpCode_TXT = 0x1U,
    OpCode_BIN = 0x2U,
    OpCode_Close = 0x8U,
    OpCode_Ping = 0x9U,
    OpCode_Pong = 0xAU
};

typedef struct ws_write_s {
    uv_write_t *wr;
    uv_write_cb cb;
    uv_buf_t *bufs;
    int nbufs;

} ws_write_t;

extern tls_context *get_default_tls(void);

static void src_connect_cb(tlsuv_src_t *sl, int status, void *connect_ctx);
static void ws_read_cb(uv_link_t* link,
                                ssize_t nread,
                                const uv_buf_t* buf);
static void ws_write_cb(uv_link_t *l, int nwrote, void *data);
static void send_pong(tlsuv_websocket_t *ws, const char* ping_data, int len);
static void tls_hs_cb(tls_link_t *tls, int status);

static int ws_read_start(uv_link_t *l);

static const uv_link_methods_t ws_methods = {
        .close = uv_link_default_close,
        .read_start = ws_read_start,
        .write = uv_link_default_write,
        .alloc_cb_override = uv_link_default_alloc_cb_override,
        .read_cb_override = ws_read_cb
};


int tlsuv_websocket_init_with_src(uv_loop_t *loop, tlsuv_websocket_t *ws, tlsuv_src_t *src) {
    ws->loop = loop;
    ws->type = UV_IDLE;
    ws->src = src;
    ws->req = tlsuv__calloc(1, sizeof(tlsuv_http_req_t));

    char randbuf[24];
    uv_random(NULL, NULL, randbuf, sizeof(randbuf), 0, NULL);
    char key[25];
    for (int i = 0; i < 22; i++) {
        int v = randbuf[i] & 0x3f;
        if (v < 26) {
            key[i] = (char)('A' + v);
        } else if (v < 52) {
            key[i] = (char)('a' + v - 26);
        } else if (v < 62) {
            key[i] = (char)('a' + v - 52);
        } else if (v == 62){
            key[i] = '+';
        } else {
            key[i] = '/';
        }
    }
    key[22] = '=';
    key[23] = '=';
    key[24] = 0;
    set_http_header(&ws->req->req_headers, "Upgrade", "websocket");
    set_http_header(&ws->req->req_headers, "Connection", "Upgrade");
    set_http_header(&ws->req->req_headers, "Sec-WebSocket-Key", key);
    set_http_header(&ws->req->req_headers, "Sec-WebSocket-Version", "13");

    return 0;
}

int tlsuv_websocket_init(uv_loop_t *loop, tlsuv_websocket_t *ws) {
    memset(ws, 0, sizeof(tlsuv_websocket_t));
    tcp_src_init(loop, &ws->default_src);
    return tlsuv_websocket_init_with_src(loop, ws, (tlsuv_src_t *) &ws->default_src);
}

void tlsuv_websocket_set_header(tlsuv_websocket_t *ws, const char *name, const char *value) {
    set_http_header(&ws->req->req_headers, name, value);
}

int tlsuv_websocket_connect(uv_connect_t *req, tlsuv_websocket_t *ws, const char *url, uv_connect_cb conn_cb, uv_read_cb data_cb) {

    struct tlsuv_url_s u;
    if (tlsuv_parse_url(&u, url) != 0) {
        UM_LOG(ERR, "invalid websocket URL: %s", url);
        return UV_EINVAL;
    }

    bool ssl = false;
    int port;
    char *host;

    if (u.scheme != NULL) {
        if (strncasecmp("ws", u.scheme, u.scheme_len) == 0) {
            port = 80;
        }
        else if (strncasecmp("wss", u.scheme, u.scheme_len) == 0) {
            port = 443;
            ssl = true;
        }
        else {
            UM_LOG(ERR, "scheme(%.*s) is not supported", (int)u.scheme_len, u.scheme);
            return UV_EINVAL;
        }
    }
    else {
        UM_LOG(ERR, "invalid URL: no scheme");
        return UV_EINVAL;
    }

    if (ssl && ws->tls == NULL) {
        tlsuv_websocket_set_tls(ws, get_default_tls());
    }

    if (u.hostname != NULL) {
        host = tlsuv__strndup(u.hostname, u.hostname_len);
    }
    else {
        UM_LOG(ERR, "invalid URL: no host");
        return UV_EINVAL;
    }

    if (u.port != 0) {
        port = u.port;
    }

    char portstr[6];
    snprintf(portstr, sizeof(portstr), "%d", port);

    req->handle = (uv_stream_t *) ws;
    req->cb = conn_cb;

    if (ws->tls != NULL) {
        tlsuv_tls_link_init(&ws->tls_link, ws->tls->new_engine(ws->tls, host), tls_hs_cb);
    }

    const char *path = DEFAULT_PATH;
    if (u.path != NULL) {
        path = tlsuv__strndup(u.path, u.path_len);
    }

    http_req_init(ws->req, "GET", path);
    if (path != DEFAULT_PATH) {
        tlsuv__free((char*)path);
    }
    set_http_header(&ws->req->req_headers, "host", host);

    ws->host = host;
    ws->read_cb = data_cb;
    UM_LOG(DEBG, "connecting to '%s:%d'", host, port);
    return ws->src->connect(ws->src, host, portstr, src_connect_cb, req);
}

int tlsuv_websocket_write(uv_write_t *req, tlsuv_websocket_t *ws, uv_buf_t *buf, uv_write_cb cb) {
    if (ws->closed) {
        cb(req, UV_ECONNRESET);
        return UV_ECONNRESET;
    }

    uv_buf_t bufs;
    int headerlen = 6;
    if (buf->len > 125) {
        headerlen += 2;
    }
    if (buf->len > 0xffff) {
        headerlen += 6;
    }
    uint8_t mask[4];
    uv_random(NULL, NULL, mask, sizeof(mask), 0, NULL);
    char *frame = tlsuv__malloc(headerlen + buf->len);

    frame[0] = WS_FIN | OpCode_BIN;
    char *ptr = frame + 1;
    if (buf->len < 126) {
        *ptr++ = WS_MASK | (uint8_t)buf->len;
    } else if (buf->len <= 0xffff) {
        uint16_t v = htobe16(buf->len);
        *ptr++ = WS_MASK | 126U;
        memcpy(frame + 2, &v, sizeof(v));
        ptr += sizeof(v);
    } else {
        uint64_t v = htobe64(buf->len);
        *ptr++ = WS_MASK | 127U;
        memcpy(frame + 2, &v, sizeof(v));
        ptr += sizeof(v);
    }
    memcpy(ptr, mask, sizeof(mask));
    ptr += sizeof(mask);

    for (size_t i = 0; i < buf->len; i++) {
        *((char*)ptr + i) = (char)(mask[i % 4] ^ buf->base[i]);
    }

    bufs.len = headerlen + buf->len;
    bufs.base = frame;

    ws_write_t *ws_wreq = tlsuv__calloc(1, sizeof(ws_write_t));
    ws_wreq->wr = req;
    ws_wreq->bufs = tlsuv__malloc(sizeof(uv_buf_t));
    ws_wreq->bufs[0] = bufs;
    ws_wreq->nbufs = 1;
    ws_wreq->cb = cb;

    return uv_link_write(&ws->ws_link, &bufs, 1, NULL, ws_write_cb, ws_wreq);
}


static void src_connect_cb(tlsuv_src_t *sl, int status, void *connect_ctx) {
    UM_LOG(DEBG, "connect rc = %d", status);
    uv_connect_t *req = connect_ctx;
    tlsuv_websocket_t *ws = (tlsuv_websocket_t *) req->handle;

    if (status < 0) {
        ws->closed = true;
        req->cb(req, status);
        return;
    }

    ws->conn_req = req;
    uv_link_init(&ws->ws_link, &ws_methods);
    ws->ws_link.data = ws;

    if (ws->tls != NULL) {
        ws->tls_link.data = ws;
        uv_link_chain(sl->link, (uv_link_t *) &ws->tls_link);
        uv_link_chain((uv_link_t *) &ws->tls_link, &ws->ws_link);
        uv_link_read_start((uv_link_t *) &ws->tls_link);
    } else {
        uv_link_chain(sl->link, &ws->ws_link);
        uv_link_read_start(&ws->ws_link);
    }
}

static void ws_write_cb(uv_link_t *l, int nwrote, void *data) {
    ws_write_t *ws_wreq = data;
    UM_LOG(VERB, "write complete rc = %d", nwrote);

    if (nwrote < 0) {
        tlsuv_websocket_t *ws = l->data;
        ws->closed = true;
    }

    if (ws_wreq->wr) {
        uv_write_t *wr = ws_wreq->wr;
        ws_wreq->cb(wr, nwrote);
    }
    for (int i=0; i < ws_wreq->nbufs; i++) {
        tlsuv__free(ws_wreq->bufs[i].base);
    }
    tlsuv__free(ws_wreq->bufs);
    tlsuv__free(ws_wreq);
}

int ws_read_start(uv_link_t *l) {
    UM_LOG(VERB, "starting ws");
    uv_link_default_read_start(l);

    tlsuv_websocket_t *ws = l->data;
    uv_buf_t buf;
    buf.base = tlsuv__malloc(8196);
    buf.len = http_req_write(ws->req, buf.base, 8196);

    UM_LOG(VERB, "starting WebSocket handshake(sending %zd bytes)[%.*s]", (size_t)buf.len, (int)buf.len, buf.base);

    ws_write_t *ws_wreq = tlsuv__calloc(1, sizeof(ws_write_t));
    ws_wreq->bufs = tlsuv__malloc(sizeof(uv_buf_t));
    ws_wreq->bufs[0] = buf;
    ws_wreq->nbufs = 1;

    return uv_link_propagate_write(l->parent, l, &buf, 1, NULL, ws_write_cb, ws_wreq);
}

void ws_read_cb(uv_link_t *l, ssize_t nread, const uv_buf_t *buf) {
    tlsuv_websocket_t *ws = l->data;
    if (nread < 0) {
        ws->closed = true;
        // still connecting
        if (ws->conn_req != NULL) {
            ws->conn_req->cb(ws->conn_req, (int)nread);
            ws->conn_req = NULL;
        } else {
            ws->read_cb((uv_stream_t *) ws, nread, buf);
        }
        return;
    }

    ssize_t processed = 0;
    bool failed = false;
    if (ws->conn_req != NULL) {
        processed = http_req_process(ws->req, buf->base, nread);
        if (processed < 0) {
            UM_LOG(ERR, "failed to parse connect/upgrade response");
            ws->conn_req->cb(ws->conn_req, -1);
            http_req_free(ws->req);
            tlsuv__free(ws->req);
            ws->req = NULL;
            failed = true;
        } else {
            UM_LOG(VERB, "processed %zd out of %zd", processed, nread);
            if (ws->req->state == completed) {
                if (ws->req->resp.code == 101) {
                    UM_LOG(VERB, "websocket connected");
                    ws->conn_req->cb(ws->conn_req, 0);
                } else {
                    UM_LOG(ERR, "failed to connect to websocket: %s(%d)", ws->req->resp.status, ws->req->resp.code);
                    ws->conn_req->cb(ws->conn_req, -1);
                    failed = true;
                }
                ws->conn_req = NULL;
                http_req_free(ws->req);
                tlsuv__free(ws->req);
                ws->req = NULL;
            }
        }
    }

    if (failed || processed == nread) {
        tlsuv__free(buf->base);
        return;
    }

    char *frame = buf->base + processed;
    char op = (char)(frame[0] & WS_OP_BITS);
    bool masked = (frame[1] & WS_MASK) != 0;
    size_t len = frame[1] & (~WS_MASK);
    char *dp = frame + 2;
    if (len == 126) {
        len = be16toh(*(uint16_t *)(&frame[2]));
        dp += 2;
    } else if (len == 127) {
        len = be64toh(*(uint64_t*)&frame[2]);
        dp += 8;
    }

    uint8_t mask[4];
    if (masked) {
        memcpy(mask, dp, sizeof(mask));
        dp += sizeof(mask);
    } else {
        memset(mask, 0, sizeof(mask));
    }

    switch (op) {
        case OpCode_TXT:
        case OpCode_BIN:
            UM_LOG(TRACE, "got data %zd masked=%d", len, masked);
            for (size_t i=0; i<len; i++) {
                buf->base[i] = (char)(*dp ^ mask[i % 4]);
                dp++;
            }
            ws->read_cb((uv_stream_t *) ws, (ssize_t)len, buf);
            break;
        case OpCode_Close:
            UM_LOG(TRACE, "got close");
            ws->read_cb((uv_stream_t *) ws, UV_EOF, buf);
            break;
        case OpCode_Ping:
            UM_LOG(TRACE, "got ping masked=%d len=%zd", masked, len);
            send_pong(ws, dp, (int)len);
            break;
        case OpCode_Pong:
            UM_LOG(TRACE, "got pong");
            break;
        default:
            UM_LOG(INFO, "got unsupported frame %hd", op);
    }

    tlsuv__free(buf->base);
}

static void send_pong(tlsuv_websocket_t *ws, const char* ping_data, int len) {
    UM_LOG(TRACE, "send_pong len=%d", len);
    uint8_t mask[4];
    uv_buf_t buf;
    buf.len = 2 + sizeof(mask) + len;
    buf.base = tlsuv__malloc(buf.len);

    buf.base[0] = WS_FIN | OpCode_Pong;
    buf.base[1] = (char)(WS_MASK | (0x7f & len));

    char *ptr = buf.base + 2;
    uv_random(NULL, NULL, mask, sizeof(mask), 0, NULL);
    memcpy(ptr, mask, sizeof(mask));
    ptr += sizeof(mask);

    if (ping_data != NULL && len > 0) {
        for (size_t i = 0; i < buf.len; i++) {
            *((char*)ptr + i) = (char)(mask[i % 4] ^ *(ping_data + i));
        }
    }

    ws_write_t *ws_wreq = tlsuv__calloc(1, sizeof(ws_write_t));
    ws_wreq->bufs = tlsuv__malloc(sizeof(uv_buf_t));
    ws_wreq->bufs[0] = buf;
    ws_wreq->nbufs = 1;

    uv_link_write(&ws->ws_link, &buf, 1, NULL, ws_write_cb, ws_wreq);
}

static void on_ws_close(tlsuv_websocket_t *ws) {
    if (ws == NULL) return;

    if (ws->req) {
        http_req_free(ws->req);
        tlsuv__free(ws->req);
        ws->req = NULL;
    }
    if (ws->host) {
        tlsuv__free(ws->host);
        ws->host = NULL;
    }
    if (ws->tls && ws->tls_link.engine) {
        ws->tls_link.engine->free(ws->tls_link.engine);
        ws->tls_link.engine = NULL;
        tlsuv_tls_link_free(&ws->tls_link);
    }

    if (ws->src) {
        ws->src->cancel(ws->src);
        tcp_src_free((tcp_src_t *) ws->src);
        ws->src = NULL;
    }

    if (ws->close_cb) {
        ws->close_cb((uv_handle_t *) ws);
    }
}

static void ws_close_cb(uv_link_t *l) {
    tlsuv_websocket_t *ws = l->data;
    l->data = NULL;

    on_ws_close(ws);
}

int tlsuv_websocket_close(tlsuv_websocket_t *ws, uv_close_cb cb) {
    ws->close_cb = cb;
    if (ws->ws_link.data != NULL) {
        uv_link_close(&ws->ws_link, ws_close_cb);
    } else {
        on_ws_close(ws);
    }
    return 0;
}

void tlsuv_websocket_set_tls(tlsuv_websocket_t *ws, tls_context *ctx) {
    ws->tls = ctx;
}

static void tls_hs_cb(tls_link_t *tls, int status) {
    tlsuv_websocket_t *ws = tls->data;
    UM_LOG(DEBG, "tls HS complete %d", status);
    if (status == TLS_HS_COMPLETE) {
        uv_link_read_start(&ws->ws_link);
    } else {
        ws->conn_req->cb(ws->conn_req, UV_ECONNABORTED);
    }
}
