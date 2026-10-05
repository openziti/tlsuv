// Copyright (c) 2026 NetFoundry Inc.
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

// TLS echo server built on tlsuv_listener_t.
//
//   echo-server <key.pem> <cert.pem> [port]
//
// without a port the OS picks a free one, and the server prints it.
// try it with: openssl s_client -connect localhost:<port> -CAfile tests/certs/ca.pem

#include "common.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlsuv/listener.h>
#include <tlsuv/tls_engine.h>
#include <tlsuv/tlsuv.h>
#include <uv.h>

static void alloc_cb(uv_handle_t *h, size_t suggested, uv_buf_t *buf) {
    buf->base = malloc(suggested);
    buf->len = buf->base ? suggested : 0;
}

static void on_close(uv_handle_t *h) {
    printf("connection closed\n");
    tlsuv_stream_delete((tlsuv_stream_t *) h);
}

static void close_stream(tlsuv_stream_t *clt) {
    // a failed handshake leaves the stream open, so closing is the app's job;
    // closing a stream that is already closing is harmless
    tlsuv_stream_close(clt, on_close);
}

static void on_write(uv_write_t *req, int status) {
    if (status < 0) {
        fprintf(stderr, "write failed: %s\n", uv_strerror(status));
        close_stream((tlsuv_stream_t *) req->handle);
    }
    free(req->data);
    free(req);
}

static void on_data(uv_stream_t *h, ssize_t nread, const uv_buf_t *buf) {
    tlsuv_stream_t *clt = (tlsuv_stream_t *) h;
    if (nread > 0) {
        // hand the buffer over to the write; on_write frees it
        uv_write_t *req = malloc(sizeof(*req));
        uv_buf_t out = uv_buf_init(buf->base, (unsigned int) nread);
        req->data = buf->base;
        if (tlsuv_stream_write(req, clt, &out, on_write) != 0) {
            free(req);
            free(buf->base);
            close_stream(clt);
        }
        return;
    }
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "read error: %s\n", uv_strerror((int) nread));
        }
        close_stream(clt);
    }
    free(buf->base);
}

static tlsuv_stream_t *on_accept(tlsuv_listener_t *l, const struct sockaddr *peer, int status) {
    if (status != 0) {
        // UV_EMFILE/UV_ENFILE: out of descriptors; the listener already shed the waiting connections
        // and keeps listening. Any other error: it has stopped (start_listen would resume it).
        fprintf(stderr, "accept failed: %s\n", uv_strerror(status));
        return NULL;
    }

    char addr[64] = "?";
    int port = 0;
    if (peer->sa_family == AF_INET) {
        uv_ip4_name((const struct sockaddr_in *) peer, addr, sizeof(addr));
        port = ntohs(((const struct sockaddr_in *) peer)->sin_port);
    } else if (peer->sa_family == AF_INET6) {
        uv_ip6_name((const struct sockaddr_in6 *) peer, addr, sizeof(addr));
        port = ntohs(((const struct sockaddr_in6 *) peer)->sin6_port);
    }
    printf("connection from %s:%d\n", addr, port);

    // zeroed memory: the listener leaves the stream's `data` field as the app set it
    return tlsuv_stream_new();
}

static void on_handshake(tlsuv_stream_t *clt, int status) {
    if (status != 0) {
        fprintf(stderr, "handshake failed: %s\n", uv_strerror(status));
        close_stream(clt);
        return;
    }
    const char *alpn = tlsuv_stream_get_protocol(clt);
    printf("handshake complete%s%s\n", alpn ? ", ALPN " : "", alpn ? alpn : "");
    tlsuv_stream_read_start(clt, alloc_cb, on_data);
}

static void on_listener_closed(uv_handle_t *h) {
    uv_stop(h->loop);
}

static void on_signal(uv_signal_t *sig, int signum) {
    printf("shutting down\n");
    uv_signal_stop(sig);
    tlsuv_listener_close((tlsuv_listener_t *) sig->data, on_listener_closed);
}

static char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(size + 1);
    size_t n = fread(buf, 1, size, f);
    fclose(f);
    buf[n] = 0;
    *len = n;
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <key.pem> <cert.pem> [port]\n", argv[0]);
        return 1;
    }
    int port = argc > 3 ? atoi(argv[3]) : 0; // 0: let the OS choose

#if !_WIN32
    signal(SIGPIPE, SIG_IGN); // peers close connections; a write to a closed socket must not kill the server
#endif
    setvbuf(stdout, NULL, _IOLBF, 0); // so the port line shows up immediately when piped
    tlsuv_set_debug(3, logger);

    size_t key_len, cert_len;
    char *key_pem = read_file(argv[1], &key_len);
    char *cert_pem = read_file(argv[2], &cert_len);
    if (key_pem == NULL || cert_pem == NULL) {
        return 1;
    }

    tls_context *tls = default_tls_context();
    tlsuv_private_key_t key = NULL;
    tlsuv_certificate_t cert = NULL;
    if (tls->load_key(&key, key_pem, key_len) != 0 || tls->load_cert(&cert, cert_pem, cert_len) != 0 ||
        tls->set_own_cert(tls, key, cert) != 0) {
        fprintf(stderr, "failed to load key/certificate\n");
        return 1;
    }

    uv_loop_t *loop = uv_default_loop();
    tlsuv_listener_t *l = tlsuv_listener_new();
    int rc = tlsuv_listener_init(loop, l, tls);

    struct sockaddr_in addr;
    uv_ip4_addr("0.0.0.0", port, &addr);
    if (rc == 0) rc = tlsuv_listener_bind(l, (const struct sockaddr *) &addr, 0);
    if (rc == 0) rc = tlsuv_listener_start_listen(l, 128, on_accept, on_handshake);
    if (rc != 0) {
        fprintf(stderr, "cannot listen on port %d: %s\n", port, uv_strerror(rc));
        return 1;
    }

    // with port 0 the actual port is only known after bind
    struct sockaddr_storage bound;
    int bound_len = sizeof(bound);
    if (tlsuv_listener_getsockname(l, (struct sockaddr *) &bound, &bound_len) == 0) {
        port = ntohs(((struct sockaddr_in *) &bound)->sin_port);
    }
    printf("echo server listening on port %d\n", port);

    uv_signal_t sig;
    uv_signal_init(loop, &sig);
    sig.data = l;
    uv_signal_start(&sig, on_signal, SIGINT);

    uv_run(loop, UV_RUN_DEFAULT);

    tlsuv_listener_delete(l);
    cert->free(cert);
    key->free(key);
    tls->free_ctx(tls);
    free(key_pem);
    free(cert_pem);
    return 0;
}
