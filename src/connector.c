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

#include <tlsuv/connector.h>
#include <stdlib.h>
#include <stdbool.h>

#include "util.h"
#include "um_debug.h"
#include "tlsuv/tlsuv.h"


#if _WIN32
#include "win32_compat.h"
#include <winsock2.h>
#define ioctl ioctlsocket
#define get_error() WSAGetLastError()
#define write(s,b,z) send(s, b, z, 0)
#define read(s,b,z) recv(s,b,z,0)
#define SHUT_RDWR SD_BOTH
#else
#define get_error() errno
#define closesocket(s) close(s)
#include <unistd.h>
#include <string.h>

#endif


struct conn_req_s {
    uv_getaddrinfo_t resolve;
    uv_poll_t poll;

    void *ctx;
    tlsuv_connect_cb cb;

    uv_os_sock_t sock;
    int error;
    int cancel;
};

static tlsuv_connector_req default_connect(uv_loop_t *l, const tlsuv_connector_t *self,
                                           const char *host, const char *port, tlsuv_connect_cb cb, void *ctx);
static void default_cancel(tlsuv_connector_req req);
static tlsuv_connector_req proxy_connect(uv_loop_t *l, const tlsuv_connector_t *self,
                                         const char *host, const char *port, tlsuv_connect_cb cb, void *ctx);
static void proxy_cancel(tlsuv_connector_req req);

// prevent freeing default connector
static void default_connector_free(void *self){
    (void)self;
}

static int default_set_auth(tlsuv_connector_t *self, tlsuv_auth_t auth, const char *username, const char *password) {
    return UV_ENOTSUP;
}

static tlsuv_connector_t default_connector = {
        .connect = default_connect,
        .set_auth = default_set_auth,
        .cancel = default_cancel,
        .free = default_connector_free,
};
static const tlsuv_connector_t *global_connector = &default_connector;

struct tlsuv_proxy_connector_s {
    tlsuv_connect connect;
    int (*set_auth)();
    void (*cancel)(tlsuv_connector_req);
    void (*free)(tlsuv_connector_t *self);
    
    tlsuv_proxy_t type;
    char *host;
    char *port;
    const char *auth_header;
    char *auth_value;
};

void tlsuv_set_global_connector(const tlsuv_connector_t *c) {
    global_connector = c ? c : &default_connector;
}

const tlsuv_connector_t* tlsuv_global_connector() {
    return global_connector;
}

static void on_close(uv_handle_t *h) {
    struct conn_req_s *req = h->data;
    free(req);
}

static void on_poll_close(uv_handle_t *h) {
    struct conn_req_s *cr = container_of(h, struct conn_req_s, poll);
    free(cr);
}

static void on_poll_connect(uv_poll_t *p, int status, int events) {
    struct conn_req_s *r = container_of(p, struct conn_req_s, poll);
    uv_poll_stop(p);

    int e;
    socklen_t len = sizeof(e);
    getsockopt(r->sock, SOL_SOCKET, SO_ERROR, &e, &len);

#if _WIN32
    switch (e) {
            case WSAECONNREFUSED: r->error = UV_ECONNREFUSED; break;
            case WSAECONNRESET: r->error = UV_ECONNRESET; break;
            case WSAECONNABORTED: r->error = UV_ECONNABORTED; break;
            default:
                r->error = -e;
        }
#else
    r->error = -e;
#endif

    if (r->cancel) {
        r->error = UV_ECANCELED;
    }

    if (r->error) {
        closesocket(r->sock);
        r->sock = (uv_os_sock_t)-1;
    }
    r->cb(r->sock, r->error, r->ctx);

    uv_close((uv_handle_t *) p, on_poll_close);
}

static void on_resolve(uv_getaddrinfo_t *r, int status, struct addrinfo *addr) {
    struct conn_req_s *cr = container_of(r, struct conn_req_s, resolve);

    if (status != 0) {
        cr->cb(cr->sock, status, cr->ctx);
        free(r);
    } else {
        cr->sock = tlsuv_socket(addr, 0);
        int rc = connect(cr->sock, addr->ai_addr, addr->ai_addrlen);
        int e = get_error();

        if (rc == 0 ||
#if _WIN32
            e == WSAEWOULDBLOCK
#else
            e == EINPROGRESS
#endif
                ) {
            uv_poll_init_socket(r->loop, &cr->poll, cr->sock);
            uv_poll_start(&cr->poll, UV_WRITABLE|UV_DISCONNECT, on_poll_connect);
        } else {
            cr->cb(cr->sock, e, cr->ctx);
            free(r);
        }
    }

    uv_freeaddrinfo(addr);
}

tlsuv_connector_req default_connect(uv_loop_t *loop, const tlsuv_connector_t *self,
                                    const char *host, const char *port,
                                    tlsuv_connect_cb cb, void *ctx) {
    struct conn_req_s *r = calloc(1, sizeof(*r));
    r->ctx = ctx;
    r->cb = cb;
    r->sock = (uv_os_sock_t)-1;

    struct addrinfo hints = {
            .ai_socktype = SOCK_STREAM,
    };

    uv_getaddrinfo(loop, &r->resolve, on_resolve, host, port, &hints);

    return r;
}

void default_cancel(tlsuv_connector_req req) {
    UM_LOG(VERB, "cancelling");
    struct conn_req_s *r = (struct conn_req_s *) req;

    r->cancel = true;
    if (uv_cancel((uv_req_t *) &r->resolve) != 0) {
        shutdown(r->sock, SHUT_RDWR);
#if _WIN32
        // on windows shutting down/closing socket does not trigger poll event
        uv_poll_stop(&r->poll);
        closesocket(r->sock);
        r->cb((uv_os_sock_t)-1, UV_ECANCELED, r->ctx);
        uv_close((uv_handle_t *) &r->poll, on_poll_close);
#endif
    }
}

struct proxy_connect_req {
    uv_work_t work;
    const struct tlsuv_proxy_connector_s *proxy;
    void *data;
    char *host;
    char *port;
    tlsuv_connect_cb cb;
    uv_os_sock_t sock;
    tlsuv_connector_req conn_req;
    int err;
    
};

static void proxy_work(uv_work_t *wr) {
    struct proxy_connect_req *r = container_of(wr, struct proxy_connect_req, work);

    const struct tlsuv_proxy_connector_s *proxy = r->proxy;

    tlsuv_socket_set_blocking(r->sock, true);

    char req[1024];
    size_t reqlen = snprintf(req, sizeof(req),
                             "CONNECT %s:%s HTTP/1.1\r\n"
                             "Host: %s:%s\r\n"
                             "Proxy-Connection: keep-alive\r\n"
                             "%s%s%s%s"
                             "\r\n",
                             r->host, r->port, r->host, r->port,
                             proxy->auth_header ? proxy->auth_header : "",
                             proxy->auth_header ? ": " : "",
                             proxy->auth_header ? proxy->auth_value : "",
                             proxy->auth_header ? "\r\n" : ""
    );
    ssize_t res = write(r->sock, req, reqlen);
    if (res < 0) {
        r->err = (int)get_error();
        closesocket(r->sock);
        r->sock = -1;
        return;
    }

    res = read(r->sock, req, sizeof(req)-1);
    if (res < 0) {
        r->err = (int)get_error();
        closesocket(r->sock);
        r->sock = -1;
        return;
    }
    req[res] = 0;

    int code = 0;
    res = sscanf(req, "HTTP/1.%*c %d ", &code);
    if (res != 1 || code != 200) {
        r->err = UV_ECONNREFUSED;
        closesocket(r->sock);
        r->sock = -1;
    }
}

static void proxy_work_cb(uv_work_t *wr, int status) {
    struct proxy_connect_req *r = container_of(wr, struct proxy_connect_req, work);
    if (status != 0) {
        closesocket(r->sock);
        r->sock = -1;
        r->err = status;
    }

    r->cb(r->sock, r->err, r->data);
    free(r->host);
    free(r->port);
    free(r);
}

static void on_proxy_connect(uv_os_sock_t fd, int status, void *req) {
    struct proxy_connect_req *r = req;
    if (status != 0) {
        r->cb(-1, status, r->data);
        free(r->port);
        free(r->host);
        free(r);
    } else {
        r->sock = fd;
        uv_queue_work(r->work.loop, &r->work, proxy_work, proxy_work_cb);
    }
}

tlsuv_connector_req proxy_connect(uv_loop_t *loop, const tlsuv_connector_t *self,
                                  const char *host, const char *port, tlsuv_connect_cb cb, void *ctx) {
    const struct tlsuv_proxy_connector_s *proxy = (const struct tlsuv_proxy_connector_s *) self;
    struct proxy_connect_req *r = calloc(1, sizeof(*r));
    r->proxy = proxy;
    r->data = ctx;
    r->cb = cb;
    r->host = strdup(host);
    r->port = strdup(port);
    r->work.loop = loop;
    r->conn_req = default_connect(loop, &default_connector, proxy->host, proxy->port, on_proxy_connect, r);
    return r;
}

int proxy_set_auth(tlsuv_connector_t *self, tlsuv_auth_t auth, const char *username, const char *password) {
    struct tlsuv_proxy_connector_s *c = (struct tlsuv_proxy_connector_s *) self;
    if (auth == tlsuv_PROXY_NONE) {
        c->auth_header = NULL;
        free(c->auth_value);
        c->auth_value = NULL;
        return 0;
    } else if (auth == tlsuv_PROXY_BASIC) {
        if (!username || !password)
            return UV_EINVAL;
        c->auth_header = "Proxy-Authorization";
        free(c->auth_value);

        char authstr[256];
        size_t auth_len = snprintf(authstr, sizeof(authstr), "%s:%s", username, password);

        c->auth_value = malloc(512);
        size_t offset = snprintf(c->auth_value, 512, "Basic ");
        char *b64 = c->auth_value + offset;
        size_t b64max = 512 - offset;
        return tlsuv_base64_encode((uint8_t *)authstr, auth_len, &b64, &b64max);
    } else {
        return UV_EINVAL;
    }
}

void proxy_cancel(tlsuv_connector_req req) {
    struct proxy_connect_req *r = (struct proxy_connect_req*)req;
    if (r->conn_req) {
        default_cancel(r->conn_req);
    } else {
        uv_cancel((uv_req_t *) &r->work);
    }
}

void proxy_free(tlsuv_connector_t *self) {
    struct tlsuv_proxy_connector_s *c = (struct tlsuv_proxy_connector_s *) self;
    free(c->host);
    free(c->port);
    free(c->auth_value);
    free(c);
}

tlsuv_connector_t *tlsuv_new_proxy_connector(tlsuv_proxy_t type, const char* host, const char * port) {
    struct tlsuv_proxy_connector_s *c = calloc(1, sizeof(*c));
    c->type = type;
    c->host = strdup(host);
    c->port = strdup(port);
    c->connect = proxy_connect;
    c->cancel = proxy_cancel;
    c->set_auth = proxy_set_auth;
    c->free = proxy_free;
    return (tlsuv_connector_t *)c;
}


