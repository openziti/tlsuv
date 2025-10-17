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
#include <tlsuv/http.h>

#if _WIN32
#include "win32_compat.h"
#include <winsock2.h>
#define ioctl ioctlsocket
#define get_error() WSAGetLastError()
#define write(s,b,z) send(s, b, z, 0)
#define read(s,b,z) recv(s,b,z,0)
#define SHUT_RDWR SD_BOTH
#define in_progress(e) (e == WSAEWOULDBLOCK)

#define poll(fds,n,to) WSAPoll(fds, n, to)

#else
#define INVALID_SOCKET (-1)
#define get_error() errno
#define closesocket(s) close(s)
#define in_progress(e) ((e) == EINPROGRESS || (e) == EWOULDBLOCK)

#include <unistd.h>
#include <string.h>
#include <sys/poll.h>

#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#define max_connect_socks 16

struct conn_req_s {
    uv_getaddrinfo_t resolve;
    void *ctx;
    tlsuv_connect_cb cb;

    uv_poll_t polls[max_connect_socks];
    int count;

    int error;
};

static tlsuv_connector_req direct_connect(uv_loop_t *loop, const tlsuv_connector_t *self,
                                          const char *host, const char *port, tlsuv_connect_cb cb, void *ctx);
static void direct_cancel(tlsuv_connector_req req);
static tlsuv_connector_req proxy_connect(uv_loop_t *l, const tlsuv_connector_t *self,
                                         const char *host, const char *port, tlsuv_connect_cb cb, void *ctx);
static void proxy_cancel(tlsuv_connector_req req);

// prevent freeing default connector
static void direct_connector_free(void *self){
    (void)self;
}

static int direct_set_auth(tlsuv_connector_t *self, tlsuv_auth_t auth, const char *username, const char *password) {
    return UV_ENOTSUP;
}

static tlsuv_connector_t direct_connector = {
        .connect = direct_connect,
        .set_auth = direct_set_auth,
        .cancel = direct_cancel,
        .free = direct_connector_free,
};

static const tlsuv_connector_t *global_connector;

struct tlsuv_proxy_connector_s {
    tlsuv_connect connect;
    int (*set_auth)(tlsuv_connector_t *self, tlsuv_auth_t auth, const char *username, const char *password);
    void (*cancel)(tlsuv_connector_req);
    void (*free)(tlsuv_connector_t *self);
    
    tlsuv_proxy_t type;
    char *host;
    char *port;
    const char *auth_header;
    char *auth_value;
};
static void init_proxy_connector(struct tlsuv_proxy_connector_s *c, tlsuv_proxy_t type, const char *host, const char *port);

static struct tlsuv_proxy_connector_s http_proxy_connector;

void tlsuv_set_global_connector(const tlsuv_connector_t *c) {
    global_connector = c ? c : &direct_connector;
}

static void init_global_connector() {
    // connector was already set
    if (global_connector != NULL) return;

    global_connector = &direct_connector;

    char proxy[1024] = {};
    size_t proxy_len = sizeof(proxy);
    if (uv_os_getenv("HTTP_PROXY", proxy, &proxy_len) == 0 ||
        uv_os_getenv("http_proxy", proxy, &proxy_len) == 0) {
        UM_LOG(INFO, "using HTTP proxy: %s", proxy);
        struct tlsuv_url_s u;
        if (tlsuv_parse_url(&u, proxy) != 0 || u.hostname == NULL) {
            UM_LOG(ERR, "invalid HTTP_PROXY URL[%s]", proxy);
            return;
        }
        *(char*)(u.hostname + u.hostname_len) = '\0'; // ensure null-termination

        if (u.port == 0) { u.port = 80; } // default port for HTTP
        char port[6] = {};
        snprintf(port, sizeof(port), "%d", u.port);
        init_proxy_connector(&http_proxy_connector, tlsuv_PROXY_HTTP, u.hostname, port);

        if (u.username && u.password) {
            *(char*)(u.username + u.username_len) = '\0'; // ensure null-termination
            *(char*)(u.password + u.password_len) = '\0'; // ensure null-termination
            http_proxy_connector.set_auth((tlsuv_connector_t *)&http_proxy_connector, tlsuv_PROXY_BASIC, u.username, u.password);
        }
        global_connector = (const tlsuv_connector_t *) &http_proxy_connector;
    }
}

const tlsuv_connector_t* tlsuv_global_connector() {
    static uv_once_t once_init = UV_ONCE_INIT;
    uv_once(&once_init, init_global_connector);
    return global_connector;
}

static void free_conn_req(struct conn_req_s *cr) {
    tlsuv__free(cr);
}

static const char *get_name(const struct sockaddr *addr) {
    static char name[128];
    if (addr && uv_ip_name(addr, name, sizeof(name)) == 0) { return name; }

    return "<unknown>";
}

static int err_to_uv(int err) {
#if _WIN32
    switch(err) {
        case ECONNREFUSED:
        case WSAECONNREFUSED:
            return UV_ECONNREFUSED;
        case ECONNABORTED:
        case WSAECONNABORTED:
            return UV_ECONNABORTED;
        case ECONNRESET:
        case WSAECONNRESET:
            return UV_ECONNRESET;
        default: return -err;
    }
#else
    return -err;
#endif
}

static void on_poll_close(uv_handle_t *h) {
    struct conn_req_s *cr = h->data;
    cr->count--;
    if (cr->count <= 0) {
        if (cr->cb) {
            cr->cb(INVALID_SOCKET, cr->error, cr->ctx);
        }
        UM_LOG(TRACE, "closing connect request");
        free_conn_req(cr);
    }
}

static void on_connect_poll(uv_poll_t *p, int status, int events) {
    struct conn_req_s *cr = p->data;
    uv_os_sock_t sock;
    if (uv_fileno((uv_handle_t*)p, (uv_os_fd_t*)&sock) != 0) {
        UM_LOG(ERR, "poll fileno error");
        cr->error = UV_EINVAL;
        uv_close((uv_handle_t*)p, on_poll_close);
        return;
    }
    UM_LOG(TRACE, "poll fd[%ld] status=%d events=%d", (long)sock, status, events);

    // check socket error status
    int err = 0;
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &(socklen_t){sizeof(err)});
    status = err_to_uv(err);

    if (status < 0) {
        UM_LOG(TRACE, "poll error on fd[%ld]: %s", (long)sock, uv_strerror(status));
        cr->error = status;
        uv_close((uv_handle_t*)p, on_poll_close);
        UM_LOG(TRACE, "closing fd[%ld]", (long)sock);
        closesocket(sock);
        return;
    }

    if (cr->cb == NULL) {
        // already handled
        uv_close((uv_handle_t*)p, on_poll_close);
        closesocket(sock);
        return;
    }

    uv_close((uv_handle_t*)p, on_poll_close);
    cr->cb(sock, 0, cr->ctx);
    cr->cb = NULL;

    for (int i = 0; i < cr->count; i++) {
        uv_handle_t *h = (uv_handle_t*)&cr->polls[i];
        if (cr->polls[i].type == UV_POLL && !uv_is_closing(h)) {
            uv_os_sock_t s = -1;
            uv_fileno(h, (uv_os_fd_t*)&s);
            uv_close(h, on_poll_close);
            UM_LOG(TRACE, "closing fd[%ld]", (long)s);
            closesocket(s);
        }
    }
}

static void on_resolve(uv_getaddrinfo_t *r, int status, struct addrinfo *addrlist) {
    struct conn_req_s *cr = container_of(r, struct conn_req_s, resolve);

    if (status == UV_EAI_CANCELED) {
        status = UV_ECANCELED;
    } else if (cr->error != 0) {
        status = cr->error;
    } else if (addrlist == NULL) {
        status = UV_EAI_NONAME;
    }

    if (status != 0) {
        uv_freeaddrinfo(addrlist);
        if (cr->cb) cr->cb(INVALID_SOCKET, status, cr->ctx);
        free_conn_req(cr);
        return;
    }

    struct addrinfo *addr = addrlist;
    int count = 0;
    int err = 0;
    while (addr && count < max_connect_socks) {
        uv_os_sock_t s = tlsuv_socket(addr, 0);
        if (s == INVALID_SOCKET) {
            err = get_error();
            // fd limit is hit, do not try to open any more sockets
            if (err == ENFILE || err == EMFILE) {
                break;
            }
            UM_LOG(TRACE, "error[%s] opening socket for %s",
                   strerror(err), get_name(addr->ai_addr));
            addr = addr->ai_next;
            continue;
        }

        UM_LOG(TRACE, "fd[%ld] connecting to %s", (long)s, get_name(addr->ai_addr));
        int rc = connect(s, addr->ai_addr, addr->ai_addrlen);
        err = get_error();
        if (rc == 0 || in_progress(err)) {
            uv_poll_init_socket(r->loop, &cr->polls[count], s);
            uv_poll_start(&cr->polls[count], UV_WRITABLE | UV_DISCONNECT, on_connect_poll);
            cr->polls[count].data = cr;
            count++;
        } else {
            UM_LOG(TRACE, "fd[%ld] failed to connect: %d/%s", (long)s, err, strerror(err));
            closesocket(s);
        }
        addr = addr->ai_next;
    }
    cr->count = count;

    uv_freeaddrinfo(addrlist);
    if (count == 0) {
        if (cr->cb) cr->cb(INVALID_SOCKET, err_to_uv(err), cr->ctx);
        free_conn_req(cr);
        return;
    }
}

tlsuv_connector_req direct_connect(uv_loop_t *loop, const tlsuv_connector_t *self,
                                   const char *host, const char *port,
                                   tlsuv_connect_cb cb, void *ctx) {
    assert(cb != NULL);
    struct conn_req_s *r = tlsuv__calloc(1, sizeof(*r));
    r->ctx = ctx;
    r->cb = cb;

    struct addrinfo hints = {
            .ai_socktype = SOCK_STREAM,
    };

    uv_getaddrinfo(loop, &r->resolve, on_resolve, host, port, &hints);

    return r;
}

void direct_cancel(tlsuv_connector_req req) {
    UM_LOG(VERB, "cancelling");
    struct conn_req_s *r = (struct conn_req_s *) req;

    // try to cancel resolve/connect request before it started
    uv_cancel((uv_req_t *) &r->resolve);
    r->error = UV_ECANCELED;
    for (int i = 0; i < max_connect_socks; i++) {
        uv_handle_t *h = (uv_handle_t*)&r->polls[i];
        if (h->type == UV_POLL && !uv_is_closing(h)) {
            uv_close(h, on_poll_close);
        }
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
    volatile bool cancel;
    int err;
};

static void proxy_work(uv_work_t *wr) {
    volatile struct proxy_connect_req *r = container_of(wr, struct proxy_connect_req, work);

    const struct tlsuv_proxy_connector_s *proxy = r->proxy;
    if (r->cancel) {
        r->err = UV_ECANCELED;
        return;
    }

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
        r->err = err_to_uv((int)get_error());
        closesocket(r->sock);
        r->sock = -1;
        return;
    }


    struct pollfd pfd = {
            .fd = r->sock,
            .events = POLLIN,
    };

    while(poll(&pfd, 1, 50) == 0) {
        if (r->cancel) {
            r->err = UV_ECANCELED;
            return;
        }
    }

    if (pfd.revents & (POLLHUP|POLLERR)) {
        r->err = UV_ECONNREFUSED;
        return;
    }

    res = read(r->sock, req, sizeof(req)-1);
    if (res < 0) {
        r->err = err_to_uv((int)get_error());
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

    UM_LOG(TRACE, "fd[%lu] is connected via HTTP proxy", (unsigned long)r->sock);
    if (r->cb) r->cb(r->sock, r->err, r->data);
    tlsuv__free(r->host);
    tlsuv__free(r->port);
    tlsuv__free(r);
}

static void on_proxy_connect(uv_os_sock_t fd, int status, void *req) {
    struct proxy_connect_req *r = req;
    r->conn_req = NULL;
    if (status != 0) {
        if (r->cb) r->cb(-1, status, r->data);
        tlsuv__free(r->port);
        tlsuv__free(r->host);
        tlsuv__free(r);
    } else {
        r->sock = fd;
        UM_LOG(TRACE, "fd[%lu] starting HTTP proxy connect", (unsigned long)r->sock);
        uv_queue_work(r->work.loop, &r->work, proxy_work, proxy_work_cb);
    }
}

tlsuv_connector_req proxy_connect(uv_loop_t *loop, const tlsuv_connector_t *self,
                                  const char *host, const char *port, tlsuv_connect_cb cb, void *ctx) {

    assert(loop);
    assert(self);
    assert(cb != NULL);
    assert(host != NULL && port != NULL);

    const struct tlsuv_proxy_connector_s *proxy = (const struct tlsuv_proxy_connector_s *) self;
    struct proxy_connect_req *r = tlsuv__calloc(1, sizeof(*r));
    r->proxy = proxy;
    r->data = ctx;
    r->cb = cb;
    r->host = tlsuv__strdup(host);
    r->port = tlsuv__strdup(port);
    r->work.loop = loop;
    r->conn_req = direct_connect(loop, &direct_connector, proxy->host, proxy->port, on_proxy_connect, r);
    return r;
}

int proxy_set_auth(tlsuv_connector_t *self, tlsuv_auth_t auth, const char *username, const char *password) {
    struct tlsuv_proxy_connector_s *c = (struct tlsuv_proxy_connector_s *) self;
    if (auth == tlsuv_PROXY_NONE) {
        c->auth_header = NULL;
        tlsuv__free(c->auth_value);
        c->auth_value = NULL;
        return 0;
    }

    if (auth == tlsuv_PROXY_BASIC) {
        if (!username || !password)
            return UV_EINVAL;
        c->auth_header = "Proxy-Authorization";
        tlsuv__free(c->auth_value);

        char authstr[256];
        size_t auth_len = snprintf(authstr, sizeof(authstr), "%s:%s", username, password);

        c->auth_value = tlsuv__malloc(512);
        size_t offset = snprintf(c->auth_value, 512, "Basic ");
        char *b64 = c->auth_value + offset;
        size_t b64max = 512 - offset;
        return tlsuv_base64_encode((uint8_t *)authstr, auth_len, &b64, &b64max);
    }

    return UV_EINVAL;
}

void proxy_cancel(tlsuv_connector_req req) {
    struct proxy_connect_req *r = (struct proxy_connect_req*)req;
    if (r->conn_req) {
        tlsuv_connector_req cr = r->conn_req;
        r->conn_req = NULL;
        direct_cancel(cr);
        return;
    }
    r->cancel = true;
    if (r->work.type == UV_WORK) {
        uv_cancel((uv_req_t *) &r->work);
    }
}

void proxy_free(tlsuv_connector_t *self) {
    struct tlsuv_proxy_connector_s *c = (struct tlsuv_proxy_connector_s *) self;
    tlsuv__free(c->host);
    tlsuv__free(c->port);
    tlsuv__free(c->auth_value);
    tlsuv__free(c);
}

tlsuv_connector_t *tlsuv_new_proxy_connector(tlsuv_proxy_t type, const char* host, const char * port) {
    struct tlsuv_proxy_connector_s *c = tlsuv__calloc(1, sizeof(*c));
    init_proxy_connector(c, type, host, port);

    return (tlsuv_connector_t *)c;
}

static void init_proxy_connector(struct tlsuv_proxy_connector_s *c, tlsuv_proxy_t type, const char *host, const char *port) {
    c->type = type;
    c->host = tlsuv__strdup(host);
    c->port = tlsuv__strdup(port);
    c->connect = proxy_connect;
    c->cancel = proxy_cancel;
    c->set_auth = proxy_set_auth;
    c->free = proxy_free;
}


