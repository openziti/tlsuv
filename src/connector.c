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
    union {
        uv_getaddrinfo_t resolve;
        uv_work_t connect;
    };
    struct addrinfo *addr;

    void *ctx;
    tlsuv_connect_cb cb;

    uv_os_sock_t sock;
    int error;
    volatile bool cancel;
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

static void free_conn_req(struct conn_req_s *cr) {
    cr->addr ? uv_freeaddrinfo(cr->addr) : 0;
    tlsuv__free(cr);
}

static const char *get_name(const struct sockaddr *addr) {
    static char name[128];
    if (addr && uv_ip_name(addr, name, sizeof(name)) == 0) { return name; }

    return "<unknown>";
}

static const char *get_error_msg(int err) {
#if _WIN32
    static char msg[256];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, 0, msg, sizeof(msg), NULL);
    return msg;
#else
    return strerror(err);
#endif
}

static int err_to_uv(int err) {
#if _WIN32
    switch(err) {
        case WSAECONNREFUSED: return UV_ECONNREFUSED;
        case WSAECONNABORTED: return UV_ECONNABORTED;
        case WSAECONNRESET: return UV_ECONNRESET;
        default: return -err;
    }
#else
    return -err;
#endif
}

static void connect_work(uv_work_t *work) {
    volatile struct conn_req_s *cr = container_of(work, struct conn_req_s, connect);
    int rc = 0;
    int err = 0;
    int count = 0;

    cr->sock = INVALID_SOCKET;
    uv_os_sock_t fds[max_connect_socks];
    for (int i = 0; i < max_connect_socks; i++) fds[i] = INVALID_SOCKET;
    if (cr->cancel) {
        err = ECANCELED;
        goto done;
    }

    struct addrinfo *addr = cr->addr;
    while (addr && count < max_connect_socks) {
        uv_os_sock_t s = tlsuv_socket(addr, 0);
        UM_LOG(TRACE, "connecting fd[%ld] to %s", (long)s, get_name(addr->ai_addr));
        rc = connect(s, addr->ai_addr, addr->ai_addrlen);
        err = get_error();
        if (rc == 0 || in_progress(err)) {
            fds[count++] = s;
        } else {
            UM_LOG(TRACE, "fd[%ld] failed to connect: %d/%s", (long)s, err, strerror(err));
            closesocket(s);
        }
        addr = addr->ai_next;
    }

    if (count < 1) {
        goto done;
    }

    struct pollfd poll_fds[max_connect_socks];
    while (cr->sock == INVALID_SOCKET && cr->error == 0) {
        if (cr->cancel) {
            err = ECANCELED;
            break;
        }

        int poll_count = 0;
        memset(poll_fds, 0, sizeof(poll_fds));
        for (int i = 0; i < count; i++) {
            if (fds[i] == INVALID_SOCKET) continue;

            poll_fds[poll_count].fd = fds[i];
            poll_fds[poll_count].events = POLLOUT;
            poll_count++;
        }

        if (poll_count == 0) {
            err = ECONNREFUSED;
            break;
        }
        rc = poll(poll_fds, poll_count, 50);

        if (cr->cancel) {
            err = ECANCELED;
            break;
        }

        if (rc == -1) {
            err = get_error();
            break;
        }

        if (rc == 0) {
            UM_LOG(TRACE, "waiting more");
            continue;
        }

        err = 0;
        for (int i = 0; i < poll_count; i++) {
            if (poll_fds[i].revents & (POLLERR | POLLHUP)) {
                socklen_t len = sizeof(err);
                getsockopt(poll_fds[i].fd, SOL_SOCKET, SO_ERROR, &err, &len);
                if (err != 0) {
                    UM_LOG(TRACE, "fd[%ld] failed to connect: %d/%s",
                           (long) poll_fds[i].fd, err, get_error_msg(err));
                    closesocket(poll_fds[i].fd);
                    for (int idx = 0; idx < count; idx++) {
                        if (fds[idx] == poll_fds[i].fd) {
                            fds[idx] = INVALID_SOCKET;
                        }
                    }
                }
                continue;
            }

            // socket connected
            if (poll_fds[i].revents & POLLOUT) {
                cr->sock = poll_fds[i].fd;
                break;
            }
        }
    }

    done:
    if (cr->sock != INVALID_SOCKET) {
        UM_LOG(TRACE, "fd[%ld] is connected", (long)cr->sock);
    } else {
        cr->error = err_to_uv(err);
    }

    for (int i = 0; i < count; i++) {
        if (fds[i] != cr->sock && fds[i] != INVALID_SOCKET) {
            UM_LOG(TRACE, "closing fd[%ld]", (long)fds[i]);
            closesocket(fds[i]);
        }
    }
}

static void connect_done(uv_work_t *work, int status) {
    struct conn_req_s *cr = container_of(work, struct conn_req_s, connect);

    if (status == UV_ECANCELED) {
        cr->error = status;
    }
    if (cr->cancel) {
        cr->error = UV_ECANCELED;
    }
    if (cr->error && cr->sock != INVALID_SOCKET) {
        closesocket(cr->sock);
        cr->sock = INVALID_SOCKET;
    }
    if (cr->cb) cr->cb(cr->sock, cr->error, cr->ctx);
    free_conn_req(cr);
}

static void on_resolve(uv_getaddrinfo_t *r, int status, struct addrinfo *addrlist) {
    struct conn_req_s *cr = container_of(r, struct conn_req_s, resolve);

    if (status == UV_EAI_CANCELED) {
        status = UV_ECANCELED;
    } else if (cr->cancel) {
        status = UV_ECANCELED;
    } else if (addrlist == NULL) {
        status = UV_EAI_NONAME;
    }

    if (status != 0) {
        uv_freeaddrinfo(addrlist);
        if (cr->cb) cr->cb(cr->sock, status, cr->ctx);
        free_conn_req(cr);
        return;
    }

    cr->addr = addrlist;
    uv_queue_work(r->loop, &cr->connect, connect_work, connect_done);
}

tlsuv_connector_req default_connect(uv_loop_t *loop, const tlsuv_connector_t *self,
                                    const char *host, const char *port,
                                    tlsuv_connect_cb cb, void *ctx) {
    assert(cb != NULL);
    struct conn_req_s *r = tlsuv__calloc(1, sizeof(*r));
    r->ctx = ctx;
    r->cb = cb;
    r->sock = INVALID_SOCKET;

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

    // try to cancel resolve/connect request before it started
    uv_cancel((uv_req_t *) &r->resolve);
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
        r->err = -(int)get_error();
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
        r->err = -(int)get_error();
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
    r->conn_req = default_connect(loop, &default_connector, proxy->host, proxy->port, on_proxy_connect, r);
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
        default_cancel(cr);
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
    c->type = type;
    c->host = tlsuv__strdup(host);
    c->port = tlsuv__strdup(port);
    c->connect = proxy_connect;
    c->cancel = proxy_cancel;
    c->set_auth = proxy_set_auth;
    c->free = proxy_free;
    return (tlsuv_connector_t *)c;
}


