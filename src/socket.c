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

#include "util.h"
#include <uv.h>

uv_os_sock_t tlsuv_socket(const struct addrinfo *addr, bool blocking) {
    uv_os_sock_t sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

    int on = 1;
    int flags;

#if defined(SO_NOSIGPIPE)
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#elif defined(F_SETNOSIGPIPE)
    fcntl(sock, F_SETNOSIGPIPE, on);
#endif

#if defined(FD_CLOEXEC)
    flags = fcntl(sock, F_GETFD);
    fcntl(sock, F_SETFD, flags | FD_CLOEXEC);
#endif

    tlsuv_socket_set_blocking(sock, blocking);

    return sock;
}

