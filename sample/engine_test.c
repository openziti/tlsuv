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

#if _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS //
//windows specific includes
#else
#include <netdb.h>
#include <zconf.h>
#include <arpa/inet.h>
#define SOCKET int //differences tween windows and posix
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlsuv/tlsuv.h>
#include "common.h"

#define HOST "httpbingo.org"
#define PATH "/json"

int sockClose(SOCKET sock)
{
    //a helper to hide the differences between closing a socket in windows vs posix
    int status = 0;
#ifdef _WIN32
    status = shutdown(sock, SD_BOTH);
    if (status == 0) { status = closesocket(sock); }
#else
    status = shutdown(sock, SHUT_RDWR);
    if (status == 0) { status = close(sock); }
#endif
    return status;
}


int main(int argc, char **argv) {
    tlsuv_set_debug(5, logger);

#if _WIN32
    //changes the output to UTF-8 so that the windows output looks correct and not all jumbly
    SetConsoleOutputCP(65001);
    WSADATA WSAData;
    int err = WSAStartup(MAKEWORD(2, 0), &WSAData);

    if (err != 0) {
        printf("WSAStartup failed with error: %d\n", err);
        return 1;
    }
#endif

    struct hostent *he = gethostbyname(HOST);

    char ip[1000];
    struct in_addr **addr = (struct in_addr **) he->h_addr_list;
    for (int i = 0; addr[i] != NULL; i++) {
        strncpy(ip, inet_ntoa(*addr[i]), sizeof(ip));
    }

    printf("ip: %s\n", ip);

    tls_context *tls = default_tls_context(NULL, 0);
    tlsuv_engine_t engine = tls->new_engine(tls, HOST);
    const char *alpn[] = { "http/1.1" };
    engine->set_protocols(engine, alpn, 1);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Forcefully attaching socket to the port 8080
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   &opt, sizeof(opt))) {
        perror("setsockopt");
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip);
    address.sin_port = htons(443);
    
    if (connect(sock, (const struct sockaddr *) &address, addrlen) != 0) {
        perror("failed to connect");
        printf("connection with the server failed...\n");
        exit(0);
    }
    else {
        printf("connected\n");
    }

    engine->set_io_fd(engine, (uv_os_sock_t)sock);

    // do handshake
    do {
        tls_handshake_state state = engine->handshake(engine);

        if (state == TLS_HS_COMPLETE) {
            printf("handshake complete alpn[%s]\n", engine->get_alpn(engine));
            break;
        }
        else if (state == TLS_HS_ERROR) {
            fprintf(stderr, "handshake failed\n");
            exit(1);
        }
    } while (true);

    const char *req = "GET " PATH " HTTP/1.1\n"
                      "Accept: */*\n"
                      "Accept-Enconding: plain\n"
                      "Connection: keep-alive\n"
                      "Host: " HOST "\n"
                      "User-Agent: HTTPie/1.0.2\n"
                      "\n";

    engine->write(engine, req, strlen(req));

    char resp[12800];
    size_t resp_read = 0;

    int read_res = 0;
    do {
        fprintf(stderr, "reading(%d)...\n", read_res);
        read_res = engine->read(engine, resp, &resp_read, sizeof(resp));
        fprintf(stderr, "read(%d,%zd)...\n", read_res, resp_read);

        if (resp_read > 0) {
            printf("%.*s", (int) resp_read, resp);
            fflush(stdout);
        }
        else
            fprintf(stderr, "read_res = %d\n", read_res);
    } while (read_res != TLS_EOF && read_res != TLS_ERR);

    printf("closing \n");

    engine->close(engine);

    sockClose(sock);

#if _WIN32
    WSACleanup();
#endif

    engine->free(engine);
    tls->free_ctx(tls);
}