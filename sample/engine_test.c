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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlsuv/tlsuv.h>

#define HOST "wttr.in"

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
        strcpy(ip, inet_ntoa(*addr[i]));
    }

    printf("ip: %s\n", ip);

    tls_context *tls = default_tls_context(NULL, 0);
    tls_engine *engine = tls->api->new_engine(tls->ctx, HOST);

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

    // do handshake
    char ssl_in[32 * 1024];
    char ssl_out[32 * 1024];
    size_t in_bytes = 0;
    size_t out_bytes = 0;

    int i = 0;
    do {
        tls_handshake_state state = engine->api->handshake(engine->engine, ssl_in, in_bytes, ssl_out, &out_bytes,
                                                           sizeof(ssl_out));

        if (state == TLS_HS_COMPLETE) {
            printf("handshake complete\n");
            break;
        }
        else if (state == TLS_HS_ERROR) {
            fprintf(stderr, "handshake failed\n");
            exit(1);
        }

        printf("hs: out_bytes=%zd, state=%x\n", out_bytes, state);
        if (out_bytes > 0) {
            size_t wrote = send(sock, ssl_out, out_bytes, 0);
            printf("hs: wrote_bytes=%zd\n", wrote);
        }

        in_bytes = recv(sock, ssl_in, sizeof(ssl_in), 0);
        printf("hs: in_bytes=%zd\n", in_bytes);
    } while (true);

    const char *req = "GET /Charlotte HTTP/1.1\n"
                      "Accept: */*\n"
                      "Accept-Enconding: plain\n"
                      "Connection: keep-alive\n"
                      "Host: " HOST "\n"
                      "User-Agent: HTTPie/1.0.2\n"
                      "\n";

    engine->api->write(engine->engine, req, strlen(req), ssl_out, &out_bytes, sizeof(ssl_out));
    printf("writing req=%zd bytes\n", out_bytes);

    send(sock, ssl_out, out_bytes, 0);

    char resp[128];
    size_t resp_read = 0;

    int read_res = 0;
    do {
        if (read_res == 0 || read_res == TLS_READ_AGAIN) {
            in_bytes = recv(sock, ssl_in, sizeof(ssl_in), 0);
            printf("read resp=%zd bytes\n", in_bytes);
        }
        else {
            in_bytes = 0;
        }

        read_res = engine->api->read(engine->engine, ssl_in, in_bytes, resp, &resp_read, sizeof(resp));
        printf("%*.*s", (int) resp_read, (int) resp_read, resp);
    } while (read_res == TLS_READ_AGAIN || read_res == TLS_MORE_AVAILABLE);

    engine->api->close(engine->engine, ssl_out, &out_bytes, sizeof(ssl_out));
    send(sock, ssl_out, out_bytes, 0);

    sockClose(sock);

#if _WIN32
    WSACleanup();
#endif

    tls->api->free_engine(engine);
    tls->api->free_ctx(tls);
}