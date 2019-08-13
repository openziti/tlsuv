//
// Created by eugene on 8/8/19.
//

#include <netdb.h>
#include <zconf.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <uv_mbed/uv_mbed.h>

#define HOST "wttr.in"


int main(int argc, char **argv) {
    struct hostent *he = gethostbyname(HOST);

    char ip[1000];
    struct in_addr **addr = (struct in_addr **) he->h_addr_list;
    for (int i = 0; addr[i] != NULL; i++) {
        strcpy(ip, inet_ntoa(*addr[i]));
    }

    printf("ip: %s\n", ip);

    tls_context *tls = default_tls_context(NULL, 0);
    tls_engine *engine = tls->api->new_engine(tls->ctx, HOST);

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Forcefully attaching socket to the port 8080
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
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
            size_t wrote = write(sock, ssl_out, out_bytes);
            printf("hs: wrote_bytes=%zd\n", wrote);
        }

        in_bytes = read(sock, ssl_in, sizeof(ssl_in));
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
    write(sock, ssl_out, out_bytes);

    char resp[128];
    size_t resp_read = 0;

    int read_res = 0;
    do {
        if (read_res == 0 || read_res == TLS_READ_AGAIN) {
            in_bytes = read(sock, ssl_in, sizeof(ssl_in));
            printf("read resp=%zd bytes\n", in_bytes);
        }
        else {
            in_bytes = 0;
        }

        read_res = engine->api->read(engine->engine, ssl_in, in_bytes, resp, &resp_read, sizeof(resp));
        printf("%*.*s", (int) resp_read, (int) resp_read, resp);
    } while (read_res == TLS_READ_AGAIN || read_res == TLS_MORE_AVAILABLE);

    engine->api->close(engine->engine, ssl_out, &out_bytes, sizeof(ssl_out));
    write(sock, ssl_out, out_bytes);

    close(sock);

    tls->api->free_engine(engine);
    tls->api->free_ctx(tls);
}

