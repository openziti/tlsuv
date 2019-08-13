//
// Created by eugene on 3/14/19.
//


#include <uv.h>
#include <stdlib.h>
#include <uv_mbed/uv_mbed.h>

#define HOST "www.wttr.in"

static void alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char*) malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_close(uv_handle_t* h) {
    printf("mbed is closed\n");
    uv_mbed_free((uv_mbed_t *) h);
}

void on_data(uv_stream_t *h, ssize_t nread, const uv_buf_t* buf) {
    if (nread > 0) {
        printf("%*.*s", (int) nread, (int) nread, buf->base);
        fflush(stdout);
    } else if (nread == UV_EOF) {
        printf("=====================\nconnection closed\n");
        uv_mbed_close((uv_mbed_t *) h, on_close);
    }
    else if (nread < 0) {
        fprintf(stderr, "read error %ld: %s\n", nread, uv_strerror((int) nread));
        uv_mbed_close((uv_mbed_t *) h, on_close);
    }

    free(buf->base);
}

void write_cb(uv_write_t *wr, int status) {
    if (status < 0) {
        fprintf(stderr, "write failed: %d: %s\n", status, uv_strerror(status));
        uv_mbed_close((uv_mbed_t *) wr->handle, on_close);
    }
    printf("request sent %d\n", status);
    free(wr);
}

void on_connect(uv_connect_t *cr, int status) {
    if (status < 0) {
        fprintf(stderr, "connect failed: %d: %s\n", status, uv_strerror(status));
        uv_mbed_close((uv_mbed_t *) cr->handle, on_close);
        return;
    }

    uv_mbed_t *mbed = (uv_mbed_t *) cr->handle;
    uv_mbed_read(mbed, alloc, on_data);

    uv_write_t *wr = malloc(sizeof(uv_write_t));
    char req[] = "GET / HTTP/1.1\r\n"
                       "Accept: */*\r\n"
                       "Connection: close\r\n"
                 "Host: " HOST "\r\n"
                 "User-Agent: curl/0.5.0\r\n"
                       "\r\n";

    uv_buf_t buf = uv_buf_init(req, sizeof(req));
    uv_mbed_write(wr, mbed, &buf, write_cb);
}

int main() {
    uv_loop_t* l = uv_default_loop();

    uv_mbed_t mbed;
    uv_mbed_init(l, &mbed, NULL);

    uv_connect_t* req = calloc(1, sizeof(uv_connect_t));
    uv_mbed_connect(req, &mbed, HOST, 443, on_connect);

    uv_run(l, UV_RUN_DEFAULT);
    free(req);
}
