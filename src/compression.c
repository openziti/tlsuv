
#include <uv.h>
#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include "um_debug.h"

#include "compression.h"

#define NO_GZIP (1 << 16)

static uv_once_t init_guard;
static uv_lib_t zlib;
static const char* (*zlib_ver)(void);
static ulong (*zlib_flags)(void);
static int (*inflateEnd_f)(z_streamp strm);
static int (*inflateInit_f)(z_streamp strm, const char *version, int stream_size);
static int (*inflateInit2_f) (z_streamp strm, int  windowBits, const char *version, int stream_size);
static int (*inflate_f)(z_streamp strm, int flush);
static const char * (*zError_f) (int);

static const char *ZLibVersion;
static char *encodings;

struct um_http_inflater_s {
    z_stream s;
    int complete;

    data_cb cb;
    void *cb_ctx;
};


static void* my_alloc(void *ctx, unsigned int c, unsigned int s) {
    printf("allocating %d * %d\n", c, s);
    return calloc(c, s);
}

static void my_free(void *ctx, void *p) {
    free(p);
}

static void init() {

#define CHECK_DL(op) do{ \
if ((op) != 0)           \
goto on_error;           \
} while(0)

    CHECK_DL(uv_dlopen("libz.so", &zlib));
    CHECK_DL(uv_dlsym(&zlib, "zlibVersion", (void **) &zlib_ver));
    CHECK_DL(uv_dlsym(&zlib, "zlibCompileFlags", (void **) &zlib_flags));
    CHECK_DL(uv_dlsym(&zlib, "inflateEnd", (void **) &inflateEnd_f));
    CHECK_DL(uv_dlsym(&zlib, "inflateInit_", (void **) &inflateInit_f));
    CHECK_DL(uv_dlsym(&zlib, "inflateInit2_", (void **) &inflateInit2_f));
    CHECK_DL(uv_dlsym(&zlib, "inflate", (void **) &inflate_f));
    CHECK_DL(uv_dlsym(&zlib, "zError", (void **) &zError_f));


    ZLibVersion = zlib_ver();
    if (ZLibVersion[0] != ZLIB_VERSION[0]) {
        return;
    }
    if (zlib_flags() & NO_GZIP) {
        encodings = "deflate";
    } else {
        encodings = "gzip, deflate";
    }

    on_error:
    UM_LOG(ERR, "failed to initialize HTTP decompression: %s", uv_dlerror(&zlib));

    done:
    return;
}

const char *um_available_encoding() {
    uv_once(&init_guard, init);
    return encodings;
}

#define inflateInit_ inflateInit_f
#define inflateInit2_ inflateInit2_f

http_inflater_t *um_get_inflater(const char *encoding, data_cb cb, void *ctx) {
    um_available_encoding();

    http_inflater_t *inf = calloc(1, sizeof(http_inflater_t));
    inf->s.zalloc = my_alloc;
    inf->s.zfree = my_free;
    if (strcmp(encoding, "gzip") == 0)
        inflateInit2(&inf->s, 16 + MAX_WBITS);
    else if (strcmp(encoding, "deflate") == 0)
        inflateInit(&inf->s);
    else {
        free(inf);
        return NULL;
    }

    inf->cb = cb;
    inf->cb_ctx = ctx;
    return inf;
}

void um_free_inflater(http_inflater_t *inflater) {
    if (inflater) {
        inflateEnd_f(&inflater->s);
        free(inflater);
    }
}

int um_inflate(http_inflater_t *inflater, const char *compressed, size_t len) {
    inflater->s.next_in = compressed;
    inflater->s.avail_in = len;
    char decompressed[32 * 1024];
    while(inflater->s.avail_in > 0) {
        inflater->s.next_out = decompressed;
        inflater->s.avail_out = sizeof(decompressed);
        int rc = inflate_f(&inflater->s, Z_FULL_FLUSH);
        ssize_t decomp_count = sizeof(decompressed) - inflater->s.avail_out;
        if (decomp_count > 0) {
            inflater->cb(inflater->cb_ctx, decompressed, decomp_count);
        }
        if (rc == Z_STREAM_END) {
            inflater->complete = 1;
            break;
        }
    }
    return 0;
}

int um_inflate_state(http_inflater_t *inflater) {
    if (inflater->s.msg) return -1;

    return inflater->complete;
}
