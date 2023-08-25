
// Copyright (c) NetFoundry Inc.
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
static unsigned long (*zlib_flags)(void);
static int (*inflateEnd_f)(z_streamp strm);
static int (*inflateInit_f)(z_streamp strm, const char *version, int stream_size);
static int (*inflateInit2_f) (z_streamp strm, int  windowBits, const char *version, int stream_size);
static int (*inflate_f)(z_streamp strm, int flush);
static const char * (*zError_f) (int);

static const char *ZLibVersion;
static char *encodings;

struct tlsuv_http_inflater_s {
    z_stream s;
    int complete;

    data_cb cb;
    void *cb_ctx;
};

static void* comp_alloc(void *ctx, unsigned int c, unsigned int s) {
    return calloc(c, s);
}

static void comp_free(void *ctx, void *p) {
    free(p);
}

#if __linux__
#define SO_lib(p) (#p ".so")
#elif defined(__APPLE__)
#define SO_lib(p) (#p ".dylib")
#else

#endif

static void init(void) {

#if _WIN32
    // on WIN32 zlib is not usually available
    // so we link it statically and set functions pointers directly
    zlib_ver = zlibVersion;
    zlib_flags = zlibCompileFlags;
    inflateInit_f = inflateInit_;
    inflateInit2_f = inflateInit2_;
    inflateEnd_f = inflateEnd;
    inflate_f = inflate;
    zError_f = zError;
#else
#define CHECK_DL(op) do{ \
if ((op) != 0)           \
goto on_error;           \
} while(0)

    CHECK_DL(uv_dlopen(SO_lib(libz), &zlib));
    CHECK_DL(uv_dlsym(&zlib, "zlibVersion", (void **) &zlib_ver));
    CHECK_DL(uv_dlsym(&zlib, "zlibCompileFlags", (void **) &zlib_flags));
    CHECK_DL(uv_dlsym(&zlib, "inflateEnd", (void **) &inflateEnd_f));
    CHECK_DL(uv_dlsym(&zlib, "inflateInit_", (void **) &inflateInit_f));
    CHECK_DL(uv_dlsym(&zlib, "inflateInit2_", (void **) &inflateInit2_f));
    CHECK_DL(uv_dlsym(&zlib, "inflate", (void **) &inflate_f));
    CHECK_DL(uv_dlsym(&zlib, "zError", (void **) &zError_f));
#endif

    ZLibVersion = zlib_ver();
    if (ZLibVersion[0] != ZLIB_VERSION[0]) {
        return;
    }
    if (zlib_flags() & NO_GZIP) {
        encodings = "deflate";
    } else {
        encodings = "gzip, deflate";
    }
    goto done;

    on_error:
    UM_LOG(ERR, "failed to initialize HTTP decompression: %s", uv_dlerror(&zlib));

    done:
    return;
}

const char *um_available_encoding(void) {
    uv_once(&init_guard, init);
    return encodings;
}

#define inflateInit_ inflateInit_f
#define inflateInit2_ inflateInit2_f

http_inflater_t *um_get_inflater(const char *encoding, data_cb cb, void *ctx) {
    um_available_encoding();

    http_inflater_t *inf = calloc(1, sizeof(http_inflater_t));
    inf->s.zalloc = comp_alloc;
    inf->s.zfree = comp_free;
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
    inflater->s.next_in = (uint8_t *)compressed;
    inflater->s.avail_in = (uInt)len;
    uint8_t decompressed[32 * 1024];
    while(inflater->s.avail_in > 0) {
        inflater->s.next_out = decompressed;
        inflater->s.avail_out = sizeof(decompressed);
        int rc = inflate_f(&inflater->s, Z_FULL_FLUSH);
        if (rc == Z_DATA_ERROR) {
            return -1;
        }
        size_t decomp_count = sizeof(decompressed) - inflater->s.avail_out;
        if (decomp_count > 0) {
            inflater->cb(inflater->cb_ctx, (const char*)decompressed, (ssize_t)decomp_count);
        }
        if (rc == Z_STREAM_END) {
            inflater->complete = 1;
            return 1;
        }
    }
    return 0;
}

int um_inflate_state(http_inflater_t *inflater) {
    if (inflater->s.msg) return -1;

    return inflater->complete;
}
