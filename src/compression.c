
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

#include "alloc.h"
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
    return tlsuv__calloc(c, s);
}

static void comp_free(void *ctx, void *p) {
    tlsuv__free(p);
}

static void init(void) {
    zlib_ver = zlibVersion;
    zlib_flags = zlibCompileFlags;
    inflateInit_f = inflateInit_;
    inflateInit2_f = inflateInit2_;
    inflateEnd_f = inflateEnd;
    inflate_f = inflate;
    zError_f = zError;

    ZLibVersion = zlib_ver();
    if (ZLibVersion[0] != ZLIB_VERSION[0]) {
        UM_LOG(WARN, "zlib version[%s] is not supported", ZLibVersion);
        return;
    }

    if (zlib_flags() & NO_GZIP) {
        encodings = "deflate";
    } else {
        encodings = "gzip, deflate";
    }
}

const char *um_available_encoding(void) {
    uv_once(&init_guard, init);
    return encodings;
}

http_inflater_t *um_get_inflater(const char *encoding, data_cb cb, void *ctx) {
    um_available_encoding();

    http_inflater_t *inf = tlsuv__calloc(1, sizeof(http_inflater_t));
    inf->s.zalloc = comp_alloc;
    inf->s.zfree = comp_free;
    if (strcmp(encoding, "gzip") == 0)
        inflateInit2(&inf->s, 16 + MAX_WBITS);
    else if (strcmp(encoding, "deflate") == 0)
        inflateInit(&inf->s);
    else {
        tlsuv__free(inf);
        return NULL;
    }

    inf->cb = cb;
    inf->cb_ctx = ctx;
    return inf;
}

void um_free_inflater(http_inflater_t *inflater) {
    if (inflater) {
        inflateEnd_f(&inflater->s);
        tlsuv__free(inflater);
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
