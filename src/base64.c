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

#include "um_debug.h"

#include <stdlib.h>
#include <uv.h>

#include "alloc.h"

static const unsigned char base64[] = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
        'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
        'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
};

static const unsigned char pr2six[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 63,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

static size_t base64url_decode_len(const char *bufcoded) {
    size_t nbytesdecoded;
    register const unsigned char *bufin;
    register size_t nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded;
}

int tlsuv_base64_encode(const uint8_t *in, size_t in_len, char **out, size_t *out_len) {
    size_t b64len = in_len * 4 / 3 + 3;

    if (*out != NULL && *out_len < b64len) {
        return UV_ENOMEM;
    }
    if (*out == NULL) {
        *out = tlsuv__malloc(b64len + 1);
    }

    uint8_t *outp = (uint8_t *)*out;
    uint8_t ch1, ch2, ch3;
    int i = 0;
    for (; i + 2 < in_len; ) {
        ch1 = in[i++];
        ch2 = in[i++];
        ch3 = in[i++];

        *outp++ = base64[ (ch1 >> 2) & 0x3f ];
        *outp++ = base64[ ((ch1 & 0x3) << 4) | (ch2 >> 4) & 0xf ];
        *outp++ = base64[ ((ch2 & 0xf) << 2) | (ch3 >> 6) & 0x3 ];
        *outp++ = base64[ (ch3 & 0x3f) ];
    }

    if (i < in_len) {
        ch1 = in[i++];
        ch2 = i < in_len ? in[i] : 0;
        *outp++ = base64[ ch1 >> 2 & 0x3f ];
        *outp++ = base64[ ((ch1 & 0x3) << 4) | (ch2 >> 4) & 0xf ];

        if (i < in_len) {
            *outp++ = base64[ ((ch2 & 0xf) << 2) ];
        } else {
            *outp++ = '=';
        }
        *outp++ = '=';
    }
    *outp = 0;

    *out_len = (char*)outp - *out;
    return 0;
}

size_t tlsuv_base64url_decode(const char *in, char **out, size_t *out_len) {

    *out_len = base64url_decode_len(in);
    if (*out_len == 0) {
        *out = NULL;
        return 0;
    }
    unsigned char *buf = tlsuv__calloc(*out_len + 1, 1);

    register const unsigned char *bufin;
    register unsigned char *bufout;
    register size_t nprbytes;

    bufin = (const unsigned char *) in;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) in) - 1;

    bufout = (unsigned char *) buf;
    bufin = (const unsigned char *) in;

    while (nprbytes > 4) {
        *(bufout++) = (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
        *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
        *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }

    if (nprbytes > 1)
        *(bufout++) = (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    if (nprbytes > 2)
        *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    if (nprbytes > 3)
        *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);

    size_t len = (bufout - buf);
    *out_len = len;
    *out = (char*)buf;

    UM_LOG(DEBG, "base64url_decode len is: %zu", len);

    return len;
}


