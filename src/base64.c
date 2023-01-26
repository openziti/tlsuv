#include "um_debug.h"

/*
Copyright 2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdlib.h>

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

size_t tlsuv_base64url_decode(const char *in, char **out, size_t *out_len) {

    *out_len = base64url_decode_len(in);
    unsigned char *buf = malloc(*out_len);

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
    *out = buf;

    UM_LOG(DEBG, "base64url_decode len is: %zu", len);

    return len;
}


