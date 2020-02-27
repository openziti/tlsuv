/*
Copyright 2019-2020 NetFoundry, Inc.

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
#include <stdint.h>
#include <string.h>
#ifdef _WIN32
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#else
#include <sys/param.h>
#endif
#include "bio.h"

struct msg {
    size_t len;
    uint8_t *buf;

    STAILQ_ENTRY(msg) next;
};

BIO *um_BIO_new(int zerocopy) {
    BIO* bio = calloc(1, sizeof(BIO));
    bio->available = 0;
    bio->headoffset = 0;
    bio->qlen = 0;
    bio->zerocopy = zerocopy;

    STAILQ_INIT(&bio->message_q);
    return bio;
}

void um_BIO_free(BIO* b) {
    while(!STAILQ_EMPTY(&b->message_q)) {
        struct msg *m = STAILQ_FIRST(&b->message_q);
        STAILQ_REMOVE_HEAD(&b->message_q, next);
        free(m->buf);
        free(m);
    }

    free(b);
}

size_t um_BIO_available(BIO* bio) {
    return bio->available;
}

int um_BIO_put(BIO *bio, const uint8_t *buf, size_t len) {
    struct msg *m = malloc(sizeof(struct msg));
    if (m == NULL) {
        return -1;
    }

    if (bio->zerocopy) {
        m->buf = buf;
    } else {
        m->buf = malloc(len);
        if (m->buf == NULL) {
            free(m);
            return -1;
        }
        memcpy(m->buf, buf, len);
    }

    m->len = len;

    STAILQ_INSERT_TAIL(&bio->message_q, m, next);
    bio->available += len;
    bio->qlen += 1;

    return len;
}

int um_BIO_read(BIO *bio, uint8_t *buf, size_t len) {

    size_t total = 0;

    while (! STAILQ_EMPTY(&bio->message_q) && total < len) {
        struct msg *m = STAILQ_FIRST(&bio->message_q);

        size_t recv_size = MIN(len - total, m->len - bio->headoffset);
        memcpy(buf + total, m->buf + bio->headoffset, recv_size);
        bio->headoffset += recv_size;
        bio->available -= recv_size;
        total += recv_size;

        if (bio->headoffset == m->len) {
            STAILQ_REMOVE_HEAD(&bio->message_q, next);
            bio->headoffset = 0;
            bio->qlen -= 1;

            free(m->buf);
            free(m);
        }
    }

    return (int) total;
}
