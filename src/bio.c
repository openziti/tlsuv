//
// Created by eugene on 3/14/19.
//

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/param.h>
#include "bio.h"

struct msg {
    size_t len;
    uint8_t *buf;

    STAILQ_ENTRY(msg) next;
};

BIO *BIO_new(int zerocopy) {
    BIO* bio = calloc(1, sizeof(BIO));
    bio->available = 0;
    bio->headoffset = 0;
    bio->qlen = 0;
    bio->zerocopy = zerocopy;

    STAILQ_INIT(&bio->message_q);
    return bio;
}

void BIO_free(BIO* b) {
    while(!STAILQ_EMPTY(&b->message_q)) {
        struct msg *m = STAILQ_FIRST(&b->message_q);
        STAILQ_REMOVE_HEAD(&b->message_q, next);
        free(m->buf);
        free(m);
    }

    free(b);
}

size_t BIO_available(BIO* bio) {
    return bio->available;
}

int BIO_put(BIO *bio, const uint8_t *buf, size_t len) {
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

int BIO_read(BIO *bio, uint8_t *buf, size_t len) {

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