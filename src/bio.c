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

    SIMPLEQ_ENTRY(msg) next;
};

BIO *BIO_new() {
    BIO* bio = calloc(1, sizeof(BIO));
    bio->available = 0;
    bio->headoffset = 0;
    SIMPLEQ_INIT(&bio->message_q);
    return bio;
}

void BIO_free(BIO* b) {
    while(!SIMPLEQ_EMPTY(&b->message_q)) {
        struct msg *m = SIMPLEQ_FIRST(&b->message_q);
        SIMPLEQ_REMOVE_HEAD(&b->message_q, next);
        free(m->buf);
        free(m);
    }

    free(b);
}

size_t BIO_available(BIO* bio) {
    return bio->available;
}

void BIO_put(BIO *bio, uint8_t *buf, size_t len) {
    struct msg *m = malloc(sizeof(struct msg));
    m->buf = malloc(len);
    m->len = len;
    memcpy(m->buf, buf, len);
    bio->available += len;

    SIMPLEQ_INSERT_TAIL(&bio->message_q, m, next);
}

int BIO_read(BIO *bio, uint8_t *buf, size_t len) {
    if (SIMPLEQ_EMPTY(&bio->message_q)) {
        return -1;
    }

    struct msg *m = SIMPLEQ_FIRST(&bio->message_q);

    size_t recv_size = MIN(len, m->len - bio->headoffset);
    memcpy(buf, m->buf + bio->headoffset, recv_size);
    bio->headoffset += recv_size;
    bio->available -= recv_size;

    if (bio->headoffset == m->len) {
        SIMPLEQ_REMOVE_HEAD(&bio->message_q, next);
        bio->headoffset = 0;

        free(m->buf);
        free(m);
    }

    return (int) recv_size;
}


