//
// Created by eugene on 3/14/19.
//

#ifndef UV_MBED_BIO_H
#define UV_MBED_BIO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

struct msg;

struct bio {
    size_t available;
    size_t headoffset;
    uint qlen;
    int zerocopy;
    STAILQ_HEAD(msgq, msg) message_q;
};

// zerocopy means that buffer passed into BIO_put will be owned/released by BIO,
// this avoids an extra alloc/copy operation
struct bio* bio_new(int zerocopy);
void bio_free(struct bio*);

int bio_put(struct bio *, const uint8_t *buf, size_t len);
size_t bio_read(struct bio*, uint8_t *buf, size_t len);
size_t bio_available(struct bio*);

#endif //UV_MBED_BIO_H
