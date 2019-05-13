//
// Created by eugene on 3/14/19.
//

#ifndef UV_MBED_BIO_H
#define UV_MBED_BIO_H

#include <sys/queue.h>

typedef struct bio {
    size_t available;
    size_t headoffset;
    uint qlen;
    int zerocopy;
    STAILQ_HEAD(msgq, msg) message_q;
} BIO;

// zerocopy means that buffer passed into BIO_put will be owned/released by BIO,
// this avoids an extra alloc/copy operation
BIO* BIO_new(int zerocopy);
void BIO_free(BIO*);

int BIO_put(BIO *, const uint8_t *buf, size_t len);
int BIO_read(BIO*, uint8_t *buf, size_t len);
size_t BIO_available(BIO*);

#endif //UV_MBED_BIO_H
