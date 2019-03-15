//
// Created by eugene on 3/14/19.
//

#ifndef UV_MBED_BIO_H
#define UV_MBED_BIO_H

#include <sys/queue.h>

typedef struct bio {
    size_t available;
    size_t headoffset;
    SIMPLEQ_HEAD(msgq, msg) message_q;
} BIO;

BIO* BIO_new();
void BIO_free(BIO*);

void BIO_put(BIO *, const uint8_t *buf, size_t len);
int BIO_read(BIO*, uint8_t *buf, size_t len);
size_t BIO_available(BIO*);

#endif //UV_MBED_BIO_H
