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

#ifndef UV_MBED_BIO_H
#define UV_MBED_BIO_H

#include "uv_mbed/queue.h"

typedef struct bio {
    size_t available;
    size_t headoffset;
    unsigned int qlen;
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

