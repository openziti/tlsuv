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

#ifndef TLSUV_BIO_H
#define TLSUV_BIO_H

#include "tlsuv/queue.h"
#include <stdint.h>

typedef struct tlsuv_bio_s {
    size_t available;
    size_t headoffset;
    unsigned int qlen;
    STAILQ_HEAD(msgq, msg) message_q;
} tlsuv_BIO;

// create new BIO
tlsuv_BIO *tlsuv_BIO_new(void);
void tlsuv_BIO_free(tlsuv_BIO *bio);

int tlsuv_BIO_put(tlsuv_BIO *bio, const uint8_t *buf, size_t len);
int tlsuv_BIO_read(tlsuv_BIO *bio, uint8_t *buf, size_t len);
size_t tlsuv_BIO_available(tlsuv_BIO *bio);

#endif//TLSUV_BIO_H
