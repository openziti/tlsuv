//
// Created by Eugene Kobyakov on 7/24/24.
//

#ifndef TLSUV_KEYCHAIN_H
#define TLSUV_KEYCHAIN_H

#include <stddef.h>
#include <stdint.h>

enum keychain_key_type {
    keychain_key_invalid,
    keychain_key_ec,
    keychain_key_rsa,
};

typedef void* keychain_key_t;

// generic keychain API
typedef struct keychain_s keychain_t;
struct keychain_s {
    int (*gen_key)(keychain_key_t *pk, enum keychain_key_type type, const char *name);
    int (*load_key)(keychain_key_t*, const char *name);
    int (*rem_key)(const char *name);

    enum keychain_key_type (*key_type)(keychain_key_t k);
    int (*key_public)(keychain_key_t k, char *buf, size_t *len);
    int (*key_sign)(keychain_key_t k, const uint8_t * data, size_t datalen,
                    uint8_t *sig, size_t *siglen, int p);

    void (*free_key)(keychain_key_t k);
};

const keychain_t* tlsuv_keychain();
void tlsuv_set_keychain(keychain_t *);


#endif //TLSUV_KEYCHAIN_H
