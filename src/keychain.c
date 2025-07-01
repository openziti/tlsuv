//
// 	Copyright NetFoundry Inc.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

#include <uv.h>
#include <assert.h>
#include "keychain.h"

#if defined(__APPLE__) || _WIN32
extern keychain_t* platform_keychain();
#endif

static keychain_t *KEYCHAIN;
static uv_once_t init_guard;

static void init(void) {
#if defined(__APPLE__) || _WIN32
    tlsuv_set_keychain(platform_keychain());
#endif
}

const keychain_t* tlsuv_keychain() {
    uv_once(&init_guard, init);
    return KEYCHAIN;
}
void tlsuv_set_keychain(keychain_t *kc) {
    assert(KEYCHAIN == NULL);
    KEYCHAIN = kc;
}

int keychain_gen_key(keychain_key_t *pk, enum keychain_key_type type, const char *name) {
    if (tlsuv_keychain() == NULL) return -1;
    return tlsuv_keychain()->gen_key(pk, type, name);
}
int keychain_load_key(keychain_key_t *pk, const char *name) {
    if (tlsuv_keychain() == NULL) return -1;
    return tlsuv_keychain()->load_key(pk, name);
}
int keychain_rem_key(const char *name) {
    if (tlsuv_keychain() == NULL) return -1;
    return tlsuv_keychain()->rem_key(name);
}
enum keychain_key_type keychain_key_type(keychain_key_t k) {
    if (tlsuv_keychain() == NULL) return keychain_key_invalid;
    return tlsuv_keychain()->key_type(k);
}
int keychain_key_public(keychain_key_t k, char *buf, size_t *len) {
    if (tlsuv_keychain() == NULL) return -1;
    return tlsuv_keychain()->key_public(k, buf, len);
}
int keychain_key_sign(keychain_key_t k, const uint8_t * data, size_t datalen,
                      uint8_t *sig, size_t *siglen, int p) {
    if (tlsuv_keychain() == NULL) return -1;
    return tlsuv_keychain()->key_sign(k, data, datalen, sig, siglen, p);
}
void keychain_free_key(keychain_key_t k) {
    if (tlsuv_keychain() == NULL) return;
    tlsuv_keychain()->free_key(k);
}
