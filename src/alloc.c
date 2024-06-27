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

#include <uv.h>
#include <malloc.h>

struct allocator_t {
    uv_malloc_func malloc_f;
    uv_realloc_func realloc_f;
    uv_calloc_func calloc_f;
    uv_free_func free_f;
};

static struct allocator_t ALLOC = {
        .malloc_f = malloc,
        .realloc_f = realloc,
        .calloc_f = calloc,
        .free_f = free,
};


#if USE_OPENSSL
#include <openssl/crypto.h>
#include <string.h>
#include <assert.h>

static void * crypto_malloc(size_t num, const char *file, int line) {
    return ALLOC.malloc_f(num);
}

static void * crypto_realloc(void *addr, size_t num, const char *file, int line) {
    return ALLOC.realloc_f(addr, num);
}

static void crypto_free(void *addr, const char *file, int line) {
    ALLOC.free_f(addr);
}
#endif

#if USE_MBEDTLS
#include <mbedtls/platform.h>
#endif

void tlsuv_set_allocator(uv_malloc_func malloc_f,
                         uv_realloc_func realloc_f,
                         uv_calloc_func calloc_f,
                         uv_free_func free_f) {

    ALLOC.malloc_f = malloc_f;
    ALLOC.realloc_f = realloc_f;
    ALLOC.calloc_f = calloc_f;
    ALLOC.free_f = free_f;

    uv_replace_allocator(malloc_f, realloc_f, calloc_f, free_f);
#if USE_OPENSSL
    CRYPTO_set_mem_functions(crypto_malloc, crypto_realloc, crypto_free);
#endif

#if USE_MBEDTLS && defined(MBEDTLS_PLATFORM_MEMORY)
#if !defined(MBEDTLS_PLATFORM_CALLOC_MACRO)
    mbedtls_platform_set_calloc_free(calloc_f, free_f);
#endif
#endif
}


void *tlsuv__malloc(size_t size) {
    return ALLOC.malloc_f(size);
}

void *tlsuv__calloc(size_t n, size_t size) {
    return ALLOC.calloc_f(n, size);
}

void *tlsuv__realloc(void *addr, size_t size) {
    return ALLOC.realloc_f(addr, size);
}

void tlsuv__free(void *addr) {
    return ALLOC.free_f(addr);
}

extern char* tlsuv__strndup(const char* s, size_t len) {
    assert(s != NULL);
    char *r = malloc(len + 1);
    memcpy(r, s, len);
    r[len] = 0;
    return r;
}

char* tlsuv__strdup(const char *s) {
    assert(s != NULL);
    return tlsuv__strndup(s, strlen(s));
}

