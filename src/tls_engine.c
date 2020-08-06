#include <uv_mbed/tls_engine.h>
#include "um_debug.h"

/*
Copyright (c) 2020 NetFoundry, Inc.

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

#ifdef USE_MBEDTLS
extern tls_context* new_mbedtls_ctx(const char* ca, size_t ca_len);
static tls_context_factory factory = new_mbedtls_ctx;
#elif USE_OPENSSL
extern tls_context* new_openssl_ctx(const char* ca, size_t ca_len);
static tls_context_factory factory = new_openssl_ctx;
#else
static tls_context_factory factory = NULL;
#endif

void set_default_tls_impl(tls_context_factory f) {
    factory = f;
}

tls_context *default_tls_context(const char *ca, size_t ca_len) {
    if (factory == NULL) {
        UM_LOG(ERR, "FATAL error no default TLS engine is set");
        return NULL;
    }
    return factory(ca, ca_len);
}