// Copyright (c) 2025. NetFoundry Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
//         https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//


#ifndef TLSUV_CERT_H
#define TLSUV_CERT_H

#include <tlsuv/tls_engine.h>
#include <wincrypt.h>

typedef struct win32_cert {
    struct tlsuv_certificate_s api;
    HCERTSTORE store;
} win32_cert_t;

extern win32_cert_t *win32_new_cert(HCERTSTORE);

const char* win32_error(DWORD code);

#endif //TLSUV_CERT_H
