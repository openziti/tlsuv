
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

#ifndef TLSUV_P11_H
#define TLSUV_P11_H

#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name)  returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#else
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name)  returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#endif

#include "pkcs11/pkcs11.h"
#include <stddef.h>

struct p11_context_s {
    void *lib;
    CK_FUNCTION_LIST *funcs;
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id;
};

struct p11_key_ctx_s {
    CK_ULONG key_type;
    CK_OBJECT_HANDLE priv_handle;
    CK_OBJECT_HANDLE pub_handle;
    CK_MECHANISM_TYPE sign_mechanism;

    struct p11_context_s *ctx;
    void *pub; // mbedtls_rsa_context or mbedtls_ecdsa_context
};

typedef struct p11_context_s p11_context;
typedef struct p11_key_ctx_s p11_key_ctx;

int p11_init(p11_context *p11, const char *lib, const char *slot, const char *pin);
int p11_load_key(p11_context *p11, p11_key_ctx *p11_key, const char *id, const char *label);
int p11_get_key_attr(p11_key_ctx *key, CK_ATTRIBUTE_TYPE type, char **val, size_t *len);
void p11_key_free(p11_key_ctx *key);
const char *p11_strerror(CK_RV rv);


#ifdef __cplusplus
}
#endif
#endif//TLSUV_P11_H
