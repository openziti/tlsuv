/*
Copyright 2019 NetFoundry, Inc.

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

#include "mbed_p11.h"
#include "p11_errors.h"

#if _WIN32
#define strncasecmp _strnicmp
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define P11(op) do {\
int rc; rc = (op); \
if (rc != CKR_OK) return rc; \
} while(0)


static int p11_getopt(const char *q, const char *opt, char *out, size_t maxout);

static int mp11_init(mp11_context *p11, const char *lib, const char *slot, const char *pin);

static int mp11_get_key(mbedtls_pk_context *key, mp11_context *ctx, const char *id);

static mp11_context CTX;

int mp11_load_key(mbedtls_pk_context *key,
        const char *path, const char *pin, const char *slot,
        const char *key_id) {
    int rc;

    if (CTX.lib == NULL) {
        rc = mp11_init(&CTX, path, slot, pin);
        if (rc != 0) {
            return rc;
        }
    }

    rc = mp11_get_key(key, &CTX, key_id);
    return rc;
}

static int mp11_get_key(mbedtls_pk_context *key, mp11_context *ctx, const char *idstr) {
    mp11_key_ctx *p11_key = calloc(1, sizeof(mp11_key_ctx));

    CK_ULONG cls = CKO_PRIVATE_KEY;
    char id[32];
    CK_ULONG idlen;

    CK_ULONG qcount = 1;
    CK_ATTRIBUTE query[3] = {
            {CKA_CLASS, &cls, sizeof(cls)}
    };

    if (idstr == NULL) {
        return CKR_KEY_NEEDED;
    }
    if (strcmp(idstr, "") != 0) {
        idlen = (strlen(idstr) + 1) / 2;

        for (int idx = 0; idx < idlen; idx++) {
            sscanf(idstr + 2 * idx, "%2hhx", &id[idx]);
        }
        // parse id
        query[qcount].type = CKA_ID;
        query[qcount].pValue = id;
        query[qcount].ulValueLen = idlen;

        qcount++;
    }

    CK_ULONG objc;
    P11(ctx->funcs->C_FindObjectsInit(ctx->session, query, qcount));
    P11(ctx->funcs->C_FindObjects(ctx->session, &p11_key->priv_handle, 1, &objc));
    P11(ctx->funcs->C_FindObjectsFinal(ctx->session));

    if (objc == 0) {
        return CKR_KEY_NEEDED;
    }

    cls = CKO_PUBLIC_KEY;
    P11(ctx->funcs->C_FindObjectsInit(ctx->session, query, qcount));
    P11(ctx->funcs->C_FindObjects(ctx->session, &p11_key->pub_handle, 1, &objc));
    P11(ctx->funcs->C_FindObjectsFinal(ctx->session));
    if (objc == 0) {
        return CKR_KEY_NEEDED;
    }

    CK_ULONG key_type;
    CK_ATTRIBUTE attr = {CKA_KEY_TYPE, &key_type, sizeof(key_type)};

    P11(ctx->funcs->C_GetAttributeValue(ctx->session, p11_key->priv_handle, &attr, 1));

    switch (key_type) {
        case CKK_ECDSA:
        P11(p11_load_ecdsa(key, p11_key, &CTX));
            break;

        case CKK_RSA:
        P11(p11_load_rsa(key, p11_key, &CTX));
            break;

        default: {
            return CKR_KEY_HANDLE_INVALID;
        }
    }

    return 0;
}


static int mp11_init(mp11_context *p11, const char *lib, const char *slot, const char *pin) {
    memset(p11, 0, sizeof(mp11_context));

    CK_C_GetFunctionList f;
    
#if _WIN32
    P11( (p11->lib = LoadLibrary(lib)) != NULL ? CKR_OK : CKR_LIBRARY_LOAD_FAILED);
    P11( (f = (CK_C_GetFunctionList)GetProcAddress(p11->lib, "C_GetFunctionList")) != NULL ? CKR_OK : CKR_LIBRARY_LOAD_FAILED);
#else
    p11->lib = (CK_C_GetFunctionList)dlopen(lib, RTLD_LAZY);
    if (p11->lib == NULL) {
        return CKR_FUNCTION_FAILED;
    }
    P11( (f = dlsym(p11->lib, "C_GetFunctionList")) != NULL ? CKR_OK : CKR_LIBRARY_LOAD_FAILED);
#endif

    P11(f(&p11->funcs));
    P11(p11->funcs->C_Initialize(NULL));

    CK_SLOT_ID slot_id;
    if (slot == NULL || strcmp(slot, "") == 0) {
        CK_SLOT_ID_PTR slots;
        CK_ULONG slot_count;
        P11(p11->funcs->C_GetSlotList(CK_TRUE, NULL, &slot_count));
        slots = calloc(slot_count, sizeof(CK_SLOT_ID));
        P11(p11->funcs->C_GetSlotList(CK_TRUE, slots, &slot_count));
        slot_id = slots[0];
        /* WARNING: "slot id not specified. using the first slot[%lx] reported by driver", slot_id); */
        free(slots);
    }
    else {
        slot_id = strtoul(slot, NULL, 16);
    }
    p11->slot_id = slot_id;

    P11(p11->funcs->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &p11->session));
    P11(p11->funcs->C_Login(p11->session, CKU_USER, (uint8_t *) pin, strlen(pin)));

    return 0;
}

const char *p11_strerror(CK_RV rv) {
#define ERR_CASE(e) case e: return #e;
    switch (rv) {
        P11_ERRORS(ERR_CASE)

        default:
            return "Unexpected Error";
    }
}
