
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "p11.h"
#include "um_debug.h"
#include "alloc.h"


#define P11(op) do {\
CK_RV rc; rc = (op); \
if (rc != CKR_OK) { \
            UM_LOG(WARN, "%s => %ld/%s", #op, (long)rc, p11_strerror(rc));\
            return (int)rc; \
   }\
} while(0)

#define set_attr_var(t, attr, val)                \
    do {                                          \
        t##temp[t##idx].type = (attr);            \
        t##temp[t##idx].pValue = &(val);          \
        t##temp[t##idx].ulValueLen = (CK_ULONG)sizeof(val); \
        (t##idx)++;                               \
    } while (0)

#define set_attr_ptr(t, attr, p)                 \
    do {                                         \
        if ((p) != NULL) {                       \
            t##temp[t##idx].type = (attr);       \
            t##temp[t##idx].pValue = (void*)(p);        \
            t##temp[t##idx].ulValueLen = (CK_ULONG)p##len; \
            t##idx++;                            \
        }                                        \
    } while (0)

static int p11_get_obj_attr(p11_context *p11, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE type, uint8_t **val, CK_ULONG *len);

int p11_init(p11_context *p11, const char *lib, const char *slot, const char *pin) {
    memset(p11, 0, sizeof(p11_context));

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
    CK_RV err = p11->funcs->C_Initialize(NULL);
    if (err != CKR_OK && err != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        return (int)err;
    }

    CK_SLOT_ID slot_id;
    if (slot == NULL || strcmp(slot, "") == 0) {
        CK_SLOT_ID_PTR slots;
        CK_ULONG slot_count;
        P11(p11->funcs->C_GetSlotList(CK_TRUE, NULL, &slot_count));
        slots = tlsuv__calloc(slot_count, sizeof(CK_SLOT_ID));
        P11(p11->funcs->C_GetSlotList(CK_TRUE, slots, &slot_count));
        slot_id = slots[0];
        /* WARNING: "slot id not specified. using the first slot[%lx] reported by driver", slot_id); */
        tlsuv__free(slots);
    }
    else {
        slot_id = strtoul(slot, NULL, 16);
    }
    p11->slot_id = slot_id;

    P11(p11->funcs->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &p11->session));
    err = p11->funcs->C_Login(p11->session, CKU_USER, (uint8_t *) pin, (CK_ULONG)strlen(pin));
    if (err != CKR_OK && err != CKR_USER_ALREADY_LOGGED_IN) {
        UM_LOG(WARN, "failed to login to pkcs#11 token: %lu/%s", err, p11_strerror(err));
        return (int)err;
    }

    return 0;
}

static const unsigned char * get_ec_params(int keysize, int *ec_params_len) {
    static unsigned char prime521v1[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x0, 0x23 };
    static unsigned char prime384v1[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
    static unsigned char prime256v1[] = { 0x06, 0x08, 0x2A, 0x86 , 0x48 , 0xCE , 0x3D, 0x03, 0x01, 0x07 };
    static unsigned char nistp244[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21 };
    static unsigned char prime192v1[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01 };

    if (keysize >= 521) {
        *ec_params_len = sizeof(prime521v1);
        return prime521v1;
    }

    if (keysize >= 384) {
        *ec_params_len = sizeof(prime384v1);
        return prime384v1;
    }

    if (keysize >= 256) {
        *ec_params_len = sizeof(prime256v1);
        return prime256v1;
    }
    if (keysize >= 244) {
        *ec_params_len = sizeof(nistp244);
        return nistp244;
    }
    if (keysize >= 192) {
        *ec_params_len = sizeof(prime192v1);
        return prime192v1;
    }
    return NULL;
}

int p11_gen_key(p11_context *p11, p11_key_ctx *p11_key, const char *label) {
    // in the preference order
    CK_MECHANISM_TYPE try_types[] = {
            CKM_EC_KEY_PAIR_GEN,
            CKM_RSA_PKCS_KEY_PAIR_GEN
    };

    CK_KEY_TYPE keytype = 0;
    CK_MECHANISM_INFO info;
    CK_MECHANISM mech = {0};
    CK_ULONG keysize = 0;
    CK_RV rv;
    for (int i = 0; i < sizeof(try_types)/sizeof(try_types[0]); i++) {
        rv = p11->funcs->C_GetMechanismInfo(p11->slot_id, try_types[0], &info);
        if (rv == CKR_OK && (info.flags & CKF_GENERATE_KEY_PAIR)) {
            mech.mechanism = try_types[i];
            keysize = info.ulMaxKeySize;
            switch (try_types[i]) {
                case CKM_RSA_PKCS_KEY_PAIR_GEN: keytype = CKK_RSA; break;
                case CKM_EC_KEY_PAIR_GEN: keytype = CKK_EC; break;
            }
            goto found;
        }
    }
    UM_LOG(WARN, "did not find suitable key generation mechanism");
    return -1;

    found:
    UM_LOG(DEBG, "found key generation mechanism[%lu] for key type[%lu] size[%ld]", mech.mechanism, keytype, keysize);

    int ecparamslen = 0;
    const unsigned char *ecparams;

    CK_BYTE id[8];
    int idlen = sizeof(id);
    p11->funcs->C_GenerateRandom(p11->session, id, sizeof(id));

    CK_BYTE rsaexp[] = { 1, 0, 1};
    int rsaexplen = sizeof(rsaexp);
    CK_BBOOL false_val = CK_FALSE;
    CK_BBOOL true_val = CK_TRUE;
    CK_OBJECT_CLASS pubcls = CKO_PUBLIC_KEY, privcls = CKO_PRIVATE_KEY;

    CK_ATTRIBUTE privtemp[20];
    int prividx = 0;
    set_attr_ptr(priv, CKA_ID, id);
    set_attr_var(priv, CKA_CLASS, privcls);
    set_attr_var(priv, CKA_KEY_TYPE, keytype);
    set_attr_var(priv, CKA_PRIVATE, true_val);
    set_attr_var(priv, CKA_TOKEN, true_val);
    set_attr_var(priv, CKA_SENSITIVE, true_val);
    set_attr_var(priv, CKA_DECRYPT, true_val);
    set_attr_var(priv, CKA_SIGN, true_val);
    set_attr_var(priv, CKA_UNWRAP, true_val);
    if (label) {
        size_t labellen = strlen(label);
        set_attr_ptr(priv, CKA_LABEL, label);
    }

    CK_ATTRIBUTE pubtemp[20];
    int pubidx = 0;
    set_attr_ptr(pub, CKA_ID, id);
    set_attr_var(pub, CKA_CLASS, pubcls);
    set_attr_var(pub, CKA_KEY_TYPE, keytype);
    set_attr_var(pub, CKA_TOKEN, true_val);
    set_attr_var(pub, CKA_ENCRYPT, true_val);
    set_attr_var(pub, CKA_VERIFY, true_val);
    set_attr_var(pub, CKA_WRAP, true_val);
    if (label) {
        size_t labellen = strlen(label);
        set_attr_ptr(pub, CKA_LABEL, label);
    }

    if (keytype == CKK_EC) {
        ecparams = get_ec_params((int)keysize, &ecparamslen);
        set_attr_ptr(pub, CKA_EC_PARAMS, ecparams);
    }

    if (keytype == CKK_RSA) {
        set_attr_var(pub, CKA_MODULUS_BITS, keysize);
        set_attr_ptr(pub, CKA_PUBLIC_EXPONENT, rsaexp);
    }

    CK_OBJECT_HANDLE pubh = 0, privh = 0;
    rv = p11->funcs->C_GenerateKeyPair(p11->session, &mech, pubtemp, pubidx, privtemp, prividx, &pubh, &privh);
    if (rv != CKR_OK) {
        UM_LOG(WARN, "failed to generate key pair mech[%ld], keytype[%ld], size[%ld]: %lu/%s", mech.mechanism, keytype, keysize, rv, p11_strerror(rv));
        return -1;
    }


    p11_key->ctx = p11;
    p11_key->priv_handle = privh;
    p11_key->pub_handle = pubh;
    p11_key->key_type = keytype;

    return 0;
}

int p11_store_key_cert(p11_key_ctx *key, char *cert, size_t certlen, char *subj, size_t subjlen) {
    p11_context *p11 = key->ctx;

    uint8_t *id = NULL;
    CK_ULONG idlen;
    p11_get_obj_attr(p11, key->priv_handle, CKA_ID, &id, &idlen);

    uint8_t *label = NULL;
    CK_ULONG labellen;
    p11_get_obj_attr(p11, key->priv_handle, CKA_LABEL, &label, &labellen);

    CK_OBJECT_CLASS cls = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
    CK_BBOOL private = CK_FALSE;
    CK_BBOOL store = CK_TRUE;

    CK_ATTRIBUTE certtemp[10];
    int certidx = 0;


    set_attr_var(cert, CKA_CLASS, cls);
    set_attr_var(cert, CKA_PRIVATE, private);
    set_attr_var(cert, CKA_TOKEN, store);
    set_attr_var(cert, CKA_CERTIFICATE_TYPE, cert_type);

    set_attr_ptr(cert, CKA_ID, id);
    set_attr_ptr(cert, CKA_LABEL, label);
    set_attr_ptr(cert, CKA_SUBJECT, subj);
    set_attr_ptr(cert, CKA_VALUE, cert);

    CK_OBJECT_HANDLE h;
    CK_RV rc = p11->funcs->C_CreateObject(p11->session, certtemp, certidx, &h);

    tlsuv__free(label);
    tlsuv__free(id);

    if (rc != CKR_OK) {
        UM_LOG(WARN, "failed to store cert to pkcs#11 token: %lu/%s", rc, p11_strerror(rc));
        return -1;
    }
    return 0;
}

int p11_get_key_cert(p11_key_ctx *key, char **val, size_t *len) {
    p11_context *p11 = key->ctx;
    CK_ULONG cls = CKO_CERTIFICATE;

    uint8_t *id = NULL;
    CK_ULONG idlen;
    p11_get_obj_attr(p11, key->priv_handle, CKA_ID, &id, &idlen);


    CK_ULONG qcount = 2;
    CK_ATTRIBUTE query[2];
    query[0].type = CKA_CLASS;
    query[0].pValue = &cls;
    query[0].ulValueLen = sizeof(cls);

    query[1].type = CKA_ID;
    query[1].pValue = id;
    query[1].ulValueLen = idlen;

    CK_ULONG objc;
    CK_OBJECT_HANDLE cert_handle;
    P11(p11->funcs->C_FindObjectsInit(p11->session, query, qcount));
    P11(p11->funcs->C_FindObjects(p11->session, &cert_handle, 1, &objc));
    P11(p11->funcs->C_FindObjectsFinal(p11->session));

    tlsuv__free(id);
    if (objc == 0) {
        UM_LOG(WARN, "certificate not found");
        *val = NULL;
        *len = 0;
        return -1;
    }

    CK_ULONG ck_len;
    int rc = p11_get_obj_attr(p11, cert_handle, CKA_VALUE, (uint8_t **)val, &ck_len);
    if (rc == 0) {
        *len = ck_len;
    }
    return rc;
}


int p11_get_key_attr(p11_key_ctx *key, CK_ATTRIBUTE_TYPE type, char **val, size_t *len) {
    CK_ULONG ck_len;
    int rc = p11_get_obj_attr(key->ctx, key->pub_handle, type, (uint8_t **)val, &ck_len);
    if (rc == 0) {
        *len = ck_len;
    }
    return rc;
}

static int p11_get_obj_attr(p11_context *p11, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE type, uint8_t **val, CK_ULONG *len) {

        // load public key
    CK_ATTRIBUTE attr[] = {
            {type, NULL, 0},
    };

    CK_RV rc = p11->funcs->C_GetAttributeValue(p11->session, h, attr, 1);
    if (rc != CKR_OK) {
        *val = NULL;
        *len = 0;
        return (int)rc;
    }

    *len = attr[0].ulValueLen;
    *val = tlsuv__calloc(1, *len + 1);

    attr[0].pValue = *val;
    rc = p11->funcs->C_GetAttributeValue(p11->session, h, attr, 1);
    if (rc != CKR_OK) {
        tlsuv__free(*val);
        *val = NULL;
        *len = 0;
        return (int)rc;
    }
    return 0;
}

int p11_load_key(p11_context *p11, p11_key_ctx *p11_key, const char *idstr, const char *label) {
    CK_ULONG cls = CKO_PRIVATE_KEY;
    char id[32];
    CK_ULONG idlen;

    CK_ULONG qcount = 1;
    CK_ATTRIBUTE query[3] = {
            {CKA_CLASS, &cls, sizeof(cls)}
    };

    if (idstr && strlen(idstr) > 0) {
        idlen = (CK_ULONG)(strlen(idstr) + 1) / 2;

        for (CK_ULONG idx = 0; idx < idlen; idx++) {
            sscanf(idstr + 2 * idx, "%2hhx", &id[idx]);
        }
        // parse id
        query[qcount].type = CKA_ID;
        query[qcount].pValue = id;
        query[qcount].ulValueLen = idlen;

        qcount++;
    } else if (label && strlen(label) > 0) {
        query[qcount].type = CKA_LABEL;
        query[qcount].pValue = (void*)label;
        query[qcount].ulValueLen = (CK_ULONG)strlen(label);

        qcount++;
    } else {
        UM_LOG(WARN, "cannot query private without id or label");
        return CKR_KEY_NEEDED;
    }

    CK_ULONG objc;
    P11(p11->funcs->C_FindObjectsInit(p11->session, query, qcount));
    P11(p11->funcs->C_FindObjects(p11->session, &p11_key->priv_handle, 1, &objc));
    P11(p11->funcs->C_FindObjectsFinal(p11->session));

    if (objc == 0) {
        UM_LOG(WARN, "key not found with following attributes: id[%s] label[%s]", idstr, label);
        return CKR_KEY_NEEDED;
    }

    cls = CKO_PUBLIC_KEY;
    P11(p11->funcs->C_FindObjectsInit(p11->session, query, qcount));
    P11(p11->funcs->C_FindObjects(p11->session, &p11_key->pub_handle, 1, &objc));
    P11(p11->funcs->C_FindObjectsFinal(p11->session));
    if (objc == 0) {
        return CKR_KEY_NEEDED;
    }

    CK_ATTRIBUTE attr = {CKA_KEY_TYPE, &p11_key->key_type, sizeof(p11_key->key_type)};

    P11(p11->funcs->C_GetAttributeValue(p11->session, p11_key->priv_handle, &attr, 1));
    p11_key->ctx = p11;
    return 0;
}

int p11_key_sign(p11_key_ctx *key, const uint8_t *digest, int digest_len, uint8_t *sig, size_t *siglen, CK_MECHANISM_TYPE padding) {
    p11_context *p11 = key->ctx;

    CK_MECHANISM mech = {0};
    switch (key->key_type) {
        case CKK_EC: mech.mechanism = CKM_ECDSA; break;
        case CKK_RSA: mech.mechanism = padding; break;
    }

    CK_RV rc = p11->funcs->C_SignInit(p11->session, &mech, key->priv_handle);
    if (rc != CKR_OK) {
        UM_LOG(WARN, "failed to init sign op: %s", p11_strerror(rc));
        return -1;
    }
    CK_ULONG ck_siglen = (CK_ULONG)*siglen;
    rc = p11->funcs->C_Sign(p11->session, (CK_BYTE_PTR)digest, digest_len, (CK_BYTE_PTR) sig, &ck_siglen);
    if (rc != CKR_OK) {
        UM_LOG(WARN, "failed to perform sign op: %s", p11_strerror(rc));
        return -1;
    }
    *siglen = ck_siglen;
    return 0;
}

void p11_key_free(p11_key_ctx *key) {
    if (key) {
        tlsuv__free(key->ctx);
        tlsuv__free(key);
    }
}

#define P11_ERRORS(XX) \
XX(CKR_OK) \
XX(CKR_CANCEL) \
XX(CKR_HOST_MEMORY) \
XX(CKR_SLOT_ID_INVALID) \
XX(CKR_GENERAL_ERROR) \
XX(CKR_FUNCTION_FAILED) \
XX(CKR_ARGUMENTS_BAD) \
XX(CKR_NO_EVENT) \
XX(CKR_NEED_TO_CREATE_THREADS) \
XX(CKR_CANT_LOCK) \
XX(CKR_ATTRIBUTE_READ_ONLY) \
XX(CKR_ATTRIBUTE_SENSITIVE) \
XX(CKR_ATTRIBUTE_TYPE_INVALID) \
XX(CKR_ATTRIBUTE_VALUE_INVALID) \
XX(CKR_ACTION_PROHIBITED) \
XX(CKR_DATA_INVALID) \
XX(CKR_DATA_LEN_RANGE) \
XX(CKR_DEVICE_ERROR) \
XX(CKR_DEVICE_MEMORY) \
XX(CKR_DEVICE_REMOVED) \
XX(CKR_ENCRYPTED_DATA_INVALID) \
XX(CKR_ENCRYPTED_DATA_LEN_RANGE) \
XX(CKR_FUNCTION_CANCELED) \
XX(CKR_FUNCTION_NOT_PARALLEL) \
XX(CKR_FUNCTION_NOT_SUPPORTED) \
XX(CKR_KEY_HANDLE_INVALID) \
XX(CKR_KEY_SIZE_RANGE) \
XX(CKR_KEY_TYPE_INCONSISTENT) \
XX(CKR_KEY_NOT_NEEDED) \
XX(CKR_KEY_CHANGED) \
XX(CKR_KEY_NEEDED) \
XX(CKR_KEY_INDIGESTIBLE) \
XX(CKR_KEY_FUNCTION_NOT_PERMITTED) \
XX(CKR_KEY_NOT_WRAPPABLE) \
XX(CKR_KEY_UNEXTRACTABLE) \
XX(CKR_MECHANISM_INVALID) \
XX(CKR_MECHANISM_PARAM_INVALID) \
XX(CKR_OBJECT_HANDLE_INVALID) \
XX(CKR_OPERATION_ACTIVE) \
XX(CKR_OPERATION_NOT_INITIALIZED) \
XX(CKR_PIN_INCORRECT) \
XX(CKR_PIN_INVALID) \
XX(CKR_PIN_LEN_RANGE) \
XX(CKR_PIN_EXPIRED) \
XX(CKR_PIN_LOCKED) \
XX(CKR_SESSION_CLOSED) \
XX(CKR_SESSION_COUNT) \
XX(CKR_SESSION_HANDLE_INVALID) \
XX(CKR_SESSION_PARALLEL_NOT_SUPPORTED) \
XX(CKR_SESSION_READ_ONLY) \
XX(CKR_SESSION_EXISTS) \
XX(CKR_SESSION_READ_ONLY_EXISTS) \
XX(CKR_SESSION_READ_WRITE_SO_EXISTS) \
XX(CKR_SIGNATURE_INVALID) \
XX(CKR_SIGNATURE_LEN_RANGE) \
XX(CKR_TEMPLATE_INCOMPLETE) \
XX(CKR_TEMPLATE_INCONSISTENT) \
XX(CKR_TOKEN_NOT_PRESENT) \
XX(CKR_TOKEN_NOT_RECOGNIZED) \
XX(CKR_TOKEN_WRITE_PROTECTED) \
XX(CKR_UNWRAPPING_KEY_HANDLE_INVALID) \
XX(CKR_UNWRAPPING_KEY_SIZE_RANGE) \
XX(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT) \
XX(CKR_USER_ALREADY_LOGGED_IN) \
XX(CKR_USER_NOT_LOGGED_IN) \
XX(CKR_USER_PIN_NOT_INITIALIZED) \
XX(CKR_USER_TYPE_INVALID) \
XX(CKR_USER_ANOTHER_ALREADY_LOGGED_IN) \
XX(CKR_USER_TOO_MANY_TYPES) \
XX(CKR_WRAPPED_KEY_INVALID) \
XX(CKR_WRAPPED_KEY_LEN_RANGE) \
XX(CKR_WRAPPING_KEY_HANDLE_INVALID) \
XX(CKR_WRAPPING_KEY_SIZE_RANGE) \
XX(CKR_WRAPPING_KEY_TYPE_INCONSISTENT) \
XX(CKR_RANDOM_SEED_NOT_SUPPORTED) \
XX(CKR_RANDOM_NO_RNG) \
XX(CKR_DOMAIN_PARAMS_INVALID) \
XX(CKR_CURVE_NOT_SUPPORTED) \
XX(CKR_BUFFER_TOO_SMALL) \
XX(CKR_SAVED_STATE_INVALID) \
XX(CKR_INFORMATION_SENSITIVE) \
XX(CKR_STATE_UNSAVEABLE) \
XX(CKR_CRYPTOKI_NOT_INITIALIZED) \
XX(CKR_CRYPTOKI_ALREADY_INITIALIZED) \
XX(CKR_MUTEX_BAD) \
XX(CKR_MUTEX_NOT_LOCKED) \
XX(CKR_NEW_PIN_MODE) \
XX(CKR_NEXT_OTP) \
XX(CKR_EXCEEDED_MAX_ITERATIONS) \
XX(CKR_FIPS_SELF_TEST_FAILED) \
XX(CKR_LIBRARY_LOAD_FAILED) \
XX(CKR_PIN_TOO_WEAK) \
XX(CKR_PUBLIC_KEY_INVALID) \
XX(CKR_FUNCTION_REJECTED) \
XX(CKR_VENDOR_DEFINED)

const char *p11_strerror(CK_RV rv) {
#define ERR_CASE(e) case e: return #e;
    switch (rv) {
        P11_ERRORS(ERR_CASE)

        default:
            return "Unexpected Error";
    }
}
