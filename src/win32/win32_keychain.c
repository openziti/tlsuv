// Copyright (c) 2024. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <tlsuv/keychain.h>
#include <util.h>

#include <ncrypt.h>
#include "../um_debug.h"
#include "../alloc.h"

#if USE_OPENSSL
#include <openssl/ecdsa.h>
#endif

static NCRYPT_PROV_HANDLE provider = 0;

static const char* win32_error(DWORD code) {
    static char msg[1024];

    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)msg, sizeof(msg), NULL);
    return msg;
}

static BOOL do_init(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    static const LPWSTR preferred[] = {
            MS_PLATFORM_CRYPTO_PROVIDER,
            MS_KEY_STORAGE_PROVIDER,
    };

    NTSTATUS rc;
    for (int i = 0; i < sizeof(preferred)/sizeof(preferred[0]); i++) {
        rc = NCryptOpenStorageProvider(&provider, preferred[i], 0);
        if (rc == ERROR_SUCCESS) {
            break;
        }
    }

    if (rc != ERROR_SUCCESS) {
        UM_LOG(ERR, "failed to initialize Windows keychain: %s", win32_error(rc));
        return FALSE;
    }

    wchar_t name[1024];
    DWORD nlen;
    DWORD type = 0;
    DWORD size = sizeof(type);
    NCryptGetProperty(provider, NCRYPT_NAME_PROPERTY, (PBYTE)name, sizeof(name), &nlen, 0);
    NCryptGetProperty(provider, NCRYPT_IMPL_TYPE_PROPERTY, (PBYTE)&type, size, &size, 0);

    UM_LOG(INFO, "initialized keychain[%ls] %s hardware support",
           name, type & NCRYPT_IMPL_HARDWARE_FLAG ? "with" : "without");
    return TRUE;
}

static void init() {
    static INIT_ONCE s_init = INIT_ONCE_STATIC_INIT;
    InitOnceExecuteOnce(&s_init, do_init, NULL, NULL);
}

static wchar_t* name_to_wchar(const char *name) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, name, (int) strlen(name), NULL, 0);
    wchar_t *wname = tlsuv__calloc(wlen, sizeof(wchar_t) + 1);
    MultiByteToWideChar(CP_UTF8, 0, name, (int)strlen(name), wname, wlen);
    return wname;
}

static int gen_key(keychain_key_t *key, enum keychain_key_type type, const char *name){
    init();
    static wchar_t *algos[] = {
            NCRYPT_ECDSA_P384_ALGORITHM,
            NCRYPT_ECDSA_P256_ALGORITHM,
    };

    if (type != keychain_key_ec) {
        UM_LOG(ERR, "unsupported key type: %d", type);
        return -1;
    }

    wchar_t *wname = name_to_wchar(name);
    int res = -1;

    NCRYPT_KEY_HANDLE h = 0;
    wchar_t *algo = NULL;
    for (int i = 0; i < sizeof(algos)/sizeof(algos[0]); i++) {
        if (NCryptIsAlgSupported(provider, algos[i], 0) == ERROR_SUCCESS) {
            algo = algos[i];
            break;
        }
    }
    UM_LOG(DEBG, "generating key with algo[%ls]", algo);
    SECURITY_STATUS rc = NCryptCreatePersistedKey(provider, &h, algo, wname, 0, 0);

    if (rc != ERROR_SUCCESS) {
        UM_LOG(ERR, "failed to generate key[%ls]: %s", wname, win32_error(rc));
        goto done;
    }
    rc = NCryptFinalizeKey(h, 0);
    if (rc != ERROR_SUCCESS) {
        UM_LOG(ERR, "failed to generate key[%ls]: %s", wname, win32_error(rc));
        goto done;
    }

    *key = (keychain_key_t) h;
    res = 0;

    done:
    tlsuv__free(wname);
    return res;
}

static int load_key(keychain_key_t *k, const char *name) {
    init();
    wchar_t *wname = name_to_wchar(name);

    NCRYPT_KEY_HANDLE keyh = 0;
    SECURITY_STATUS rc = NCryptOpenKey(provider, &keyh, wname, 0, 0);

    tlsuv__free(wname);
    
    if (rc == ERROR_SUCCESS) {
        *k = (keychain_key_t) keyh;
        return 0;
    }
    
    UM_LOG(ERR, "failed to load key[%s]: %s", name, win32_error(rc));

    return -1;
}

static void free_key(keychain_key_t key){
    NCRYPT_KEY_HANDLE h = (NCRYPT_KEY_HANDLE) key;
    if (NCryptIsKeyHandle(h)) {
        NCryptFreeObject(h);
    }
}

static int rem_key(const char *name){
    init();

    wchar_t *wname = name_to_wchar(name);
    int res = 0;

    NCRYPT_KEY_HANDLE keyh = 0;
    SECURITY_STATUS rc = NCryptOpenKey(provider, &keyh, wname, 0, 0);

    if (rc == ERROR_SUCCESS) {
        rc = NCryptDeleteKey(keyh, 0);
        if (rc != ERROR_SUCCESS) {
            UM_LOG(WARN, "failed to delete key[%s]: %s", name, win32_error(rc));
            res = -1;
        }
    } else {
        UM_LOG(WARN, "failed to open key[%s]: %s", name, win32_error(rc));
    }

    return res;
}

static enum keychain_key_type key_type(keychain_key_t key){

    NCRYPT_KEY_HANDLE h = (NCRYPT_KEY_HANDLE) key;
    wchar_t buf[16];
    DWORD len;

    SECURITY_STATUS rc = NCryptGetProperty(h, NCRYPT_ALGORITHM_GROUP_PROPERTY, (PBYTE)buf, sizeof(buf), &len, 0);
    if (rc == ERROR_SUCCESS) {
        if (wcscmp(NCRYPT_RSA_ALGORITHM_GROUP, buf) == 0) {
            return keychain_key_rsa;
        }

        if (wcscmp(NCRYPT_ECDSA_ALGORITHM_GROUP, buf) == 0) {
            return keychain_key_ec;
        }
    }
    return keychain_key_invalid;
}

static int key_size(keychain_key_t key){
    NCRYPT_KEY_HANDLE h = (NCRYPT_KEY_HANDLE) key;
    DWORD bits = 0;
    DWORD len;
    SECURITY_STATUS rc = NCryptGetProperty(h, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof(bits), &len, 0);
    if (rc == ERROR_SUCCESS && bits > 0) {
        return (int)bits;
    }

    NCRYPT_SUPPORTED_LENGTHS lengths;
    rc = NCryptGetProperty(h, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&lengths, sizeof(lengths), &len, 0);
    if (rc == ERROR_SUCCESS) {
        return (int)lengths.dwDefaultLength;
    }

    return -1;
}
static int key_public(keychain_key_t key, char *pub, size_t *publen){
    NCRYPT_KEY_HANDLE h = (NCRYPT_KEY_HANDLE) key;
    int res = -1;
    DWORD len = 0;
    uint8_t blob[8 * 1024];

    SECURITY_STATUS rc = NCryptExportKey(h, (NCRYPT_KEY_HANDLE) NULL, BCRYPT_PUBLIC_KEY_BLOB, NULL,
                                         blob, sizeof(blob), &len, 0);
    if (rc != ERROR_SUCCESS) {
        return -1;
    }

    BCRYPT_KEY_BLOB *keyBlob = (BCRYPT_KEY_BLOB *) blob;
    switch (keyBlob->Magic) {
        case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P521_MAGIC: {
            BCRYPT_ECCKEY_BLOB *eccBlob = (BCRYPT_ECCKEY_BLOB *) keyBlob;
            size_t keylen = 2 * eccBlob->cbKey;
            pub[0] = 0x4; // uncompressed form
            memcpy(pub + 1, blob + sizeof(BCRYPT_ECCKEY_BLOB), keylen);
            *publen = keylen + 1;
            res = 0;
            break;
        }
        default:
            break;
    }
    return res;
}

static int key_sign(keychain_key_t key, const uint8_t *d, size_t dl, uint8_t *sig, size_t *siglen, int opt){
#if USE_OPENSSL
    UM_LOG(DEBG, "signing %zd bytes", dl);
    NCRYPT_KEY_HANDLE h = (NCRYPT_KEY_HANDLE) key;
    uint8_t sigbuf[512];
    ULONG sl = sizeof(sigbuf);
    SECURITY_STATUS rc = NCryptSignHash(h, NULL, (uint8_t *) d, (DWORD) dl, sigbuf, sl, &sl, 0);
    if (rc != ERROR_SUCCESS) {
        UM_LOG(ERR, "failed to sign: %s", win32_error(rc));
        return -1;
    }

    BIGNUM *r = BN_bin2bn(sigbuf, (int)sl/2, NULL);
    BIGNUM *s = BN_bin2bn(sigbuf + sl/2, (int)sl/2, NULL);
    ECDSA_SIG *ecdsa = ECDSA_SIG_new();
    ECDSA_SIG_set0(ecdsa, r, s);

    uint8_t *p = sig;
    *siglen = i2d_ECDSA_SIG(ecdsa, &p);
    ECDSA_SIG_free(ecdsa);
    return 0;
#else
    UM_LOG(ERR, "should not be here: keychain is only supported with OpenSSL");
    return -1;
#endif
}


static keychain_t win32_keychain = {
        .gen_key = gen_key,
        .load_key = load_key,
        .free_key = free_key,
        .rem_key = rem_key,
        .key_type = key_type,
        .key_bits = key_size,
        .key_public = key_public,
        .key_sign = key_sign,
};

keychain_t* platform_keychain() {
    return &win32_keychain;
}