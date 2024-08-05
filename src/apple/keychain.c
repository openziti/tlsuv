
#include <security/SecKey.h>
#include <security/Security.h>

#include "../keychain.h"
#include "um_debug.h"

static SecKeyRef find_private_key(const char *name, OSStatus *code);

static const char* keychain_strerror(OSStatus s) {
    static char err[1024];
    CFStringRef e = SecCopyErrorMessageString(s, NULL);
    if (e == NULL) {
        snprintf(err, sizeof(err), "unknown error code[%d]", s);
    } else {
        const char *str = CFStringGetCStringPtr(e, kCFStringEncodingUTF8);
        if (str) {
            snprintf(err, sizeof(err), "%s", str);
        } else if (!CFStringGetCString(e, err, sizeof(err), kCFStringEncodingUTF8)) {
            snprintf(err, sizeof(err), "<could not extract error message>");
        }
        CFRelease(e);
    }
    return err;
}

static const char* keychain_errmsg(CFErrorRef err) {
    static char msg[1024];
    if (err == NULL) return "OK";

    CFStringRef desc = CFErrorCopyDescription(err);
    const char *str = CFStringGetCStringPtr(desc, kCFStringEncodingUTF8);
    if (str) {
        snprintf(msg, sizeof(msg), "%s", str);
    } else if (!CFStringGetCString(desc, msg, sizeof(msg), kCFStringEncodingUTF8)) {
        snprintf(msg, sizeof(msg), "<could not extract error message>");
    }
    CFRelease(desc);
    return msg;
}

static int gen_key(keychain_key_t *pk, enum keychain_key_type type, const char *name) {
    SecKeyRef existing = find_private_key(name, NULL);
    if (existing != NULL) {
        UM_LOG(WARN, "key[%s] already exists", name);
        CFRelease(existing);
        return EEXIST;
    }

    UM_LOG(DEBG, "generating key[%s]", name);
    static int32_t ec_size = 521;
    static int rsa_size = 4096;

    CFNumberRef bits = NULL;
    CFStringRef cf_key_type = NULL;
    if (type == keychain_key_ec) {
        bits = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &ec_size);
        cf_key_type = kSecAttrKeyTypeECSECPrimeRandom;
    } else if (type == keychain_key_rsa) {
        bits = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &rsa_size);
        cf_key_type = kSecAttrKeyTypeRSA;
    } else {
        return EINVAL;
    }
    
    CFDataRef tag = CFDataCreate(kCFAllocatorDefault, (const uint8_t *)name, (CFIndex) strlen(name));
    CFStringRef label = CFStringCreateWithCString(kCFAllocatorDefault, name, kCFStringEncodingUTF8);
    
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
    CFDictionaryAddValue(params, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionaryAddValue(params, kSecReturnRef, kCFBooleanTrue);
    CFDictionaryAddValue(params, kSecAttrApplicationTag, tag);
    CFDictionaryAddValue(params, kSecAttrLabel, label);
    CFDictionaryAddValue(params, kSecAttrIsExtractable, kCFBooleanFalse);
    CFDictionaryAddValue(params, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionaryAddValue(params, kSecAttrKeyType, cf_key_type);
    CFDictionaryAddValue(params, kSecAttrKeySizeInBits, bits);

    CFErrorRef error = NULL;
    SecKeyRef key = SecKeyCreateRandomKey(params, &error);
    SecKeyRef pub = SecKeyCopyPublicKey(key);

    // store public key back so that pubkey data can be loaded after
    // https://forums.developer.apple.com/forums/thread/8030
    CFMutableDictionaryRef pubparams = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
    CFDictionaryAddValue(pubparams, kSecAttrApplicationTag, tag);
    CFDictionaryAddValue(pubparams, kSecAttrLabel, label);
    CFDictionarySetValue(pubparams, kSecAttrIsExtractable, kCFBooleanTrue);
    CFDictionaryAddValue(pubparams, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(pubparams, kSecValueRef, pub);

    OSStatus pubadd = SecItemAdd(pubparams, NULL);
    if (pubadd != errSecSuccess) {
        UM_LOG(WARN, "failed to store pubkey to keychain: %s", keychain_strerror(pubadd));
    }

    CFRelease(pubparams);
    CFRelease(pub);
    CFRelease(params);
    CFRelease(tag);
    CFRelease(label);
    
    if (key == NULL) {
        return (int)CFErrorGetCode(error);
    }

    *pk = key;
    return 0;
}

static int key_size(keychain_key_t k) {
    SecKeyRef key = k;
    CFDictionaryRef atts = SecKeyCopyAttributes(key);
    CFNumberRef num = CFDictionaryGetValue(atts, kSecAttrKeySizeInBits);
    int val = 0;
    CFNumberGetValue(num, kCFNumberNSIntegerType, &val);
    CFRelease(num);
    CFRelease(atts);
    return val;
}

static enum keychain_key_type key_type(keychain_key_t k) {
    SecKeyRef key = k;
    CFDictionaryRef atts = SecKeyCopyAttributes(key);
    const void *t = CFDictionaryGetValue(atts, kSecAttrKeyType);

    CFRelease(atts);
    
    if (t == kSecAttrKeyTypeEC) {
        return keychain_key_ec;
    }

    if (t == kSecAttrKeyTypeRSA) {
        return keychain_key_rsa;
    }

    return keychain_key_invalid;
}

static int key_public(keychain_key_t k, char *buf, size_t *len) {
    UM_LOG(ERR, "getting public");
    SecKeyRef key = k;
    SecKeyRef pub = SecKeyCopyPublicKey(key);
    if (pub == NULL) {
        UM_LOG(WARN, "failed to retrieve public key: not available");
        return -1;
    }

    CFErrorRef err = NULL;
    CFDataRef d = SecKeyCopyExternalRepresentation(pub, &err);
    if (err != NULL) {
        UM_LOG(ERR, "failed to retrieve public key: %s", keychain_errmsg(err));
        CFRelease(pub);
        return (int)CFErrorGetCode(err);
    }

    CFIndex publen = CFDataGetLength(d);
    assert (publen <= *len);

    *len = publen;
    memcpy(buf, CFDataGetBytePtr(d), publen);

    CFRelease(d);
    CFRelease(pub);

    return 0;
}

static int key_sign(keychain_key_t k,
                    const uint8_t * data, size_t datalen,
                    uint8_t *sig, size_t *siglen, int p) {
    UM_LOG(DEBG, "signing");
    SecKeyRef key = k;
    CFErrorRef err = NULL;
    SecKeyAlgorithm algorithm;

    switch (key_type(k)) {
        case keychain_key_ec:
            algorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
            break;
        case keychain_key_rsa:
            if (p == 1) { // RSA_PKCS1_PADDING
                algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw;
            } else if (p == 3) { // RSA_NO_PADDING
                algorithm = kSecKeyAlgorithmRSASignatureRaw;
            }
            break;
        default:
            UM_LOG(ERR, "unsupported key type");
            return EINVAL;
    };

    CFDataRef d = CFDataCreate(kCFAllocatorDefault, data, (CFIndex)datalen);
    CFDataRef signature = SecKeyCreateSignature(
            key, algorithm,
            d, &err);
    CFRelease(d);

    if (signature) {
        CFIndex len = CFDataGetLength(signature);
        CFDataGetBytes(signature, CFRangeMake(0, len), sig);
        *siglen = (size_t)len;
        CFRelease(signature);
        return 0;
    }

    UM_LOG(WARN, "failed to sign data: %s", keychain_errmsg(err));
    return (int) CFErrorGetCode(err);
}

static void free_key(keychain_key_t k) {
    if (k != NULL) {
        SecKeyRef key = k;
        CFRelease(key);
    }
}

static int rem_key(const char *name) {
    UM_LOG(INFO, "removing key %s", name);
    CFDataRef tag = CFDataCreate(kCFAllocatorDefault, (const uint8_t *)name, (CFIndex) strlen(name));

    CFMutableDictionaryRef dq = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
    CFDictionaryAddValue(dq, kSecClass, kSecClassKey);
    CFDictionaryAddValue(dq, kSecAttrApplicationTag, tag);
    CFDictionaryAddValue(dq, kSecMatchLimit, kSecMatchLimitAll);

    OSStatus r = SecItemDelete(dq);

    CFRelease(dq);
    CFRelease(tag);
    if (r != errSecSuccess) {
        UM_LOG(WARN, "failed to remove key: %s", keychain_strerror(r));
        return -1;
    }
    return 0;
}

static SecKeyRef find_private_key(const char *name, OSStatus *code) {
    CFDataRef tag = CFDataCreate(kCFAllocatorDefault, (const uint8_t *)name, (CFIndex) strlen(name));

    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
    CFDictionaryAddValue(q, kSecClass, kSecClassKey);
    CFDictionaryAddValue(q, kSecAttrApplicationTag, tag);
    CFDictionaryAddValue(q, kSecReturnRef, kCFBooleanTrue);
    CFDictionaryAddValue(q, kSecAttrKeyClass, kSecAttrKeyClassPrivate);

    CFTypeRef ref = NULL;
    OSStatus r = SecItemCopyMatching(q, &ref);
    CFRelease(q);
    CFRelease(tag);

    if (code) *code = r;

    if (r == errSecSuccess) {
        assert(ref != NULL);
        assert(CFGetTypeID(ref) == SecKeyGetTypeID());
        return (SecKeyRef)ref;
    }
    
    return NULL;
}

static int load_key(keychain_key_t *k, const char *name) {
    UM_LOG(INFO, "loading key %s", name);

    OSStatus r;
    SecKeyRef key = find_private_key(name, &r);

    if (k != NULL) {
        *k = (keychain_key_t) key;
    }
    if (r != errSecSuccess) {
        UM_LOG(ERR, "failed to load key[%s]: %s", name, keychain_strerror(r));
        return ENOENT;
    }
    return 0;
}

static keychain_t apple_keychain = {
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
    return &apple_keychain;
}
