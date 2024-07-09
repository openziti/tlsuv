
#include <security/SecKeychain.h>
#include <security/SecKey.h>
#include <security/Security.h>

#include "../keychain.h"
#include "um_debug.h"

const char* keychain_strerror(OSStatus s) {
    static char err[1024];
    CFStringRef e = SecCopyErrorMessageString(s, NULL);
    CFStringGetCString(e, err, sizeof(err), kCFStringEncodingUTF8);
    CFRelease(e);
    return err;
}

const char* keychain_errmsg(CFErrorRef err) {
    static char msg[1024];
    if (err == NULL) return "OK";

    CFStringRef desc = CFErrorCopyDescription(err);
    CFStringGetCString(desc, msg, sizeof(msg), kCFStringEncodingUTF8);
    CFRelease(desc);
    return msg;
}

int keychain_gen_key(keychain_key_t *pk, enum keychain_key_type type, const char *name) {
    static int32_t ec_size = 256;
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
        return -1;
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

    CFRelease(params);
    CFRelease(tag);
    CFRelease(label);
    
    if (key == NULL) {
        return (int)CFErrorGetCode(error);
    }

    *pk = key;
    return 0;
}

enum keychain_key_type keychain_key_type(keychain_key_t k) {
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

int keychain_key_public(keychain_key_t k, char *buf, size_t *len) {
    SecKeyRef key = k;
    SecKeyRef pub = SecKeyCopyPublicKey(key);
    if (pub == NULL) {
        UM_LOG(WARN, "failed to retrieve public key: not available");
        return -1;
    }

    CFErrorRef err = NULL;
    CFDataRef d = SecKeyCopyExternalRepresentation(pub, &err);
    if (err != NULL) {
        UM_LOG(WARN, "failed to retrieve public key: %s", keychain_errmsg(err));
        CFRelease(pub);
        return -1;
    }

    CFIndex publen = CFDataGetLength(d);
    assert (publen <= *len);

    *len = publen;
    memcpy(buf, CFDataGetBytePtr(d), publen);

    CFRelease(d);
    CFRelease(pub);

    return 0;
}

int keychain_key_sign(keychain_key_t k,
                      const uint8_t * data, size_t datalen,
                      uint8_t *sig, size_t *siglen, int p) {
    SecKeyRef key = k;
    CFErrorRef err = NULL;
    CFDataRef d = CFDataCreate(kCFAllocatorDefault, data, (CFIndex)datalen);
    SecKeyAlgorithm const algorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
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
    return -1;
}

void keychain_free_key(keychain_key_t k) {
    if (k != NULL) {
        SecKeyRef key = k;
        CFRelease(key);
    }
}

int keychain_rem_key(const char *name) {
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

int keychain_load_key(keychain_key_t *k, const char *name) {
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

    if (r == errSecSuccess) {
        assert(ref != NULL);
        *k = (keychain_key_t) ref;
        return 0;
    }

    if (ref) {
        CFRelease(ref);
    }

    *k = NULL;
    UM_LOG(WARN, "failed to load key[%s]: %s", name, keychain_strerror(r));
    return -1;
}

