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


#include "context.h"
#include "tlsuv/tls_engine.h"
#include "tlsuv/tlsuv.h"
#include "um_debug.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <CommonCrypto/CommonDigest.h>
#include <Security/SecImportExport.h>
#include <Security/SecKeychain.h>
#include <Security/Security.h>
#include <Security/SecureTransport.h>

static tls_context ctx_api;
static struct tlsuv_private_key_s sec_key_api;
static struct tlsuv_public_key_s pub_key_api;
static struct tlsuv_certificate_s sec_cert_api;

static int load_file(const char* path, char** content, size_t* l);

const char* applesec_error(OSStatus code) {
    static char errorbuf[1024];
    CFStringRef err = SecCopyErrorMessageString(code, NULL);
    if (err == NULL) {
        // not every OSStatus is a Security.framework code
        snprintf(errorbuf, sizeof(errorbuf), "unknown error: %d", (int) code);
        return errorbuf;
    }
    CFStringGetCString(err, errorbuf, sizeof(errorbuf), kCFStringEncodingUTF8);
    CFRelease(err);
    return errorbuf;
}

// converts a CFStringRef into a static buffer, for logging only
static const char* cfstr(CFStringRef s) {
    static char buf[512];
    if (s == NULL || !CFStringGetCString(s, buf, sizeof(buf), kCFStringEncodingUTF8)) {
        strcpy(buf, "<none>");
    }
    return buf;
}

static const char* cferr(CFErrorRef err) {
    if (err == NULL) return "<none>";
    CFStringRef d = CFErrorCopyDescription(err);
    const char* s = cfstr(d);
    if (d) CFRelease(d);
    return s;
}

static enum applesec_key_type key_type_of(SecKeyRef k) {
    CFDictionaryRef attrs = SecKeyCopyAttributes(k);
    if (attrs == NULL) return APPLESEC_KEY_UNKNOWN;

    enum applesec_key_type t = APPLESEC_KEY_UNKNOWN;
    CFStringRef kt = CFDictionaryGetValue(attrs, kSecAttrKeyType);
    if (kt != NULL) {
        if (CFEqual(kt, kSecAttrKeyTypeRSA)) {
            t = APPLESEC_KEY_RSA;
        } else if (CFEqual(kt, kSecAttrKeyTypeECSECPrimeRandom) || CFEqual(kt, kSecAttrKeyTypeEC)) {
            t = APPLESEC_KEY_EC;
        }
    }
    CFRelease(attrs);
    return t;
}

// ---------------------------------------------------------------- CA bundle

// `ca` is either a PEM/DER blob or a path to one
static int load_ca(struct sectransport_ctx* ctx, const char* ca, size_t ca_len) {
    if (ctx->ca_bundle != NULL) {
        CFRelease(ctx->ca_bundle);
        ctx->ca_bundle = NULL;
    }
    if (ca == NULL || ca_len == 0) return 0;

    char* file_buf = NULL;
    size_t file_len = 0;
    const char* buf = ca;
    size_t buflen = ca_len;
    if (load_file(ca, &file_buf, &file_len) == 0) {
        buf = file_buf;
        buflen = file_len;
    }

    SecExternalItemType type = kSecItemTypeCertificate;
    SecExternalFormat fmt = kSecFormatUnknown;
    CFDataRef bundle = CFDataCreate(kCFAllocatorDefault, (const uint8_t*)buf, (CFIndex)buflen);
    OSStatus rc = SecItemImport(bundle, NULL, &fmt, &type, 0, NULL, NULL, &ctx->ca_bundle);
    CFRelease(bundle);
    free(file_buf);

    if (rc != errSecSuccess) {
        UM_LOG(WARN, "failed to load CA bundle: %d/%s", (int) rc, applesec_error(rc));
        ctx->ca_bundle = NULL;
        return -1;
    }
    return 0;
}

static int tls_set_ca_bundle(tls_context* ctx, const char* ca, size_t ca_len) {
    return load_ca((struct sectransport_ctx*)ctx, ca, ca_len);
}

// ------------------------------------------------------------------ context

tls_context* new_applesec_ctx(const char* ca, size_t ca_len) {
    struct sectransport_ctx* ctx = tlsuv__calloc(1, sizeof(*ctx));
    ctx->api = ctx_api;

    UM_LOG(INFO, "using %s; note SecureTransport tops out at TLS 1.2", ctx->api.version());

    load_ca(ctx, ca, ca_len);

    return &ctx->api;
}

int configure_applesec(void) {
    // Security.framework has no config file/provider concept
    return 0;
}

static void tls_free_ctx(tls_context* ctx) {
    struct sectransport_ctx* c = (struct sectransport_ctx*)ctx;
    if (c->ca_bundle) CFRelease(c->ca_bundle);
    if (c->ssl_chain) CFRelease(c->ssl_chain);
    if (c->tmp_keychain) {
        SecKeychainDelete(c->tmp_keychain);
        CFRelease(c->tmp_keychain);
    }
    if (c->tmp_keychain_path) {
        unlink(c->tmp_keychain_path);
        tlsuv__free(c->tmp_keychain_path);
    }
    tlsuv__free(c);
}

static const char* tls_lib_version(void) {
    static char version[64] = {0};
    if (*version == 0) {
        CFBundleRef secBundle = CFBundleGetBundleWithIdentifier(CFSTR("com.apple.security"));
        CFStringRef id = secBundle ? CFBundleGetIdentifier(secBundle) : NULL;
        CFDictionaryRef info = secBundle ? CFBundleGetInfoDictionary(secBundle) : NULL;
        CFStringRef v1 = info ? CFDictionaryGetValue(info, CFSTR("CFBundleShortVersionString")) : NULL;
        CFStringRef v2 = info ? CFDictionaryGetValue(info, CFSTR("CFBundleVersion")) : NULL;

        CFMutableStringRef v = CFStringCreateMutable(kCFAllocatorDefault, 64);
        CFStringAppend(v, id ? id : CFSTR("com.apple.security"));
        if (v1) {
            CFStringAppend(v, CFSTR(" "));
            CFStringAppend(v, v1);
        }
        if (v2) {
            CFStringAppend(v, CFSTR("/"));
            CFStringAppend(v, v2);
        }

        CFStringGetCString(v, version, sizeof(version), kCFStringEncodingASCII);
        CFRelease(v);
    }
    return version;
}

static void tls_set_cert_verify(tls_context* ctx,
                                int (*verify_f)(const struct tlsuv_certificate_s* cert, void* v_ctx),
                                void* v_ctx) {
    struct sectransport_ctx* c = (struct sectransport_ctx*)ctx;
    c->cert_verify_f = verify_f;
    c->verify_ctx = v_ctx;
}

static const char* tls_strerror(long code) {
    return applesec_error((OSStatus)code);
}

// --------------------------------------------------------------------- keys

static int gen_key(tlsuv_private_key_t* key_ref) {
    int32_t bits = 256;
    CFNumberRef size = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &bits);

    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionaryAddValue(attrs, kSecAttrKeySizeInBits, size);
    CFRelease(size);

    CFErrorRef err = NULL;
    SecKeyRef k = SecKeyCreateRandomKey(attrs, &err);
    CFRelease(attrs);

    if (k == NULL) {
        UM_LOG(ERR, "failed to generate key: %s", cferr(err));
        if (err) CFRelease(err);
        return -1;
    }
    if (err) CFRelease(err);

    struct sectransport_priv_key* pk = tlsuv__calloc(1, sizeof(*pk));
    pk->api = sec_key_api;
    pk->key = k;
    pk->key_type = APPLESEC_KEY_EC;
    *key_ref = &pk->api;
    return 0;
}

// standard-alphabet base64. src/base64.c cannot be used here: its table is
// URL-safe (it maps '-' to 62 and treats '+' as a terminator).
static int b64_decode(const char* in, size_t inlen, uint8_t* out, size_t* outlen) {
    static const int8_t d[256] = {
        ['A'] = 0, ['B'] = 1, ['C'] = 2, ['D'] = 3, ['E'] = 4, ['F'] = 5,
        ['G'] = 6, ['H'] = 7, ['I'] = 8, ['J'] = 9, ['K'] = 10, ['L'] = 11,
        ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
        ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
        ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
        ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
        ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
        ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
        ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53,
        ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
        ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63,
    };

    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (size_t i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=') break;
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (d[c] == 0 && c != 'A') return -1;
        acc = (acc << 6) | (uint32_t)d[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[n++] = (uint8_t)(acc >> bits);
        }
    }
    *outlen = n;
    return 0;
}

// returns the DER between the PEM armour lines, or -1 if `pem` is not PEM
static int pem_to_der(const char* pem, size_t len, uint8_t** der, size_t* derlen) {
    const char* begin = memmem(pem, len, "-----BEGIN ", 11);
    if (begin == NULL) return -1;
    const char* body = memchr(begin, '\n', len - (begin - pem));
    if (body == NULL) return -1;
    body++;

    const char* end = memmem(body, len - (body - pem), "-----END ", 9);
    if (end == NULL) return -1;

    size_t b64len = end - body;
    uint8_t* buf = tlsuv__malloc(b64len); // decoded is always smaller
    if (b64_decode(body, b64len, buf, derlen) != 0) {
        tlsuv__free(buf);
        return -1;
    }
    *der = buf;
    return 0;
}

// reads one DER tag, returning its contents
static bool der_next(const uint8_t** p, const uint8_t* end, uint8_t tag,
                     const uint8_t** body, size_t* bodylen) {
    if (end - *p < 2 || **p != tag) return false;
    (*p)++;

    size_t l = *(*p)++;
    if (l & 0x80) {
        size_t n = l & 0x7f;
        if (n == 0 || n > 4 || (size_t)(end - *p) < n) return false;
        l = 0;
        while (n-- > 0) l = (l << 8) | *(*p)++;
    }
    if ((size_t)(end - *p) < l) return false;

    *body = *p;
    *bodylen = l;
    *p += l;
    return true;
}

// writes a DER tag and length, returning the number of bytes written
static size_t der_write_tl(uint8_t* out, uint8_t tag, size_t len) {
    size_t n = 0;
    out[n++] = tag;
    if (len < 0x80) {
        out[n++] = (uint8_t)len;
    } else if (len < 0x100) {
        out[n++] = 0x81;
        out[n++] = (uint8_t)len;
    } else {
        out[n++] = 0x82;
        out[n++] = (uint8_t)(len >> 8);
        out[n++] = (uint8_t)len;
    }
    return n;
}

// SecItemImport handles PKCS#8 RSA and SEC1 EC, but rejects PKCS#8 EC outright.
//
//   PrivateKeyInfo ::= SEQUENCE { version INTEGER,
//                                 privateKeyAlgorithm SEQUENCE { OID ecPublicKey, OID curve },
//                                 privateKey OCTET STRING -- ECPrivateKey }
//
// The wrapped ECPrivateKey leaves out the curve, since the algorithm identifier
// already names it -- and Security cannot import it that way. So rebuild a
// standalone SEC1 key with the curve OID put back as its [0] parameters:
//
//   ECPrivateKey ::= SEQUENCE { version INTEGER (1),
//                               privateKey OCTET STRING,
//                               [0] parameters, [1] publicKey }
static CFDataRef unwrap_pkcs8_ec(const uint8_t* der, size_t derlen) {
    static const uint8_t OID_EC_PUBKEY[] = {0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};

    const uint8_t *p = der, *end = der + derlen;
    const uint8_t* seq;
    size_t seqlen;
    if (!der_next(&p, end, 0x30, &seq, &seqlen)) return NULL;

    const uint8_t *q = seq, *qend = seq + seqlen;
    const uint8_t* item;
    size_t itemlen;
    if (!der_next(&q, qend, 0x02, &item, &itemlen)) return NULL; // version
    if (!der_next(&q, qend, 0x30, &item, &itemlen)) return NULL; // algorithm
    if (itemlen < sizeof(OID_EC_PUBKEY) || memcmp(item, OID_EC_PUBKEY, sizeof(OID_EC_PUBKEY)) != 0) {
        return NULL; // not an EC key
    }

    // the curve OID follows ecPublicKey inside the algorithm identifier
    const uint8_t *a = item + sizeof(OID_EC_PUBKEY), *aend = item + itemlen;
    const uint8_t* curve_tlv = a;
    const uint8_t* curve;
    size_t curvelen;
    if (!der_next(&a, aend, 0x06, &curve, &curvelen)) return NULL;
    size_t curve_tlv_len = a - curve_tlv;

    const uint8_t* inner;
    size_t innerlen;
    if (!der_next(&q, qend, 0x04, &inner, &innerlen)) return NULL; // privateKey

    // walk the wrapped ECPrivateKey: version, privateKey, then whatever follows
    const uint8_t *r = inner, *rend = inner + innerlen;
    const uint8_t* iseq;
    size_t iseqlen;
    if (!der_next(&r, rend, 0x30, &iseq, &iseqlen)) return NULL;

    const uint8_t *s = iseq, *send = iseq + iseqlen;
    const uint8_t* head = s;
    if (!der_next(&s, send, 0x02, &item, &itemlen)) return NULL; // version
    if (!der_next(&s, send, 0x04, &item, &itemlen)) return NULL; // privateKey
    size_t headlen = s - head;
    const uint8_t* tail = s;
    size_t taillen = send - s;

    // if the curve is already there, the key is usable as-is
    if (taillen > 0 && *tail == 0xA0) {
        return CFDataCreate(kCFAllocatorDefault, inner, (CFIndex)innerlen);
    }

    uint8_t params[16];
    size_t paramslen = der_write_tl(params, 0xA0, curve_tlv_len);

    size_t contentlen = headlen + paramslen + curve_tlv_len + taillen;
    uint8_t* out = tlsuv__malloc(contentlen + 8);
    size_t n = der_write_tl(out, 0x30, contentlen);
    memcpy(out + n, head, headlen);
    n += headlen;
    memcpy(out + n, params, paramslen);
    n += paramslen;
    memcpy(out + n, curve_tlv, curve_tlv_len);
    n += curve_tlv_len;
    memcpy(out + n, tail, taillen);
    n += taillen;

    CFDataRef result = CFDataCreate(kCFAllocatorDefault, out, (CFIndex)n);
    tlsuv__free(out);
    return result;
}

// SecItemImport auto-detects PEM and DER, PKCS#8 RSA and the traditional
// OpenSSL/SEC1 forms. `keyParams` must stay NULL: passing a populated
// SecItemImportExportKeyParameters fails with errSecItemNotFound, since
// keyAttributes there takes CSSM values rather than kSecAttr* constants.
static OSStatus import_key(CFDataRef data, SecKeychainRef kc, CFArrayRef* items) {
    SecExternalFormat fmt = kSecFormatUnknown;
    SecExternalItemType type = kSecItemTypePrivateKey;
    OSStatus rc = SecItemImport(data, NULL, &fmt, &type, 0, NULL, kc, items);
    if (rc == errSecSuccess) return rc;

    // PKCS#8 EC: unwrap to SEC1 and retry
    uint8_t* der = NULL;
    size_t derlen = 0;
    bool owned = false;
    if (pem_to_der((const char*)CFDataGetBytePtr(data), CFDataGetLength(data), &der, &derlen) == 0) {
        owned = true;
    } else {
        der = (uint8_t*)CFDataGetBytePtr(data);
        derlen = CFDataGetLength(data);
    }

    CFDataRef sec1 = unwrap_pkcs8_ec(der, derlen);
    if (owned) tlsuv__free(der);
    if (sec1 == NULL) return rc;

    fmt = kSecFormatOpenSSL;
    type = kSecItemTypePrivateKey;
    OSStatus rc2 = SecItemImport(sec1, NULL, &fmt, &type, 0, NULL, kc, items);
    CFRelease(sec1);
    return rc2 == errSecSuccess ? rc2 : rc;
}

static int load_key(tlsuv_private_key_t* key_ref, const char* keystr, size_t len) {
    char* file_buf = NULL;
    size_t file_len = 0;
    const char* buf = keystr;
    size_t buflen = len;
    if (load_file(keystr, &file_buf, &file_len) == 0) {
        buf = file_buf;
        buflen = file_len;
    }

    CFDataRef data = CFDataCreate(kCFAllocatorDefault, (const uint8_t*)buf, (CFIndex)buflen);
    free(file_buf);

    CFArrayRef items = NULL;
    OSStatus rc = import_key(data, NULL, &items);
    if (rc != errSecSuccess || items == NULL || CFArrayGetCount(items) == 0) {
        UM_LOG(WARN, "failed to load private key: %s", applesec_error(rc));
        if (items) CFRelease(items);
        CFRelease(data);
        return -1;
    }

    SecKeyRef k = (SecKeyRef)CFArrayGetValueAtIndex(items, 0);
    if (CFGetTypeID(k) != SecKeyGetTypeID()) {
        UM_LOG(WARN, "imported item is not a key");
        CFRelease(items);
        CFRelease(data);
        return -1;
    }
    CFRetain(k);
    CFRelease(items);

    // for some keys Security loads the private key but then fails to derive the
    // public one; reloading from its external representation works around it.
    SecKeyRef pub = SecKeyCopyPublicKey(k);
    if (pub == NULL) {
        CFDictionaryRef attrs = SecKeyCopyAttributes(k);
        CFDataRef kd = SecKeyCopyExternalRepresentation(k, NULL);
        if (kd != NULL && attrs != NULL) {
            CFErrorRef err = NULL;
            SecKeyRef k1 = SecKeyCreateWithData(kd, attrs, &err);
            if (k1 != NULL) {
                CFRelease(k);
                k = k1;
            } else {
                UM_LOG(WARN, "could not derive public key: %s", cferr(err));
            }
            if (err) CFRelease(err);
        }
        if (kd) CFRelease(kd);
        if (attrs) CFRelease(attrs);
    } else {
        CFRelease(pub);
    }

    struct sectransport_priv_key* pk = tlsuv__calloc(1, sizeof(*pk));
    pk->api = sec_key_api;
    pk->key = k;
    pk->key_type = key_type_of(k);
    pk->pem = data; // keeps the exact bytes for to_pem() and keychain re-import
    *key_ref = &pk->api;
    return 0;
}

static SecKeyAlgorithm sign_algo(enum applesec_key_type type, enum hash_algo algo) {
    if (type == APPLESEC_KEY_EC) {
        switch (algo) {
        case hash_SHA256: return kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
        case hash_SHA384: return kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
        case hash_SHA512: return kSecKeyAlgorithmECDSASignatureDigestX962SHA512;
        }
    } else if (type == APPLESEC_KEY_RSA) {
        switch (algo) {
        case hash_SHA256: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
        case hash_SHA384: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384;
        case hash_SHA512: return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512;
        }
    }
    return NULL;
}

// raw r||s form, as produced by JWS. EC only.
static SecKeyAlgorithm sign_algo_raw(enum applesec_key_type type, enum hash_algo algo) {
    if (type != APPLESEC_KEY_EC) return NULL;
    switch (algo) {
    case hash_SHA256: return kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256;
    case hash_SHA384: return kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA384;
    case hash_SHA512: return kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA512;
    }
    return NULL;
}

static CFDataRef digest_of(enum hash_algo algo, const char* data, size_t datalen) {
    uint8_t md[CC_SHA512_DIGEST_LENGTH];
    CC_LONG n = (CC_LONG)datalen;
    size_t mdlen;
    switch (algo) {
    case hash_SHA256:
        CC_SHA256(data, n, md);
        mdlen = CC_SHA256_DIGEST_LENGTH;
        break;
    case hash_SHA384:
        CC_SHA384(data, n, md);
        mdlen = CC_SHA384_DIGEST_LENGTH;
        break;
    case hash_SHA512:
        CC_SHA512(data, n, md);
        mdlen = CC_SHA512_DIGEST_LENGTH;
        break;
    default:
        return NULL;
    }
    return CFDataCreate(kCFAllocatorDefault, md, (CFIndex)mdlen);
}

// shared by pubkey_verify() and cert_verify(): accepts the DER encoding our own
// sign() produces, and falls back to the raw r||s form JWS uses.
static int verify_with_key(SecKeyRef key, enum applesec_key_type type, enum hash_algo algo,
                           const char* data, size_t datalen, const char* sig, size_t siglen) {
    CFDataRef d = digest_of(algo, data, datalen);
    if (d == NULL) return -1;
    CFDataRef s = CFDataCreate(kCFAllocatorDefault, (const uint8_t*)sig, (CFIndex)siglen);

    int rc = -1;
    SecKeyAlgorithm algos[] = {sign_algo(type, algo), sign_algo_raw(type, algo)};
    for (unsigned i = 0; i < sizeof(algos) / sizeof(algos[0]); i++) {
        if (algos[i] == NULL) continue;
        CFErrorRef err = NULL;
        if (SecKeyVerifySignature(key, algos[i], d, s, &err)) {
            rc = 0;
            if (err) CFRelease(err);
            break;
        }
        if (err) CFRelease(err);
    }

    CFRelease(d);
    CFRelease(s);
    return rc;
}

static void privkey_free(struct tlsuv_private_key_s* pk) {
    struct sectransport_priv_key* key = container_of(pk, struct sectransport_priv_key, api);
    if (key->key) CFRelease(key->key);
    if (key->pem) CFRelease(key->pem);
    tlsuv__free(key);
}

static int privkey_to_pem(struct tlsuv_private_key_s* pk, char** pem, size_t* pemlen) {
    struct sectransport_priv_key* key = container_of(pk, struct sectransport_priv_key, api);
    CFDataRef data = key->pem;

    if (data == NULL) {
        OSStatus rc = SecItemExport(key->key, kSecFormatPEMSequence, kSecItemPemArmour, NULL, &data);
        if (rc != errSecSuccess) {
            UM_LOG(WARN, "failed to export key as PEM: %s", applesec_error(rc));
            return -1;
        }
    }

    CFIndex size = CFDataGetLength(data);
    *pem = tlsuv__calloc(1, size + 1);
    memcpy(*pem, CFDataGetBytePtr(data), size);
    *pemlen = size;
    if (data != key->pem) {
        CFRelease(data);
    }
    return 0;
}

static struct tlsuv_public_key_s* privkey_pubkey(struct tlsuv_private_key_s* pk) {
    struct sectransport_priv_key* key = container_of(pk, struct sectransport_priv_key, api);
    SecKeyRef pub = SecKeyCopyPublicKey(key->key);
    if (pub == NULL) {
        UM_LOG(WARN, "failed to derive public key");
        return NULL;
    }

    struct sectransport_pub_key* pubkey = tlsuv__calloc(1, sizeof(*pubkey));
    pubkey->api = pub_key_api;
    pubkey->key = pub;
    pubkey->key_type = key->key_type;
    return &pubkey->api;
}

static int privkey_sign(struct tlsuv_private_key_s* pk, enum hash_algo algo,
                        const char* data, size_t datalen,
                        char* sig, size_t* siglen) {
    struct sectransport_priv_key* key = container_of(pk, struct sectransport_priv_key, api);
    SecKeyAlgorithm algorithm = sign_algo(key->key_type, algo);
    if (algorithm == NULL) {
        UM_LOG(WARN, "unsupported key type/hash combination");
        return -1;
    }

    CFDataRef d = digest_of(algo, data, datalen);
    if (d == NULL) return -1;

    CFErrorRef err = NULL;
    CFDataRef s = SecKeyCreateSignature(key->key, algorithm, d, &err);
    CFRelease(d);

    if (s == NULL) {
        UM_LOG(WARN, "failed to sign: %s", cferr(err));
        if (err) CFRelease(err);
        return -1;
    }
    if (err) CFRelease(err);

    // *siglen arrives as the capacity of `sig`
    CFIndex n = CFDataGetLength(s);
    if ((size_t)n > *siglen) {
        UM_LOG(WARN, "signature buffer too small: need %ld have %zd", (long) n, *siglen);
        CFRelease(s);
        return -1;
    }
    memcpy(sig, CFDataGetBytePtr(s), n);
    *siglen = n;
    CFRelease(s);
    return 0;
}

static struct tlsuv_private_key_s sec_key_api = {
    .free = privkey_free,
    .to_pem = privkey_to_pem,
    .pubkey = privkey_pubkey,
    .sign = privkey_sign,
    // PKCS#11/keychain only
    .get_certificate = NULL,
    .store_certificate = NULL,
};

static void pubkey_free(struct tlsuv_public_key_s* pk) {
    struct sectransport_pub_key* key = container_of(pk, struct sectransport_pub_key, api);
    if (key->key) CFRelease(key->key);
    tlsuv__free(key);
}

static int pubkey_to_pem(struct tlsuv_public_key_s* pk, char** pem, size_t* pemlen) {
    struct sectransport_pub_key* key = container_of(pk, struct sectransport_pub_key, api);
    CFDataRef data = NULL;
    OSStatus rc = SecItemExport(key->key, kSecFormatPEMSequence, kSecItemPemArmour, NULL, &data);

    if (rc != errSecSuccess) {
        UM_LOG(WARN, "failed to export key as PEM: %s", applesec_error(rc));
        return -1;
    }

    CFIndex size = CFDataGetLength(data);
    *pem = tlsuv__calloc(1, size + 1);
    memcpy(*pem, CFDataGetBytePtr(data), size);
    *pemlen = size;
    CFRelease(data);
    return 0;
}

static int pubkey_verify(struct tlsuv_public_key_s* pub,
                         enum hash_algo algo, const char* data, size_t datalen,
                         const char* sig, size_t siglen) {
    struct sectransport_pub_key* key = container_of(pub, struct sectransport_pub_key, api);
    return verify_with_key(key->key, key->key_type, algo, data, datalen, sig, siglen);
}

static struct tlsuv_public_key_s pub_key_api = {
    .free = pubkey_free,
    .to_pem = pubkey_to_pem,
    .verify = pubkey_verify,
};

// -------------------------------------------------------------- certificates

static void cert_free(struct tlsuv_certificate_s* c) {
    if (c == NULL) return;

    struct sectransport_cert* cert = container_of(c, struct sectransport_cert, api);
    if (cert->chain) CFRelease(cert->chain);
    tlsuv__free(cert);
}

static int cert_to_pem(const struct tlsuv_certificate_s* c, int full, char** pem, size_t* pem_len) {
    struct sectransport_cert* cert = container_of(c, struct sectransport_cert, api);
    CFTypeRef item = full ? (CFTypeRef)cert->chain : CFArrayGetValueAtIndex(cert->chain, 0);
    CFDataRef data = NULL;
    OSStatus rc = SecItemExport(item, kSecFormatPEMSequence, kSecItemPemArmour, NULL, &data);
    if (rc != errSecSuccess) {
        UM_LOG(WARN, "failed to export certificate as PEM: %s", applesec_error(rc));
        return -1;
    }

    CFIndex len = CFDataGetLength(data);
    *pem = tlsuv__calloc(1, len + 1);
    CFDataGetBytes(data, CFRangeMake(0, len), (uint8_t*)*pem);
    *pem_len = len;
    CFRelease(data);
    return 0;
}

static int cert_expiration(const struct tlsuv_certificate_s* c, struct tm* exp) {
    struct sectransport_cert* cert = container_of(c, struct sectransport_cert, api);
    SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(cert->chain, 0);

    CFStringRef oid = kSecOIDX509V1ValidityNotAfter;
    CFArrayRef keys = CFArrayCreate(kCFAllocatorDefault, (const void**)&oid, 1, &kCFTypeArrayCallBacks);
    CFErrorRef err = NULL;
    CFDictionaryRef values = SecCertificateCopyValues(leaf, keys, &err);
    CFRelease(keys);

    int rc = -1;
    if (values != NULL) {
        CFDictionaryRef entry = CFDictionaryGetValue(values, oid);
        CFNumberRef v = entry ? CFDictionaryGetValue(entry, kSecPropertyKeyValue) : NULL;
        double abs;
        if (v != NULL && CFNumberGetValue(v, kCFNumberDoubleType, &abs)) {
            time_t t = (time_t)(abs + kCFAbsoluteTimeIntervalSince1970);
            gmtime_r(&t, exp);
            rc = 0;
        }
        CFRelease(values);
    }
    if (rc != 0) {
        UM_LOG(WARN, "failed to read certificate expiration: %s", cferr(err));
    }
    if (err) CFRelease(err);
    return rc;
}

static int cert_verify(const struct tlsuv_certificate_s* c, enum hash_algo algo,
                       const char* data, size_t datalen,
                       const char* sig, size_t siglen) {
    struct sectransport_cert* cert = container_of(c, struct sectransport_cert, api);
    SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(cert->chain, 0);

    SecKeyRef pub = SecCertificateCopyKey(leaf);
    if (pub == NULL) {
        UM_LOG(WARN, "failed to get certificate public key");
        return -1;
    }

    int rc = verify_with_key(pub, key_type_of(pub), algo, data, datalen, sig, siglen);
    CFRelease(pub);
    return rc;
}

static struct tlsuv_certificate_s sec_cert_api = {
    .free = cert_free,
    .to_pem = cert_to_pem,
    .get_expiration = cert_expiration,
    // Security has no X509_print_ex equivalent
    .get_text = NULL,
    .verify = cert_verify,
};

tlsuv_certificate_t applesec_cert_new(CFArrayRef chain) {
    struct sectransport_cert* c = tlsuv__calloc(1, sizeof(*c));
    c->api = sec_cert_api;
    c->chain = chain;
    return &c->api;
}

static int load_cert(tlsuv_certificate_t* cert, const char* certstr, size_t len) {
    *cert = NULL;

    char* file_buf = NULL;
    size_t file_len = 0;
    const char* buf = certstr;
    size_t buflen = len;
    if (load_file(certstr, &file_buf, &file_len) == 0) {
        buf = file_buf;
        buflen = file_len;
    }

    SecExternalItemType type = kSecItemTypeCertificate;
    SecExternalFormat fmt = kSecFormatUnknown;
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, (const uint8_t*)buf, (CFIndex)buflen);
    free(file_buf);

    CFArrayRef items = NULL;
    OSStatus rc = SecItemImport(data, NULL, &fmt, &type, 0, NULL, NULL, &items);
    CFRelease(data);

    if (rc != errSecSuccess || items == NULL || CFArrayGetCount(items) == 0) {
        UM_LOG(WARN, "failed to load certificate: %s", applesec_error(rc));
        if (items) CFRelease(items);
        return -1;
    }

    *cert = applesec_cert_new(items);
    return 0;
}

#define PKCS7_PEM_HEAD "-----BEGIN PKCS7-----\n"
#define PKCS7_PEM_TAIL "\n-----END PKCS7-----\n"

static int parse_pkcs7_certs(tlsuv_certificate_t* c, const char* pkcs7, size_t len) {
    *c = NULL;

    // wrap the caller's base64 in PEM armour and let Security decode it -- the
    // repo's own base64 decoder is URL-safe only and would truncate at the
    // first '+'.
    size_t armoured_len = strlen(PKCS7_PEM_HEAD) + len + strlen(PKCS7_PEM_TAIL);
    char* armoured = tlsuv__malloc(armoured_len + 1);
    snprintf(armoured, armoured_len + 1, "%s%.*s%s", PKCS7_PEM_HEAD, (int) len, pkcs7, PKCS7_PEM_TAIL);

    CFDataRef data = CFDataCreate(kCFAllocatorDefault, (const uint8_t*)armoured, (CFIndex)armoured_len);
    tlsuv__free(armoured);

    SecExternalFormat fmt = kSecFormatPKCS7;
    SecExternalItemType type = kSecItemTypeAggregate;
    CFArrayRef items = NULL;
    OSStatus rc = SecItemImport(data, NULL, &fmt, &type, kSecItemPemArmour, NULL, NULL, &items);
    CFRelease(data);

    if (rc != errSecSuccess || items == NULL || CFArrayGetCount(items) == 0) {
        UM_LOG(WARN, "failed to parse pkcs7: %s", applesec_error(rc));
        if (items) CFRelease(items);
        return -1;
    }

    *c = applesec_cert_new(items);
    return 0;
}

// ---------------------------------------------------------------- own cert

// true when `cert` is the certificate for `key`
static bool cert_matches_key(SecCertificateRef cert, SecKeyRef pub) {
    SecKeyRef cpub = SecCertificateCopyKey(cert);
    if (cpub == NULL) return false;

    CFDataRef a = SecKeyCopyExternalRepresentation(cpub, NULL);
    CFDataRef b = SecKeyCopyExternalRepresentation(pub, NULL);
    bool eq = a != NULL && b != NULL && CFEqual(a, b);

    if (a) CFRelease(a);
    if (b) CFRelease(b);
    CFRelease(cpub);
    return eq;
}

// SSLSetCertificate() needs a SecIdentityRef, and the only public way to make
// one is SecIdentityCreateWithCertificate(), which pairs a certificate with a
// private key *that lives in a keychain*. So put both in a throwaway file
// keychain that is deleted with the context.
//
// Consequence: the private key has to be extractable. That rules out keys held
// by the platform keychain (src/apple/keychain.c creates those non-extractable),
// which is why the keychain key slots are not implemented for this backend.
static int make_identity(struct sectransport_ctx* c, struct sectransport_priv_key* key,
                         SecCertificateRef leaf, SecIdentityRef* identity) {
    *identity = NULL;

    if (c->tmp_keychain == NULL) {
        char path[1024];
        const char* tmp = getenv("TMPDIR");
        snprintf(path, sizeof(path), "%stlsuv-%d-%p.keychain",
                 tmp ? tmp : "/tmp/", (int) getpid(), (void *) c);
        unlink(path);

        // random passphrase; the keychain never outlives the context
        uint8_t pw[32];
        char pwhex[sizeof(pw) * 2 + 1];
        if (SecRandomCopyBytes(kSecRandomDefault, sizeof(pw), pw) != errSecSuccess) {
            UM_LOG(ERR, "failed to generate keychain passphrase");
            return -1;
        }
        for (size_t i = 0; i < sizeof(pw); i++) {
            snprintf(pwhex + i * 2, 3, "%02x", pw[i]);
        }

        SecKeychainRef kc = NULL;
        OSStatus rc = SecKeychainCreate(path, (UInt32)strlen(pwhex), pwhex, false, NULL, &kc);
        if (rc != errSecSuccess) {
            UM_LOG(ERR, "failed to create temp keychain: %s", applesec_error(rc));
            return -1;
        }
        SecKeychainSetUserInteractionAllowed(false);

        c->tmp_keychain = kc;
        c->tmp_keychain_path = tlsuv__strdup(path);
    }

    // the key has to go in as PEM/DER; use the bytes it was loaded from, or
    // export a generated key.
    CFDataRef pem = key->pem;
    if (pem == NULL) {
        OSStatus rc = SecItemExport(key->key, kSecFormatPEMSequence, kSecItemPemArmour, NULL, &pem);
        if (rc != errSecSuccess) {
            UM_LOG(ERR, "failed to export private key: %s", applesec_error(rc));
            return -1;
        }
    }

    CFArrayRef items = NULL;
    OSStatus rc = import_key(pem, c->tmp_keychain, &items);
    if (pem != key->pem) CFRelease(pem);
    if (items) CFRelease(items);

    if (rc != errSecSuccess) {
        UM_LOG(ERR, "failed to import private key into keychain: %s", applesec_error(rc));
        return -1;
    }

    rc = SecCertificateAddToKeychain(leaf, c->tmp_keychain);
    if (rc != errSecSuccess && rc != errSecDuplicateItem) {
        UM_LOG(ERR, "failed to add certificate to keychain: %s", applesec_error(rc));
        return -1;
    }

    rc = SecIdentityCreateWithCertificate(c->tmp_keychain, leaf, identity);
    if (rc != errSecSuccess) {
        UM_LOG(ERR, "failed to create identity: %s", applesec_error(rc));
        return -1;
    }
    return 0;
}

static int tls_set_own_cert(tls_context* ctx, tlsuv_private_key_t pk, tlsuv_certificate_t cert) {
    if (ctx == NULL) return -1;
    struct sectransport_ctx* c = (struct sectransport_ctx*)ctx;

    if (c->ssl_chain) {
        CFRelease(c->ssl_chain);
        c->ssl_chain = NULL;
    }

    if (pk == NULL || cert == NULL) {
        // clearing
        return 0;
    }

    struct sectransport_priv_key* key = container_of(pk, struct sectransport_priv_key, api);
    struct sectransport_cert* cer = container_of(cert, struct sectransport_cert, api);

    SecKeyRef pub = SecKeyCopyPublicKey(key->key);
    if (pub == NULL) {
        UM_LOG(ERR, "cannot derive public key from private key");
        return -1;
    }

    // the chain is not required to be leaf-first
    CFIndex n = CFArrayGetCount(cer->chain);
    CFIndex leaf_idx = -1;
    for (CFIndex i = 0; i < n; i++) {
        if (cert_matches_key((SecCertificateRef)CFArrayGetValueAtIndex(cer->chain, i), pub)) {
            leaf_idx = i;
            break;
        }
    }
    CFRelease(pub);

    if (leaf_idx < 0) {
        UM_LOG(ERR, "no certificate in the chain matches the private key");
        return -1;
    }

    SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(cer->chain, leaf_idx);
    SecIdentityRef identity = NULL;
    if (make_identity(c, key, leaf, &identity) != 0) {
        return -1;
    }

    CFMutableArrayRef chain = CFArrayCreateMutable(kCFAllocatorDefault, n, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(chain, identity);
    CFRelease(identity);
    for (CFIndex i = 0; i < n; i++) {
        if (i != leaf_idx) {
            CFArrayAppendValue(chain, CFArrayGetValueAtIndex(cer->chain, i));
        }
    }
    c->ssl_chain = chain;
    return 0;
}

// ---------------------------------------------------------------------------

static tls_context ctx_api = {
    .version = tls_lib_version,
    .strerror = tls_strerror,
    .new_engine = applesec_new_engine,
    .free_ctx = tls_free_ctx,
    .set_ca_bundle = tls_set_ca_bundle,
    .set_own_cert = tls_set_own_cert,
    .set_cert_verify = tls_set_cert_verify,
    .parse_pkcs7_certs = parse_pkcs7_certs,
    .generate_key = gen_key,
    .load_key = load_key,
    .load_cert = load_cert,
    // not supported by this backend:
    // .allow_partial_chain
    // .generate_csr_to_pem      -- Security has no CSR API
    // .load_pkcs11_key, .generate_pkcs11_key
    // .generate_keychain_key, .load_keychain_key, .remove_keychain_key
};

static int load_file(const char* path, char** content, size_t* l) {
    uv_fs_t req;
    uv_file file;
    int rc = uv_fs_stat(NULL, &req, path, NULL);
    if (rc != 0) {
        uv_fs_req_cleanup(&req);
        return rc;
    }
    uv_buf_t buf = uv_buf_init(malloc(req.statbuf.st_size), (unsigned int)req.statbuf.st_size);
    uv_fs_req_cleanup(&req);

    file = uv_fs_open(NULL, &req, path, 0, 0, NULL);
    uv_fs_req_cleanup(&req);
    if (file < 0) {
        free(buf.base);
        return file;
    }

    int len = uv_fs_read(NULL, &req, file, &buf, 1, 0, NULL);
    uv_fs_req_cleanup(&req);

    uv_fs_close(NULL, &req, file, NULL);
    uv_fs_req_cleanup(&req);

    if (len < 0) {
        free(buf.base);
        return len;
    }

    *content = buf.base;
    *l = len;
    return 0;
}
