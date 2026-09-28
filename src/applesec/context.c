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

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#if TARGET_OS_OSX
#include <Security/SecImportExport.h>
#include <Security/SecKeychain.h>
#endif

static tls_context ctx_api;
static struct tlsuv_private_key_s sec_key_api;
static struct tlsuv_public_key_s pub_key_api;
static struct tlsuv_certificate_s sec_cert_api;

static int load_file(const char* path, char** content, size_t* l);
static CFArrayRef certs_from_data(const char* buf, size_t len);
#if !TARGET_OS_OSX
static void remove_keychain_items(struct applesec_ctx* c);
#endif

// Callers may count the terminating NUL in the length (mbedTLS requires that for PEM,
// OpenSSL ignores it). Trailing NULs are dropped so they never reach a parser (the
// keychain import in make_identity() rejects them). Only PEM is trimmed: DER may
// legitimately end in 0x00.
static size_t pem_trimmed_len(const char* buf, size_t len) {
    if (len == 0 || memmem(buf, len, "-----BEGIN ", strlen("-----BEGIN ")) == NULL) {
        return len;
    }
    while (len > 0 && buf[len - 1] == '\0') {
        len--;
    }
    return len;
}

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
static int load_ca(struct applesec_ctx* ctx, const char* ca, size_t ca_len) {
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

    buflen = pem_trimmed_len(buf, buflen);
    ctx->ca_bundle = certs_from_data(buf, buflen);
    tlsuv__free(file_buf);

    if (ctx->ca_bundle == NULL) {
        UM_LOG(WARN, "failed to load CA bundle");
        return -1;
    }
    return 0;
}

static int tls_set_ca_bundle(tls_context* ctx, const char* ca, size_t ca_len) {
    return load_ca((struct applesec_ctx*)ctx, ca, ca_len);
}

// ------------------------------------------------------------------ context

tls_context* new_applesec_ctx(const char* ca, size_t ca_len) {
    struct applesec_ctx* ctx = tlsuv__calloc(1, sizeof(*ctx));
    ctx->api = ctx_api;

    UM_LOG(INFO, "using %s", ctx->api.version());

    load_ca(ctx, ca, ca_len);

    return &ctx->api;
}

int configure_applesec(void) {
    return 0;
}

static void tls_free_ctx(tls_context* ctx) {
    struct applesec_ctx* c = (struct applesec_ctx*)ctx;
    if (c->ca_bundle) CFRelease(c->ca_bundle);
    if (c->ssl_chain) CFRelease(c->ssl_chain);
#if TARGET_OS_OSX
    if (c->tmp_keychain) {
        SecKeychainDelete(c->tmp_keychain);
        CFRelease(c->tmp_keychain);
    }
    if (c->tmp_keychain_path) {
        unlink(c->tmp_keychain_path);
        tlsuv__free(c->tmp_keychain_path);
    }
    memset_s(c->tmp_keychain_pw, sizeof(c->tmp_keychain_pw), 0, sizeof(c->tmp_keychain_pw));
#else
    remove_keychain_items(c);
#endif
    tlsuv__free(c);
}

static enum tls_fips_status tls_fips_status(tls_context* ctx, char* module, size_t modulelen) {
    // Network.framework/Security.framework crypto is using Apple corecrypto, which holds
    // FIPS 140 validations and per Apple always runs in FIPS mode: there is no
    // non-FIPS mode to switch to, hence no API to query, so report it unconditionally
    if (module) {
        snprintf(module, modulelen, "Apple corecrypto");
    }
    return TLS_FIPS_ENABLED;
}

static const char* tls_lib_version(void) {
    static char version[64] = {0};
    if (*version == 0) {
        CFBundleRef secBundle = CFBundleGetBundleWithIdentifier(CFSTR("com.apple.Network"));
        CFStringRef id = secBundle ? CFBundleGetIdentifier(secBundle) : NULL;
        CFDictionaryRef info = secBundle ? CFBundleGetInfoDictionary(secBundle) : NULL;
        CFStringRef v1 = info ? CFDictionaryGetValue(info, CFSTR("CFBundleShortVersionString")) : NULL;
        CFStringRef v2 = info ? CFDictionaryGetValue(info, CFSTR("CFBundleVersion")) : NULL;

        CFMutableStringRef v = CFStringCreateMutable(kCFAllocatorDefault, 64);
        CFStringAppend(v, id ? id : CFSTR("com.apple.Network"));
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
    struct applesec_ctx* c = (struct applesec_ctx*)ctx;
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

    struct applesec_priv_key* pk = tlsuv__calloc(1, sizeof(*pk));
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

// --------------------------------------------------- PEM / DER (no SecItemImport)
//
// SecItemImport/SecItemExport are macOS only; certificates and keys are parsed and
// encoded here instead, on top of SecCertificateCreateWithData/CopyData and
// SecKeyCreateWithData/CopyExternalRepresentation, which exist on every Apple OS.

static const uint8_t OID_EC_PUBLIC_KEY[] = {0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
static const uint8_t OID_RSA_ENCRYPTION[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
static const uint8_t OID_PKCS7_SIGNED_DATA[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};
static const uint8_t OID_P256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
static const uint8_t OID_P384[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
static const uint8_t OID_P521[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};

// curve OID (full TLV) for a field size in bytes
static const uint8_t* curve_oid(size_t field, size_t* len) {
    switch (field) {
    case 32: *len = sizeof(OID_P256); return OID_P256;
    case 48: *len = sizeof(OID_P384); return OID_P384;
    case 66: *len = sizeof(OID_P521); return OID_P521;
    default: return NULL;
    }
}

// growable byte buffer for building DER and PEM
struct buf {
    uint8_t* data;
    size_t len;
    size_t cap;
};

static void buf_put(struct buf* b, const void* bytes, size_t len) {
    if (b->len + len > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->len + len) cap *= 2;
        b->data = tlsuv__realloc(b->data, cap);
        b->cap = cap;
    }
    memcpy(b->data + b->len, bytes, len);
    b->len += len;
}

// appends tag + length + content
static void der_put(struct buf* b, uint8_t tag, const void* content, size_t len) {
    uint8_t tl[8];
    size_t n = der_write_tl(tl, tag, len);
    buf_put(b, tl, n);
    buf_put(b, content, len);
}

// appends a BIT STRING with no unused bits
static void der_put_bits(struct buf* b, const uint8_t* bits, size_t len) {
    uint8_t tl[8];
    size_t n = der_write_tl(tl, 0x03, len + 1);
    buf_put(b, tl, n);
    buf_put(b, "\0", 1);
    buf_put(b, bits, len);
}

static void b64_encode_lines(struct buf* out, const uint8_t* in, size_t len) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int col = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t) in[i] << 16;
        if (i + 1 < len) v |= (uint32_t) in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        char q[4] = {tbl[(v >> 18) & 63], tbl[(v >> 12) & 63],
                     i + 1 < len ? tbl[(v >> 6) & 63] : '=', i + 2 < len ? tbl[v & 63] : '='};
        buf_put(out, q, 4);
        col += 4;
        if (col == 64) {
            buf_put(out, "\n", 1);
            col = 0;
        }
    }
    if (col > 0) buf_put(out, "\n", 1);
}

static void pem_put(struct buf* out, const char* label, const uint8_t* der, size_t len) {
    char line[80];
    snprintf(line, sizeof(line), "-----BEGIN %s-----\n", label);
    buf_put(out, line, strlen(line));
    b64_encode_lines(out, der, len);
    snprintf(line, sizeof(line), "-----END %s-----\n", label);
    buf_put(out, line, strlen(line));
}

// hands a PEM buffer to the caller as a NUL-terminated tlsuv__ allocation
static int pem_result(struct buf* b, char** pem, size_t* pemlen) {
    buf_put(b, "", 1); // NUL, not counted
    *pem = (char*) b->data;
    *pemlen = b->len - 1;
    return 0;
}

static bool add_certificate(CFMutableArrayRef certs, const uint8_t* der, size_t len) {
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, der, (CFIndex) len);
    SecCertificateRef cert = SecCertificateCreateWithData(kCFAllocatorDefault, data);
    CFRelease(data);
    if (cert == NULL) return false;
    CFArrayAppendValue(certs, cert);
    CFRelease(cert);
    return true;
}

// every CERTIFICATE block of a PEM bundle, or a single DER certificate.
// Other PEM blocks (keys etc.) are skipped. NULL if nothing could be parsed.
static CFArrayRef certs_from_data(const char* buf, size_t len) {
    static const char BEGIN[] = "-----BEGIN CERTIFICATE-----";
    static const char END[] = "-----END CERTIFICATE-----";

    CFMutableArrayRef certs = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    bool ok = true;
    if (memmem(buf, len, "-----BEGIN ", 11) != NULL) {
        const char* p = buf;
        const char* end = buf + len;
        const char* begin;
        while (ok && (begin = memmem(p, end - p, BEGIN, sizeof(BEGIN) - 1)) != NULL) {
            const char* body = begin + sizeof(BEGIN) - 1;
            const char* stop = memmem(body, end - body, END, sizeof(END) - 1);
            if (stop == NULL) {
                ok = false;
                break;
            }
            size_t derlen = 0;
            uint8_t* der = tlsuv__malloc(stop - body + 1);
            ok = b64_decode(body, stop - body, der, &derlen) == 0 && add_certificate(certs, der, derlen);
            tlsuv__free(der);
            p = stop + sizeof(END) - 1;
        }
    } else {
        ok = add_certificate(certs, (const uint8_t*) buf, len);
    }

    if (!ok || CFArrayGetCount(certs) == 0) {
        CFRelease(certs);
        return NULL;
    }
    return certs;
}

// PKCS#7 (CMS) SignedData, the certificates only:
//   ContentInfo ::= SEQUENCE { contentType OID signedData, [0] EXPLICIT SignedData }
//   SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo SEQUENCE,
//                             certificates [0] IMPLICIT SET OF Certificate OPTIONAL, ... }
static CFArrayRef certs_from_pkcs7(const uint8_t* der, size_t len) {
    const uint8_t *p = der, *end = der + len;
    const uint8_t* body;
    size_t bodylen;
    if (!der_next(&p, end, 0x30, &body, &bodylen)) return NULL;

    const uint8_t *q = body, *qend = body + bodylen;
    if ((size_t)(qend - q) < sizeof(OID_PKCS7_SIGNED_DATA) ||
        memcmp(q, OID_PKCS7_SIGNED_DATA, sizeof(OID_PKCS7_SIGNED_DATA)) != 0) {
        return NULL;
    }
    q += sizeof(OID_PKCS7_SIGNED_DATA);

    const uint8_t* item;
    size_t itemlen;
    if (!der_next(&q, qend, 0xA0, &item, &itemlen)) return NULL; // [0] EXPLICIT
    const uint8_t *r = item, *rend = item + itemlen;
    if (!der_next(&r, rend, 0x30, &item, &itemlen)) return NULL; // SignedData
    r = item;
    rend = item + itemlen;
    if (!der_next(&r, rend, 0x02, &item, &itemlen)) return NULL; // version
    if (!der_next(&r, rend, 0x31, &item, &itemlen)) return NULL; // digestAlgorithms
    if (!der_next(&r, rend, 0x30, &item, &itemlen)) return NULL; // encapContentInfo
    if (!der_next(&r, rend, 0xA0, &item, &itemlen)) return NULL; // certificates

    CFMutableArrayRef certs = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    const uint8_t *c = item, *cend = item + itemlen;
    while (c < cend) {
        const uint8_t* tlv = c;
        const uint8_t* cert;
        size_t certlen;
        if (!der_next(&c, cend, 0x30, &cert, &certlen) || !add_certificate(certs, tlv, c - tlv)) {
            CFRelease(certs);
            return NULL;
        }
    }
    if (CFArrayGetCount(certs) == 0) {
        CFRelease(certs);
        return NULL;
    }
    return certs;
}

// SubjectPublicKeyInfo DER for a public key
static bool spki_der(SecKeyRef key, enum applesec_key_type type, struct buf* out) {
    CFErrorRef err = NULL;
    CFDataRef rep = SecKeyCopyExternalRepresentation(key, &err);
    if (rep == NULL) {
        UM_LOG(WARN, "failed to export public key: %s", cferr(err));
        if (err) CFRelease(err);
        return false;
    }
    const uint8_t* raw = CFDataGetBytePtr(rep);
    size_t rawlen = CFDataGetLength(rep);

    struct buf alg = {0}, spki = {0};
    bool ok = true;
    if (type == APPLESEC_KEY_EC) {
        // X9.63 uncompressed point: 04 || X || Y
        size_t oidlen;
        const uint8_t* oid = curve_oid((rawlen - 1) / 2, &oidlen);
        ok = oid != NULL && raw[0] == 0x04;
        if (ok) {
            buf_put(&alg, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY));
            buf_put(&alg, oid, oidlen);
        }
    } else if (type == APPLESEC_KEY_RSA) {
        // PKCS#1 RSAPublicKey
        buf_put(&alg, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION));
        buf_put(&alg, "\x05\x00", 2); // NULL parameters
    } else {
        ok = false;
    }

    if (ok) {
        der_put(&spki, 0x30, alg.data, alg.len);
        der_put_bits(&spki, raw, rawlen);
        der_put(out, 0x30, spki.data, spki.len);
    } else {
        UM_LOG(WARN, "unsupported public key type");
    }
    tlsuv__free(alg.data);
    tlsuv__free(spki.data);
    CFRelease(rep);
    return ok;
}

// PEM for a private key: PKCS#8 "PRIVATE KEY", as the OpenSSL backend writes it
//   PrivateKeyInfo ::= SEQUENCE { version 0, privateKeyAlgorithm AlgorithmIdentifier,
//                                 privateKey OCTET STRING }
static bool private_key_pem(SecKeyRef key, enum applesec_key_type type, struct buf* pem) {
    CFErrorRef err = NULL;
    CFDataRef rep = SecKeyCopyExternalRepresentation(key, &err);
    if (rep == NULL) {
        UM_LOG(WARN, "failed to export private key: %s", cferr(err));
        if (err) CFRelease(err);
        return false;
    }
    const uint8_t* raw = CFDataGetBytePtr(rep);
    size_t rawlen = CFDataGetLength(rep);

    struct buf alg = {0}, inner = {0}, body = {0}, der = {0};
    bool ok = false;
    if (type == APPLESEC_KEY_RSA) {
        // AlgorithmIdentifier { rsaEncryption, NULL }; privateKey is the PKCS#1
        // RSAPrivateKey Security exports as is
        buf_put(&alg, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION));
        buf_put(&alg, "\x05\x00", 2);
        buf_put(&inner, raw, rawlen);
        ok = true;
    } else if (type == APPLESEC_KEY_EC && rawlen > 1 && raw[0] == 0x04 && (rawlen - 1) % 3 == 0) {
        // X9.63 private: 04 || X || Y || K
        size_t field = (rawlen - 1) / 3;
        size_t oidlen;
        const uint8_t* oid = curve_oid(field, &oidlen);
        if (oid) {
            // AlgorithmIdentifier { ecPublicKey, curve }; privateKey is
            //   ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING,
            //                               [1] publicKey BIT STRING }
            // (the curve is in the algorithm identifier, so ECPrivateKey leaves out
            // [0] parameters; the public key is kept, load_key() needs it)
            buf_put(&alg, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY));
            buf_put(&alg, oid, oidlen);

            struct buf pub = {0}, ec = {0};
            der_put_bits(&pub, raw, 1 + 2 * field);
            buf_put(&ec, "\x02\x01\x01", 3);
            der_put(&ec, 0x04, raw + 1 + 2 * field, field);
            der_put(&ec, 0xA1, pub.data, pub.len);
            der_put(&inner, 0x30, ec.data, ec.len);
            tlsuv__free(pub.data);
            tlsuv__free(ec.data);
            ok = true;
        }
    }
    if (ok) {
        buf_put(&body, "\x02\x01\x00", 3);
        der_put(&body, 0x30, alg.data, alg.len);
        der_put(&body, 0x04, inner.data, inner.len);
        der_put(&der, 0x30, body.data, body.len);
        pem_put(pem, "PRIVATE KEY", der.data, der.len);
    }
    tlsuv__free(alg.data);
    tlsuv__free(inner.data);
    tlsuv__free(body.data);
    tlsuv__free(der.data);
    if (!ok) {
        UM_LOG(WARN, "unsupported private key type");
    }
    CFRelease(rep);
    return ok;
}

// UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ), UTC only
static bool parse_asn1_time(uint8_t tag, const uint8_t* s, size_t len, time_t* t) {
    size_t ylen = tag == 0x17 ? 2 : 4;
    if ((tag != 0x17 && tag != 0x18) || len != ylen + 11 || s[len - 1] != 'Z') return false;
    for (size_t i = 0; i < len - 1; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
    }
#define DIGITS(off, n) ({ int v_ = 0; for (size_t i_ = 0; i_ < (n); i_++) v_ = v_ * 10 + (s[(off) + i_] - '0'); v_; })
    struct tm tm = {0};
    int year = DIGITS(0, ylen);
    if (ylen == 2) year += year < 50 ? 2000 : 1900; // RFC 5280 4.1.2.5.1
    tm.tm_year = year - 1900;
    tm.tm_mon = DIGITS(ylen, 2) - 1;
    tm.tm_mday = DIGITS(ylen + 2, 2);
    tm.tm_hour = DIGITS(ylen + 4, 2);
    tm.tm_min = DIGITS(ylen + 6, 2);
    tm.tm_sec = DIGITS(ylen + 8, 2);
#undef DIGITS
    *t = timegm(&tm);
    return true;
}

// notAfter of a DER certificate:
//   Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version OPTIONAL, serialNumber,
//                              signature, issuer, validity SEQUENCE { notBefore, notAfter }, ... } ... }
static bool cert_not_after(const uint8_t* der, size_t len, time_t* t) {
    const uint8_t *p = der, *end = der + len;
    const uint8_t* item;
    size_t itemlen;
    if (!der_next(&p, end, 0x30, &item, &itemlen)) return false; // Certificate
    p = item;
    end = item + itemlen;
    if (!der_next(&p, end, 0x30, &item, &itemlen)) return false; // tbsCertificate
    p = item;
    end = item + itemlen;
    if (p < end && *p == 0xA0 && !der_next(&p, end, 0xA0, &item, &itemlen)) return false; // version
    if (!der_next(&p, end, 0x02, &item, &itemlen)) return false; // serialNumber
    if (!der_next(&p, end, 0x30, &item, &itemlen)) return false; // signature
    if (!der_next(&p, end, 0x30, &item, &itemlen)) return false; // issuer
    if (!der_next(&p, end, 0x30, &item, &itemlen)) return false; // validity
    p = item;
    end = item + itemlen;
    if (p >= end || !der_next(&p, end, *p, &item, &itemlen)) return false; // notBefore
    if (p >= end) return false;
    uint8_t tag = *p;
    if (!der_next(&p, end, tag, &item, &itemlen)) return false; // notAfter
    return parse_asn1_time(tag, item, itemlen, t);
}

#if TARGET_OS_OSX
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
#endif

// SEC1 ECPrivateKey -> the ANSI X9.63 form SecKeyCreateWithData() wants:
// the uncompressed public point (0x04 || X || Y) followed by the private
// scalar, left-padded to the field size.
//
//   ECPrivateKey ::= SEQUENCE { version INTEGER (1),
//                               privateKey OCTET STRING,
//                               [0] parameters OPTIONAL,
//                               [1] publicKey OPTIONAL }
static CFDataRef sec1_to_x963(const uint8_t* sec1, size_t len) {
    const uint8_t *p = sec1, *end = sec1 + len;
    const uint8_t* seq;
    size_t seqlen;
    if (!der_next(&p, end, 0x30, &seq, &seqlen)) return NULL;

    const uint8_t *q = seq, *qend = seq + seqlen;
    const uint8_t* item;
    size_t itemlen;
    if (!der_next(&q, qend, 0x02, &item, &itemlen)) return NULL; // version

    const uint8_t* priv;
    size_t privlen;
    if (!der_next(&q, qend, 0x04, &priv, &privlen)) return NULL; // privateKey

    // skip the optional [0] parameters to reach [1] publicKey
    const uint8_t* pub = NULL;
    size_t publen = 0;
    while (q < qend) {
        const uint8_t tag = *q;
        if (!der_next(&q, qend, tag, &item, &itemlen)) break;
        if (tag == 0xA1) {
            const uint8_t *b = item, *bend = item + itemlen;
            const uint8_t* bits;
            size_t bitslen;
            if (der_next(&b, bend, 0x03, &bits, &bitslen) && bitslen > 1 && bits[0] == 0) {
                pub = bits + 1; // drop the unused-bits count
                publen = bitslen - 1;
            }
            break;
        }
    }

    // without the public point there is no way to build X9.63 short of doing
    // the scalar multiplication ourselves
    if (pub == NULL || publen < 3 || pub[0] != 0x04) return NULL;

    size_t field = (publen - 1) / 2;
    if (privlen > field) return NULL;

    uint8_t* out = tlsuv__calloc(1, publen + field);
    memcpy(out, pub, publen);
    // left-pad the scalar; DER may have dropped leading zero bytes
    memcpy(out + publen + (field - privlen), priv, privlen);

    CFDataRef result = CFDataCreate(kCFAllocatorDefault, out, (CFIndex)(publen + field));
    tlsuv__free(out);
    return result;
}

// Reduces any of the private key encodings we accept -- PKCS#8 (RSA or EC),
// PKCS#1 RSAPrivateKey, SEC1 ECPrivateKey -- to the raw representation
// SecKeyCreateWithData() takes, and says which key type it is.
static CFDataRef key_data_for(const uint8_t* der, size_t derlen, enum applesec_key_type* type) {
    static const uint8_t OID_EC_PUBKEY[] = {0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
    // NB: not OID_RSA -- Security/oidsalg.h already defines that
    static const uint8_t OID_RSA_ENC[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};

    const uint8_t *p = der, *end = der + derlen;
    const uint8_t* seq;
    size_t seqlen;
    if (!der_next(&p, end, 0x30, &seq, &seqlen)) return NULL;

    const uint8_t *q = seq, *qend = seq + seqlen;
    const uint8_t* item;
    size_t itemlen;
    if (!der_next(&q, qend, 0x02, &item, &itemlen)) return NULL; // version
    if (q >= qend) return NULL;

    // PKCS#8 PrivateKeyInfo: the version is followed by an AlgorithmIdentifier
    if (*q == 0x30) {
        const uint8_t* alg;
        size_t alglen;
        if (!der_next(&q, qend, 0x30, &alg, &alglen)) return NULL;

        const uint8_t* inner;
        size_t innerlen;
        if (!der_next(&q, qend, 0x04, &inner, &innerlen)) return NULL;

        if (alglen >= sizeof(OID_RSA_ENC) && memcmp(alg, OID_RSA_ENC, sizeof(OID_RSA_ENC)) == 0) {
            *type = APPLESEC_KEY_RSA; // privateKey is a PKCS#1 RSAPrivateKey
            return CFDataCreate(kCFAllocatorDefault, inner, (CFIndex)innerlen);
        }
        if (alglen >= sizeof(OID_EC_PUBKEY) && memcmp(alg, OID_EC_PUBKEY, sizeof(OID_EC_PUBKEY)) == 0) {
            *type = APPLESEC_KEY_EC; // privateKey is a SEC1 ECPrivateKey
            return sec1_to_x963(inner, innerlen);
        }
        return NULL;
    }

    // SEC1 ECPrivateKey: version is followed by the private scalar
    if (*q == 0x04) {
        *type = APPLESEC_KEY_EC;
        return sec1_to_x963(der, derlen);
    }

    // PKCS#1 RSAPrivateKey: version is followed by the modulus
    if (*q == 0x02) {
        *type = APPLESEC_KEY_RSA;
        return CFDataCreate(kCFAllocatorDefault, der, (CFIndex)derlen);
    }

    return NULL;
}

// Builds a SecKey directly, without going through SecItemImport. That keeps
// keys off the legacy CDSA code path, which leaks on every import.
static SecKeyRef create_private_key(CFDataRef blob, enum applesec_key_type* type) {
    uint8_t* der = NULL;
    size_t derlen = 0;
    bool owned = false;
    if (pem_to_der((const char*)CFDataGetBytePtr(blob), CFDataGetLength(blob), &der, &derlen) == 0) {
        owned = true;
    } else {
        der = (uint8_t*)CFDataGetBytePtr(blob);
        derlen = CFDataGetLength(blob);
    }

    CFDataRef key_data = key_data_for(der, derlen, type);
    if (owned) tlsuv__free(der);
    if (key_data == NULL) {
        UM_LOG(WARN, "unrecognized private key format");
        return NULL;
    }

    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionaryAddValue(attrs, kSecAttrKeyType,
                         *type == APPLESEC_KEY_RSA ? kSecAttrKeyTypeRSA
                                                   : kSecAttrKeyTypeECSECPrimeRandom);

    CFErrorRef err = NULL;
    SecKeyRef key = SecKeyCreateWithData(key_data, attrs, &err);
    CFRelease(key_data);
    CFRelease(attrs);

    if (key == NULL) {
        UM_LOG(WARN, "failed to create private key: %s", cferr(err));
    }
    if (err) CFRelease(err);
    return key;
}

#if TARGET_OS_OSX
// Still needed for the mTLS identity: SecKeyCreateWithData() produces a
// floating key, but SecIdentityCreateWithCertificate() can only pair a
// certificate with a key that lives in a keychain.
//
// SecItemImport auto-detects PEM and DER, PKCS#8 RSA and the traditional
// OpenSSL/SEC1 forms. `keyParams` must stay NULL: passing a populated
// SecItemImportExportKeyParameters fails with errSecItemNotFound, since
// keyAttributes there takes CSSM values rather than kSecAttr* constants.
static OSStatus import_key(CFDataRef data, SecKeychainRef kc, CFArrayRef* items) {
    // SecItemImport cannot parse PKCS#8 EC, and it leaks ~144 bytes of CSP
    // provider state on *every failed import* (measured: linear in the number
    // of failures). So convert up front instead of probing and retrying --
    // there must be exactly one import call, and it has to succeed.
    uint8_t* der = NULL;
    size_t derlen = 0;
    bool owned = false;
    if (pem_to_der((const char*)CFDataGetBytePtr(data), CFDataGetLength(data), &der, &derlen) == 0) {
        owned = true;
    } else {
        der = (uint8_t*)CFDataGetBytePtr(data);
        derlen = CFDataGetLength(data);
    }

    // non-NULL only for PKCS#8 EC; every other encoding imports as-is
    CFDataRef sec1 = unwrap_pkcs8_ec(der, derlen);
    if (owned) tlsuv__free(der);

    SecExternalFormat fmt = sec1 ? kSecFormatOpenSSL : kSecFormatUnknown;
    SecExternalItemType type = kSecItemTypePrivateKey;
    OSStatus rc = SecItemImport(sec1 ? sec1 : data, NULL, &fmt, &type, 0, NULL, kc, items);
    if (sec1) CFRelease(sec1);
    return rc;
}
#endif

static int load_key(tlsuv_private_key_t* key_ref, const char* keystr, size_t len) {
    char* file_buf = NULL;
    size_t file_len = 0;
    const char* buf = keystr;
    size_t buflen = len;
    if (load_file(keystr, &file_buf, &file_len) == 0) {
        buf = file_buf;
        buflen = file_len;
    }

    buflen = pem_trimmed_len(buf, buflen);
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, (const uint8_t*)buf, (CFIndex)buflen);
    tlsuv__free(file_buf);

    enum applesec_key_type type = APPLESEC_KEY_UNKNOWN;
    SecKeyRef k = create_private_key(data, &type);
    if (k == NULL) {
        CFRelease(data);
        return -1;
    }

    struct applesec_priv_key* pk = tlsuv__calloc(1, sizeof(*pk));
    pk->api = sec_key_api;
    pk->key = k;
    pk->key_type = type;
    pk->pem = data; // keeps the exact bytes for keychain re-import
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
    struct applesec_priv_key* key = container_of(pk, struct applesec_priv_key, api);
    if (key->key) CFRelease(key->key);
    if (key->pem) CFRelease(key->pem);
    tlsuv__free(key);
}

static int privkey_to_pem(struct tlsuv_private_key_s* pk, char** pem, size_t* pemlen) {
    struct applesec_priv_key* key = container_of(pk, struct applesec_priv_key, api);

    // always PKCS#8, whatever format the key was loaded from
    struct buf out = {0};
    if (!private_key_pem(key->key, key->key_type, &out)) {
        tlsuv__free(out.data);
        return -1;
    }
    return pem_result(&out, pem, pemlen);
}

static struct tlsuv_public_key_s* privkey_pubkey(struct tlsuv_private_key_s* pk) {
    struct applesec_priv_key* key = container_of(pk, struct applesec_priv_key, api);
    SecKeyRef pub = SecKeyCopyPublicKey(key->key);
    if (pub == NULL) {
        UM_LOG(WARN, "failed to derive public key");
        return NULL;
    }

    struct applesec_pub_key* pubkey = tlsuv__calloc(1, sizeof(*pubkey));
    pubkey->api = pub_key_api;
    pubkey->key = pub;
    pubkey->key_type = key->key_type;
    return &pubkey->api;
}

static int privkey_sign(struct tlsuv_private_key_s* pk, enum hash_algo algo,
                        const char* data, size_t datalen,
                        char* sig, size_t* siglen) {
    struct applesec_priv_key* key = container_of(pk, struct applesec_priv_key, api);
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
    struct applesec_pub_key* key = container_of(pk, struct applesec_pub_key, api);
    if (key->key) CFRelease(key->key);
    tlsuv__free(key);
}

static int pubkey_to_pem(struct tlsuv_public_key_s* pk, char** pem, size_t* pemlen) {
    struct applesec_pub_key* key = container_of(pk, struct applesec_pub_key, api);
    enum applesec_key_type type = key->key_type != APPLESEC_KEY_UNKNOWN ? key->key_type : key_type_of(key->key);

    struct buf der = {0};
    if (!spki_der(key->key, type, &der)) {
        tlsuv__free(der.data);
        return -1;
    }
    struct buf out = {0};
    pem_put(&out, "PUBLIC KEY", der.data, der.len);
    tlsuv__free(der.data);
    return pem_result(&out, pem, pemlen);
}

static int pubkey_verify(struct tlsuv_public_key_s* pub,
                         enum hash_algo algo, const char* data, size_t datalen,
                         const char* sig, size_t siglen) {
    struct applesec_pub_key* key = container_of(pub, struct applesec_pub_key, api);
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

    struct applesec_cert* cert = container_of(c, struct applesec_cert, api);
    if (cert->chain) CFRelease(cert->chain);
    tlsuv__free(cert);
}

static int cert_to_pem(const struct tlsuv_certificate_s* c, int full, char** pem, size_t* pem_len) {
    struct applesec_cert* cert = container_of(c, struct applesec_cert, api);
    CFIndex count = full ? CFArrayGetCount(cert->chain) : 1;

    struct buf out = {0};
    for (CFIndex i = 0; i < count; i++) {
        SecCertificateRef crt = (SecCertificateRef) CFArrayGetValueAtIndex(cert->chain, i);
        CFDataRef der = SecCertificateCopyData(crt);
        pem_put(&out, "CERTIFICATE", CFDataGetBytePtr(der), CFDataGetLength(der));
        CFRelease(der);
    }
    return pem_result(&out, pem, pem_len);
}

static int cert_expiration(const struct tlsuv_certificate_s* c, struct tm* exp) {
    struct applesec_cert* cert = container_of(c, struct applesec_cert, api);
    SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(cert->chain, 0);

    CFDataRef der = SecCertificateCopyData(leaf);
    time_t t;
    bool ok = cert_not_after(CFDataGetBytePtr(der), CFDataGetLength(der), &t);
    CFRelease(der);
    if (!ok) {
        UM_LOG(WARN, "failed to read certificate expiration");
        return -1;
    }
    gmtime_r(&t, exp);
    return 0;
}

static int cert_verify(const struct tlsuv_certificate_s* c, enum hash_algo algo,
                       const char* data, size_t datalen,
                       const char* sig, size_t siglen) {
    struct applesec_cert* cert = container_of(c, struct applesec_cert, api);
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
    struct applesec_cert* c = tlsuv__calloc(1, sizeof(*c));
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

    buflen = pem_trimmed_len(buf, buflen);
    CFArrayRef certs = certs_from_data(buf, buflen);
    tlsuv__free(file_buf);

    if (certs == NULL) {
        UM_LOG(WARN, "failed to load certificate");
        return -1;
    }

    *cert = applesec_cert_new(certs);
    return 0;
}

// `pkcs7` is base64 DER (as returned by the Ziti controller), optionally PEM armoured
static int parse_pkcs7_certs(tlsuv_certificate_t* c, const char* pkcs7, size_t len) {
    *c = NULL;

    uint8_t* der = NULL;
    size_t derlen = 0;
    if (pem_to_der(pkcs7, len, &der, &derlen) != 0) {
        der = tlsuv__malloc(len + 1);
        if (b64_decode(pkcs7, len, der, &derlen) != 0) {
            tlsuv__free(der);
            UM_LOG(WARN, "failed to parse pkcs7: invalid base64");
            return -1;
        }
    }

    CFArrayRef certs = certs_from_pkcs7(der, derlen);
    tlsuv__free(der);
    if (certs == NULL) {
        UM_LOG(WARN, "failed to parse pkcs7");
        return -1;
    }

    *c = applesec_cert_new(certs);
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

#if TARGET_OS_OSX
// the TLS client identity needs a SecIdentityRef, and the only public way to make
// one is SecIdentityCreateWithCertificate(), which pairs a certificate with a
// private key *that lives in a keychain*. So put both in a throwaway file
// keychain that is deleted with the context.
//
// Consequence: the private key has to be extractable. That rules out keys held
// by the platform keychain (src/apple/keychain.c creates those non-extractable),
// which is why the keychain key slots are not implemented for this backend.
static int make_identity(struct applesec_ctx* c, struct applesec_priv_key* key,
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
        char *pwhex = c->tmp_keychain_pw;
        _Static_assert(sizeof(c->tmp_keychain_pw) == sizeof(pw) * 2 + 1, "passphrase buffer size");
        if (SecRandomCopyBytes(kSecRandomDefault, sizeof(pw), pw) != errSecSuccess) {
            UM_LOG(ERR, "failed to generate keychain passphrase");
            return -1;
        }
        for (size_t i = 0; i < sizeof(pw); i++) {
            snprintf(pwhex + i * 2, 3, "%02x", pw[i]);
        }
        memset_s(pw, sizeof(pw), 0, sizeof(pw));

        SecKeychainRef kc = NULL;
        OSStatus rc = SecKeychainCreate(path, (UInt32)strlen(pwhex), pwhex, false, NULL, &kc);
        if (rc != errSecSuccess) {
            UM_LOG(ERR, "failed to create temp keychain: %s", applesec_error(rc));
            return -1;
        }
        SecKeychainSetUserInteractionAllowed(false);

        // new keychains lock on sleep: a later import (cert renewal, context
        // reconfiguration) would then fail with errSecAuthFailed
        SecKeychainSettings settings = {
            .version = SEC_KEYCHAIN_SETTINGS_VERS1,
            .lockOnSleep = false,
            .useLockInterval = false,
            .lockInterval = INT_MAX,
        };
        rc = SecKeychainSetSettings(kc, &settings);
        if (rc != errSecSuccess) {
            UM_LOG(WARN, "failed to disable temp keychain auto-lock: %s", applesec_error(rc));
        }

        c->tmp_keychain = kc;
        c->tmp_keychain_path = tlsuv__strdup(path);
    }

    // it may still have been locked explicitly (e.g. `security lock-keychain -a`)
    OSStatus unlock_rc = SecKeychainUnlock(c->tmp_keychain, (UInt32)strlen(c->tmp_keychain_pw),
                                           c->tmp_keychain_pw, true);
    if (unlock_rc != errSecSuccess) {
        UM_LOG(WARN, "failed to unlock temp keychain: %s", applesec_error(unlock_rc));
    }

    // the key has to go in as PEM/DER; use the bytes it was loaded from, or
    // encode a generated key (PKCS#8, which import_key() converts as needed)
    CFDataRef pem = key->pem;
    if (pem == NULL) {
        struct buf out = {0};
        if (private_key_pem(key->key, key->key_type, &out)) {
            pem = CFDataCreate(kCFAllocatorDefault, out.data, (CFIndex)out.len);
        }
        tlsuv__free(out.data);
        if (pem == NULL) {
            UM_LOG(ERR, "failed to export private key");
            return -1;
        }
    }

    CFArrayRef items = NULL;
    OSStatus rc = import_key(pem, c->tmp_keychain, &items);
    if (pem != key->pem) CFRelease(pem);
    if (items) CFRelease(items);

    // same key as a previous set_own_cert (e.g. certificate renewed, key kept): it is
    // already in the keychain, and SecIdentityCreateWithCertificate() will find it
    if (rc == errSecDuplicateItem) {
        UM_LOG(DEBG, "private key already in temp keychain");
        rc = errSecSuccess;
    }

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

#else // iOS and the other embedded platforms: no file keychains

// Neither SecIdentityCreateWithCertificate() nor file keychains exist here: the
// only public way to get a SecIdentityRef is SecItemCopyMatching(kSecClassIdentity)
// over the app's keychain, which pairs a certificate with the private key whose
// public key it carries. So add both to the keychain, look the identity up, and
// delete what was added (kc_items) when the context is freed.
//
// The items are device-only and readable after first unlock, so the identity
// keeps working in the background (e.g. from a network extension). Only items
// this context added are tracked: a key or certificate that is already there
// (another context, or left behind by a process that never freed its context)
// comes back as errSecDuplicateItem and is used, not deleted. Deleting items does
// not invalidate identities already looked up, so a context whose items were
// removed by another one keeps working.
static OSStatus add_keychain_item(struct applesec_ctx* c, CFTypeRef cls, CFTypeRef value) {
    const void* keys[] = {kSecClass, kSecValueRef, kSecAttrAccessible, kSecReturnPersistentRef};
    const void* vals[] = {cls, value, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                          kCFBooleanTrue};
    CFDictionaryRef q = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 4,
                                           &kCFTypeDictionaryKeyCallBacks,
                                           &kCFTypeDictionaryValueCallBacks);
    CFTypeRef ref = NULL;
    OSStatus rc = SecItemAdd(q, &ref);
    CFRelease(q);
    if (rc == errSecSuccess && ref != NULL) {
        if (c->kc_items == NULL) {
            c->kc_items = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        }
        CFArrayAppendValue(c->kc_items, ref);
    }
    if (ref) CFRelease(ref);
    return rc;
}

static void remove_keychain_items(struct applesec_ctx* c) {
    if (c->kc_items == NULL) return;
    for (CFIndex i = 0; i < CFArrayGetCount(c->kc_items); i++) {
        const void* keys[] = {kSecValuePersistentRef};
        const void* vals[] = {CFArrayGetValueAtIndex(c->kc_items, i)};
        CFDictionaryRef q = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 1,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
        OSStatus rc = SecItemDelete(q);
        CFRelease(q);
        if (rc != errSecSuccess && rc != errSecItemNotFound) {
            UM_LOG(WARN, "failed to remove keychain item: %s", applesec_error(rc));
        }
    }
    CFRelease(c->kc_items);
    c->kc_items = NULL;
}

static SecIdentityRef find_identity(SecCertificateRef leaf) {
    const void* keys[] = {kSecClass, kSecReturnRef, kSecMatchLimit};
    const void* vals[] = {kSecClassIdentity, kCFBooleanTrue, kSecMatchLimitAll};
    CFDictionaryRef q = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 3,
                                           &kCFTypeDictionaryKeyCallBacks,
                                           &kCFTypeDictionaryValueCallBacks);
    CFTypeRef found = NULL;
    OSStatus rc = SecItemCopyMatching(q, &found);
    CFRelease(q);
    if (rc != errSecSuccess) {
        UM_LOG(ERR, "failed to look up identity: %s", applesec_error(rc));
        return NULL;
    }

    SecIdentityRef identity = NULL;
    CFArrayRef ids = found;
    for (CFIndex i = 0; identity == NULL && i < CFArrayGetCount(ids); i++) {
        SecIdentityRef id = (SecIdentityRef)CFArrayGetValueAtIndex(ids, i);
        SecCertificateRef cert = NULL;
        if (SecIdentityCopyCertificate(id, &cert) == errSecSuccess) {
            if (CFEqual(cert, leaf)) identity = (SecIdentityRef)CFRetain(id);
            CFRelease(cert);
        }
    }
    CFRelease(found);
    if (identity == NULL) {
        UM_LOG(ERR, "failed to create identity: certificate and key not paired in keychain");
    }
    return identity;
}

static int make_identity(struct applesec_ctx* c, struct applesec_priv_key* key,
                         SecCertificateRef leaf, SecIdentityRef* identity) {
    // a duplicate is the same key or certificate from an earlier set_own_cert
    // (e.g. certificate renewed, key kept); the identity lookup finds it
    OSStatus rc = add_keychain_item(c, kSecClassKey, key->key);
    if (rc != errSecSuccess && rc != errSecDuplicateItem) {
        UM_LOG(ERR, "failed to add private key to keychain: %s", applesec_error(rc));
        return -1;
    }
    rc = add_keychain_item(c, kSecClassCertificate, leaf);
    if (rc != errSecSuccess && rc != errSecDuplicateItem) {
        UM_LOG(ERR, "failed to add certificate to keychain: %s", applesec_error(rc));
        return -1;
    }

    *identity = find_identity(leaf);
    return *identity ? 0 : -1;
}
#endif

static int tls_set_own_cert(tls_context* ctx, tlsuv_private_key_t pk, tlsuv_certificate_t cert) {
    if (ctx == NULL) return -1;
    struct applesec_ctx* c = (struct applesec_ctx*)ctx;

    if (c->ssl_chain) {
        CFRelease(c->ssl_chain);
        c->ssl_chain = NULL;
    }

    if (pk == NULL || cert == NULL) {
        // clearing
        return 0;
    }

    struct applesec_priv_key* key = container_of(pk, struct applesec_priv_key, api);
    struct applesec_cert* cer = container_of(cert, struct applesec_cert, api);

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

// ------------------------------------------------------------------ CSR (PKCS#10)

// subject attribute names as OpenSSL accepts them (short and long), with the
// string type OpenSSL's defaults produce for each
static const struct {
    const char* sn;
    const char* ln;
    const char* oid;
    uint8_t str_tag;
} dn_attrs[] = {
#define PRINTABLE 0x13
#define IA5 0x16
#define UTF8 0x0C
    {"CN", "commonName", "2.5.4.3", UTF8},
    {"SN", "surname", "2.5.4.4", UTF8},
    {"serialNumber", "serialNumber", "2.5.4.5", PRINTABLE},
    {"C", "countryName", "2.5.4.6", PRINTABLE},
    {"L", "localityName", "2.5.4.7", UTF8},
    {"ST", "stateOrProvinceName", "2.5.4.8", UTF8},
    {"street", "streetAddress", "2.5.4.9", UTF8},
    {"O", "organizationName", "2.5.4.10", UTF8},
    {"OU", "organizationalUnitName", "2.5.4.11", UTF8},
    {"title", "title", "2.5.4.12", UTF8},
    {"GN", "givenName", "2.5.4.42", UTF8},
    {"dnQualifier", "dnQualifier", "2.5.4.46", PRINTABLE},
    {"emailAddress", "emailAddress", "1.2.840.113549.1.9.1", IA5},
    {"UID", "userId", "0.9.2342.19200300.100.1.1", UTF8},
    {"DC", "domainComponent", "0.9.2342.19200300.100.1.25", IA5},
#undef PRINTABLE
#undef IA5
#undef UTF8
};

static void der_put_base128(struct buf* b, unsigned long v) {
    uint8_t tmp[10];
    size_t n = 0;
    do {
        tmp[n] = (v & 0x7F) | (n ? 0x80 : 0);
        n++;
        v >>= 7;
    } while (v != 0);
    while (n > 0) {
        buf_put(b, &tmp[--n], 1);
    }
}

// dotted decimal ("2.5.4.3") to a DER OBJECT IDENTIFIER
static bool der_put_oid(struct buf* out, const char* dotted) {
    unsigned long arcs[32];
    size_t n = 0;
    const char* p = dotted;
    while (n < sizeof(arcs) / sizeof(arcs[0])) {
        char* end;
        if (*p < '0' || *p > '9') return false;
        arcs[n++] = strtoul(p, &end, 10);
        if (*end == '\0') break;
        if (*end != '.') return false;
        p = end + 1;
    }
    if (n < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39)) return false;

    struct buf body = {0};
    der_put_base128(&body, arcs[0] * 40 + arcs[1]);
    for (size_t i = 2; i < n; i++) {
        der_put_base128(&body, arcs[i]);
    }
    der_put(out, 0x06, body.data, body.len);
    tlsuv__free(body.data);
    return true;
}

// RelativeDistinguishedName ::= SET { SEQUENCE { type OID, value string } }
static bool der_put_rdn(struct buf* name, const char* id, const char* val) {
    const char* oid = NULL;
    uint8_t tag = 0x0C;
    for (size_t i = 0; i < sizeof(dn_attrs) / sizeof(dn_attrs[0]); i++) {
        if (strcmp(id, dn_attrs[i].sn) == 0 || strcasecmp(id, dn_attrs[i].ln) == 0) {
            oid = dn_attrs[i].oid;
            tag = dn_attrs[i].str_tag;
            break;
        }
    }

    struct buf atv = {0}, seq = {0};
    bool ok = der_put_oid(&atv, oid ? oid : id); // or an OID given in dotted form
    if (ok) {
        der_put(&atv, tag, val, strlen(val));
        der_put(&seq, 0x30, atv.data, atv.len);
        der_put(name, 0x31, seq.data, seq.len);
    } else {
        UM_LOG(WARN, "unknown subject attribute '%s'", id);
    }
    tlsuv__free(atv.data);
    tlsuv__free(seq.data);
    return ok;
}

//   CertificationRequest ::= SEQUENCE {
//       certificationRequestInfo SEQUENCE { version INTEGER (0), subject Name,
//                                           subjectPKInfo SubjectPublicKeyInfo,
//                                           attributes [0] SET OF Attribute (empty) },
//       signatureAlgorithm AlgorithmIdentifier,
//       signature BIT STRING }
// signed with SHA-256, as the OpenSSL backend does
static int generate_csr(tlsuv_private_key_t pk, char** pem, size_t* pemlen, ...) {
    struct applesec_priv_key* key = container_of(pk, struct applesec_priv_key, api);
    struct buf rdns = {0}, info = {0}, cri = {0}, alg = {0}, body = {0}, der = {0}, out = {0};
    CFDataRef sig = NULL;
    int rc = -1;

    va_list va;
    va_start(va, pemlen);
    bool ok = true;
    while (ok) {
        const char* id = va_arg(va, const char*);
        if (id == NULL) break;
        const char* val = va_arg(va, const char*);
        if (val == NULL) break;
        ok = der_put_rdn(&rdns, id, val);
    }
    va_end(va);
    if (!ok) goto done;

    SecKeyAlgorithm sig_alg;
    if (key->key_type == APPLESEC_KEY_EC) {
        sig_alg = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
        der_put_oid(&alg, "1.2.840.10045.4.3.2"); // ecdsa-with-SHA256, no parameters
    } else if (key->key_type == APPLESEC_KEY_RSA) {
        sig_alg = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
        der_put_oid(&alg, "1.2.840.113549.1.1.11"); // sha256WithRSAEncryption
        buf_put(&alg, "\x05\x00", 2);
    } else {
        UM_LOG(WARN, "unsupported private key type");
        goto done;
    }

    SecKeyRef pub = SecKeyCopyPublicKey(key->key);
    if (pub == NULL) {
        UM_LOG(WARN, "failed to derive public key");
        goto done;
    }
    buf_put(&info, "\x02\x01\x00", 3);
    der_put(&info, 0x30, rdns.data, rdns.len);
    ok = spki_der(pub, key->key_type, &info);
    CFRelease(pub);
    if (!ok) goto done;
    buf_put(&info, "\xA0\x00", 2);
    der_put(&cri, 0x30, info.data, info.len);

    CFDataRef tbs = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, cri.data, (CFIndex)cri.len,
                                                kCFAllocatorNull);
    CFErrorRef err = NULL;
    sig = SecKeyCreateSignature(key->key, sig_alg, tbs, &err);
    CFRelease(tbs);
    if (sig == NULL) {
        UM_LOG(WARN, "failed to sign CSR: %s", cferr(err));
        if (err) CFRelease(err);
        goto done;
    }

    buf_put(&body, cri.data, cri.len);
    der_put(&body, 0x30, alg.data, alg.len);
    der_put_bits(&body, CFDataGetBytePtr(sig), CFDataGetLength(sig));
    der_put(&der, 0x30, body.data, body.len);
    pem_put(&out, "CERTIFICATE REQUEST", der.data, der.len);

    size_t len;
    rc = pem_result(&out, pem, &len);
    out.data = NULL; // owned by *pem now
    if (pemlen) *pemlen = len;

done:
    if (sig) CFRelease(sig);
    tlsuv__free(rdns.data);
    tlsuv__free(info.data);
    tlsuv__free(cri.data);
    tlsuv__free(alg.data);
    tlsuv__free(body.data);
    tlsuv__free(der.data);
    tlsuv__free(out.data);
    return rc;
}

// ---------------------------------------------------------------------------

static tls_context ctx_api = {
    .version = tls_lib_version,
    .strerror = tls_strerror,
    .new_engine = applesec_new_engine,
    .new_server_engine = applesec_new_server_engine,
    .free_ctx = tls_free_ctx,
    .set_ca_bundle = tls_set_ca_bundle,
    .set_own_cert = tls_set_own_cert,
    .set_cert_verify = tls_set_cert_verify,
    .parse_pkcs7_certs = parse_pkcs7_certs,
    .generate_key = gen_key,
    .load_key = load_key,
    .load_cert = load_cert,
    .fips_status = tls_fips_status,
    .generate_csr_to_pem = generate_csr,
    // not supported by this backend:
    // .allow_partial_chain
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
    uv_buf_t buf = uv_buf_init(tlsuv__malloc(req.statbuf.st_size), (unsigned int)req.statbuf.st_size);
    uv_fs_req_cleanup(&req);

    file = uv_fs_open(NULL, &req, path, 0, 0, NULL);
    uv_fs_req_cleanup(&req);
    if (file < 0) {
        tlsuv__free(buf.base);
        return file;
    }

    int len = uv_fs_read(NULL, &req, file, &buf, 1, 0, NULL);
    uv_fs_req_cleanup(&req);

    uv_fs_close(NULL, &req, file, NULL);
    uv_fs_req_cleanup(&req);

    if (len < 0) {
        tlsuv__free(buf.base);
        return len;
    }

    *content = buf.base;
    *l = len;
    return 0;
}
