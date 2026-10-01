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

#ifndef TLSUV_CERT_TEXT_H
#define TLSUV_CERT_TEXT_H

// Text description of a DER encoded X.509 certificate, for the backends whose platform
// library has no X509_print_ex of its own (applesec, win32crypto).
//
// The layout is that of the OpenSSL backend, X509_print_ex(NO_HEADER | NO_SIGDUMP |
// NO_SIGNAME): version, serial, issuer, validity, subject, public key and extensions.
//
// Header only: everything is static, so include it from the one source file of a backend
// that uses it. The renderer's own helpers are prefixed with ct_.
//
//   static char *tlsuv__cert_der_to_text(const uint8_t *der, size_t len);
//       der: one certificate (not a chain)
//       returns NUL terminated text (free with tlsuv__free()), or NULL if it cannot be read
//
//   tlsuv__dn_attrs[], tlsuv__dn_attrs_count
//       subject attribute names as OpenSSL accepts them (short and long), with the ASN.1
//       string type its defaults produce for each
//
//   struct tlsuv_buf, tlsuv__buf_put(), tlsuv__der_next()
//       the byte buffer and DER reader the renderer is built on, for the including file to
//       use for its own DER and PEM work

#include "alloc.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct tlsuv_dn_attr {
    const char* sn;
    const char* ln;
    const char* oid; // dotted decimal
    uint8_t str_tag;
};

// growable byte buffer for building text, DER and PEM
struct tlsuv_buf {
    uint8_t* data;
    size_t len;
    size_t cap;
};

static void tlsuv__buf_put(struct tlsuv_buf* b, const void* bytes, size_t len) {
    if (b->len + len > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->len + len) cap *= 2;
        b->data = tlsuv__realloc(b->data, cap);
        b->cap = cap;
    }
    memcpy(b->data + b->len, bytes, len);
    b->len += len;
}

// reads one DER tag, returning its contents
static bool tlsuv__der_next(const uint8_t** p, const uint8_t* end, uint8_t tag,
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

static const struct tlsuv_dn_attr tlsuv__dn_attrs[] = {
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
static const size_t tlsuv__dn_attrs_count = sizeof(tlsuv__dn_attrs) / sizeof(tlsuv__dn_attrs[0]);

// ------------------------------------------------------- certificate text
//
// The platform libraries of applesec and win32crypto have no counterpart of
// X509_print_ex (SecCertificateCopyValues is macOS only, and the CryptoAPI has no
// printer), so the text is rendered from the certificate's DER. It follows what
// X509_print_ex(NO_HEADER | NO_SIGDUMP | NO_SIGNAME) prints with the OpenSSL
// backend, for the fields consumers look at: version, serial, issuer, validity,
// subject, public key and the common extensions. Others are shown as OpenSSL shows
// an extension it does not know.
//
// Plain C11 with no platform calls: the dates are formatted from their ASN.1 fields.

static void ct_buf_str(struct tlsuv_buf* b, const char* s) {
    tlsuv__buf_put(b, s, strlen(s));
}

#if defined(__GNUC__)
__attribute__((format(printf, 2, 3)))
#endif
static void ct_buf_printf(struct tlsuv_buf* b, const char* fmt, ...) {
    char tmp[256];
    va_list va;
    va_start(va, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, va);
    va_end(va);
    if (n < 0) return;
    if ((size_t)n < sizeof(tmp)) {
        tlsuv__buf_put(b, tmp, n);
        return;
    }

    char* big = tlsuv__malloc(n + 1);
    va_start(va, fmt);
    vsnprintf(big, n + 1, fmt, va);
    va_end(va);
    tlsuv__buf_put(b, big, n);
    tlsuv__free(big);
}

// reads the next DER item whatever its tag
static bool ct_der_any(const uint8_t** p, const uint8_t* end, uint8_t* tag,
                       const uint8_t** body, size_t* bodylen) {
    if (*p >= end) return false;
    *tag = **p;
    return tlsuv__der_next(p, end, *tag, body, bodylen);
}

// dotted decimal of the contents of a DER OBJECT IDENTIFIER
static bool ct_oid_dotted(const uint8_t* d, size_t n, char* out, size_t outlen) {
    if (n == 0) return false;

    size_t pos = 0;
    unsigned long long v = 0;
    bool first = true;
    for (size_t i = 0; i < n; i++) {
        if (v >> 57) return false; // arc does not fit
        v = (v << 7) | (d[i] & 0x7F);
        if (d[i] & 0x80) {
            if (i == n - 1) return false;
            continue;
        }

        int w;
        if (first) {
            unsigned long long arc = v < 40 ? 0 : v < 80 ? 1 : 2;
            w = snprintf(out + pos, outlen - pos, "%llu.%llu", arc, v - arc * 40);
            first = false;
        } else {
            w = snprintf(out + pos, outlen - pos, ".%llu", v);
        }
        if (w < 0 || (size_t)w >= outlen - pos) return false;
        pos += w;
        v = 0;
    }
    return true;
}

// colon separated hex bytes, `per_line` of them on a line (0: all on one), each line
// indented
static void ct_put_hex(struct tlsuv_buf* b, const uint8_t* d, size_t n, int indent, size_t per_line, bool upper) {
    for (size_t i = 0; i < n; i++) {
        if (i == 0 || (per_line && i % per_line == 0)) {
            if (i) ct_buf_str(b, ":\n");
            ct_buf_printf(b, "%*s", indent, "");
        } else {
            ct_buf_str(b, ":");
        }
        ct_buf_printf(b, upper ? "%02X" : "%02x", d[i]);
    }
    ct_buf_str(b, "\n");
}

// a byte of a name as X509_NAME_oneline writes it: anything but ' '..'~' is \xNN
static void ct_put_dn_byte(struct tlsuv_buf* b, uint8_t c) {
    if (c < ' ' || c > '~') {
        ct_buf_printf(b, "\\x%02X", c);
    } else {
        tlsuv__buf_put(b, &c, 1);
    }
}

static void ct_put_dn_value(struct tlsuv_buf* b, uint8_t tag, const uint8_t* v, size_t n) {
    switch (tag) {
        case 0x0C: // UTF8String
        case 0x12: // NumericString
        case 0x13: // PrintableString
        case 0x14: // TeletexString
        case 0x16: // IA5String
        case 0x1A: // VisibleString
            for (size_t i = 0; i < n; i++) ct_put_dn_byte(b, v[i]);
            break;
        case 0x1E: // BMPString (UCS-2): only what fits one byte
            for (size_t i = 0; i + 1 < n; i += 2) ct_put_dn_byte(b, v[i] != 0 ? '?' : v[i + 1]);
            break;
        default:
            ct_buf_str(b, "<unsupported>");
    }
}

// OpenSSL's X509_NAME_print starts the next attribute with ", " only if its name is
// one or two upper case letters (C, ST, CN, ...); otherwise it is left as "/"
// (emailAddress, UID, ...)
static bool ct_is_short_attr(const char* a) {
    size_t n = strlen(a);
    return (n == 1 || n == 2) && a[0] >= 'A' && a[0] <= 'Z' && (n == 1 || (a[1] >= 'A' && a[1] <= 'Z'));
}

// Name ::= SEQUENCE OF RelativeDistinguishedName, printed as OpenSSL does by default:
// short names, ", " (or "/") between RDNs and "+" between the attributes of one.
// `oneline` is the "/C=US/CN=name" form, used for directory names in extensions.
static bool ct_put_name(struct tlsuv_buf* b, const uint8_t* name, size_t namelen, bool oneline) {
    const uint8_t *p = name, *end = name + namelen;
    bool first_rdn = true;
    while (p < end) {
        const uint8_t* set;
        size_t setlen;
        if (!tlsuv__der_next(&p, end, 0x31, &set, &setlen)) return false;

        const uint8_t *q = set, *qend = set + setlen;
        bool first_atv = true;
        while (q < qend) {
            const uint8_t *atv, *oid, *val;
            size_t atvlen, oidlen, vallen;
            uint8_t vtag;
            if (!tlsuv__der_next(&q, qend, 0x30, &atv, &atvlen)) return false;

            const uint8_t *a = atv, *aend = atv + atvlen;
            if (!tlsuv__der_next(&a, aend, 0x06, &oid, &oidlen) || !ct_der_any(&a, aend, &vtag, &val, &vallen)) return false;

            char dotted[64];
            if (!ct_oid_dotted(oid, oidlen, dotted, sizeof(dotted))) return false;
            const char* attr = dotted;
            for (size_t i = 0; i < tlsuv__dn_attrs_count; i++) {
                if (strcmp(dotted, tlsuv__dn_attrs[i].oid) == 0) {
                    attr = tlsuv__dn_attrs[i].sn;
                    break;
                }
            }

            if (oneline) {
                ct_buf_str(b, "/");
            } else if (!first_atv) {
                ct_buf_str(b, "+");
            } else if (!first_rdn) {
                ct_buf_str(b, ct_is_short_attr(attr) ? ", " : "/");
            }
            ct_buf_str(b, attr);
            ct_buf_str(b, "=");
            ct_put_dn_value(b, vtag, val, vallen);
            first_atv = false;
        }
        first_rdn = false;
    }
    return true;
}

// `n` digits at s[off], or -1 if one of them is not a digit
static int ct_digits(const uint8_t* s, size_t off, size_t n) {
    int v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[off + i] < '0' || s[off + i] > '9') return -1;
        v = v * 10 + (s[off + i] - '0');
    }
    return v;
}

// UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ), UTC only, as OpenSSL
// prints it: "Jul 31 17:25:35 2024 GMT"
static bool ct_put_time(struct tlsuv_buf* b, uint8_t tag, const uint8_t* v, size_t n) {
    static const char* const MONTHS[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    size_t ylen = tag == 0x17 ? 2 : 4;
    if ((tag != 0x17 && tag != 0x18) || n != ylen + 11 || v[n - 1] != 'Z') return false;

    int year = ct_digits(v, 0, ylen);
    int mon = ct_digits(v, ylen, 2);
    int day = ct_digits(v, ylen + 2, 2);
    int hour = ct_digits(v, ylen + 4, 2);
    int min = ct_digits(v, ylen + 6, 2);
    int sec = ct_digits(v, ylen + 8, 2);
    if (year < 0 || mon < 1 || mon > 12 || day < 1 || day > 31 || hour < 0 || hour > 23 ||
        min < 0 || min > 59 || sec < 0 || sec > 60) {
        return false;
    }
    if (ylen == 2) year += year < 50 ? 2000 : 1900; // RFC 5280 4.1.2.5.1

    ct_buf_printf(b, "%s %2d %02d:%02d:%02d %d GMT", MONTHS[mon - 1], day, hour, min, sec, year);
    return true;
}

static void ct_put_serial(struct tlsuv_buf* b, const uint8_t* s, size_t n) {
    bool negative = n > 0 && (s[0] & 0x80);
    while (n > 1 && s[0] == 0) { // sign padding
        s++;
        n--;
    }

    if (!negative && n <= 8) {
        unsigned long long v = 0;
        for (size_t i = 0; i < n; i++) v = (v << 8) | s[i];
        ct_buf_printf(b, "        Serial Number: %llu (0x%llx)\n", v, v);
    } else {
        ct_buf_printf(b, "        Serial Number:%s\n", negative ? " (Negative)" : "");
        ct_put_hex(b, s, n, 12, 0, false);
    }
}

// INTEGER contents as an unsigned number, if it fits
static bool ct_der_uint(const uint8_t* s, size_t n, unsigned long long* v) {
    while (n > 1 && s[0] == 0) {
        s++;
        n--;
    }
    if (n == 0 || n > 8 || (s[0] & 0x80 && n == 8)) return false;
    *v = 0;
    for (size_t i = 0; i < n; i++) *v = (*v << 8) | s[i];
    return true;
}

static const struct {
    const char* oid;
    const char* name;
    const char* nist;
    int bits;
} ct_ec_curves[] = {
    {"1.2.840.10045.3.1.7", "prime256v1", "P-256", 256},
    {"1.3.132.0.34", "secp384r1", "P-384", 384},
    {"1.3.132.0.35", "secp521r1", "P-521", 521},
    {"1.3.132.0.10", "secp256k1", NULL, 256},
};

// SubjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE { OID, parameters }, subjectPublicKey BIT STRING }
static bool ct_put_public_key(struct tlsuv_buf* b, const uint8_t* spki, size_t len) {
    const uint8_t *p = spki, *end = spki + len;
    const uint8_t *alg, *oid, *key;
    size_t alglen, oidlen, keylen;
    if (!tlsuv__der_next(&p, end, 0x30, &alg, &alglen)) return false;
    if (!tlsuv__der_next(&p, end, 0x03, &key, &keylen) || keylen < 1) return false;
    key++; // unused bits
    keylen--;

    const uint8_t *a = alg, *aend = alg + alglen;
    if (!tlsuv__der_next(&a, aend, 0x06, &oid, &oidlen)) return false;
    char dotted[64];
    if (!ct_oid_dotted(oid, oidlen, dotted, sizeof(dotted))) return false;

    if (strcmp(dotted, "1.2.840.113549.1.1.1") == 0) { // rsaEncryption
        const uint8_t *k = key, *kend = key + keylen;
        const uint8_t *seq, *mod, *exp;
        size_t seqlen, modlen, explen;
        if (!tlsuv__der_next(&k, kend, 0x30, &seq, &seqlen)) return false;
        k = seq;
        kend = seq + seqlen;
        if (!tlsuv__der_next(&k, kend, 0x02, &mod, &modlen) || !tlsuv__der_next(&k, kend, 0x02, &exp, &explen)) return false;
        if (modlen == 0) return false;
        while (modlen > 1 && mod[0] == 0) {
            mod++;
            modlen--;
        }
        size_t bits = modlen * 8;
        for (uint8_t top = mod[0]; top && !(top & 0x80); top <<= 1) bits--;

        ct_buf_str(b, "            Public Key Algorithm: rsaEncryption\n");
        ct_buf_printf(b, "                Public-Key: (%llu bit)\n", (unsigned long long)bits);
        ct_buf_str(b, "                Modulus:\n");
        // OpenSSL keeps the sign padding byte in the dump
        if (mod[0] & 0x80) {
            struct tlsuv_buf m = {0};
            uint8_t zero = 0;
            tlsuv__buf_put(&m, &zero, 1);
            tlsuv__buf_put(&m, mod, modlen);
            ct_put_hex(b, m.data, m.len, 20, 15, false);
            tlsuv__free(m.data);
        } else {
            ct_put_hex(b, mod, modlen, 20, 15, false);
        }
        unsigned long long e;
        if (ct_der_uint(exp, explen, &e)) {
            ct_buf_printf(b, "                Exponent: %llu (0x%llx)\n", e, e);
        }
        return true;
    }

    if (strcmp(dotted, "1.2.840.10045.2.1") == 0) { // id-ecPublicKey
        const uint8_t* curve;
        size_t curvelen;
        char curve_oid[64];
        if (!tlsuv__der_next(&a, aend, 0x06, &curve, &curvelen) ||
            !ct_oid_dotted(curve, curvelen, curve_oid, sizeof(curve_oid))) {
            return false;
        }

        ct_buf_str(b, "            Public Key Algorithm: id-ecPublicKey\n");
        const char *name = curve_oid, *nist = NULL;
        for (size_t i = 0; i < sizeof(ct_ec_curves) / sizeof(ct_ec_curves[0]); i++) {
            if (strcmp(curve_oid, ct_ec_curves[i].oid) == 0) {
                ct_buf_printf(b, "                Public-Key: (%d bit)\n", ct_ec_curves[i].bits);
                name = ct_ec_curves[i].name;
                nist = ct_ec_curves[i].nist;
                break;
            }
        }
        ct_buf_str(b, "                pub:\n");
        ct_put_hex(b, key, keylen, 20, 15, false);
        ct_buf_printf(b, "                ASN1 OID: %s\n", name);
        if (nist) ct_buf_printf(b, "                NIST CURVE: %s\n", nist);
        return true;
    }

    // RFC 8410 keys: the algorithm has no parameters and the key is the raw point
    static const struct {
        const char* oid;
        const char* name;
    } raw_keys[] = {
        {"1.3.101.110", "X25519"},
        {"1.3.101.111", "X448"},
        {"1.3.101.112", "ED25519"},
        {"1.3.101.113", "ED448"},
    };
    for (size_t i = 0; i < sizeof(raw_keys) / sizeof(raw_keys[0]); i++) {
        if (strcmp(dotted, raw_keys[i].oid) == 0) {
            ct_buf_printf(b, "            Public Key Algorithm: %s\n", raw_keys[i].name);
            ct_buf_printf(b, "                %s Public-Key:\n", raw_keys[i].name);
            ct_buf_str(b, "                pub:\n");
            ct_put_hex(b, key, keylen, 20, 15, false);
            return true;
        }
    }

    ct_buf_printf(b, "            Public Key Algorithm: %s\n", dotted);
    return true;
}

static const struct {
    const char* oid;
    const char* name;
} ct_ext_key_usages[] = {
    {"1.3.6.1.5.5.7.3.1", "TLS Web Server Authentication"},
    {"1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication"},
    {"1.3.6.1.5.5.7.3.3", "Code Signing"},
    {"1.3.6.1.5.5.7.3.4", "E-mail Protection"},
    {"1.3.6.1.5.5.7.3.8", "Time Stamping"},
    {"1.3.6.1.5.5.7.3.9", "OCSP Signing"},
    {"2.5.29.37.0", "Any Extended Key Usage"},
};

static const char* const CT_KEY_USAGES[] = {
    "Digital Signature", "Non Repudiation", "Key Encipherment", "Data Encipherment", "Key Agreement",
    "Certificate Sign",  "CRL Sign",        "Encipher Only",    "Decipher Only",
};

#define CT_EXT_INDENT "                "

// the body of one extension (the contents of its extnValue OCTET STRING)
static bool ct_put_ext_value(struct tlsuv_buf* b, const char* oid, const uint8_t* v, size_t n) {
    const uint8_t *p = v, *end = v + n;
    const uint8_t* item;
    size_t itemlen;

    if (strcmp(oid, "2.5.29.14") == 0) { // subject key identifier
        if (!tlsuv__der_next(&p, end, 0x04, &item, &itemlen)) return false;
        ct_put_hex(b, item, itemlen, 16, 0, true);
    } else if (strcmp(oid, "2.5.29.35") == 0) { // authority key identifier
        //   AuthorityKeyIdentifier ::= SEQUENCE { [0] keyIdentifier, [1] authorityCertIssuer,
        //                                         [2] authorityCertSerialNumber }
        // OpenSSL labels the parts only if there is more than the key identifier
        if (!tlsuv__der_next(&p, end, 0x30, &item, &itemlen)) return false;
        const uint8_t *k = item, *kend = item + itemlen;
        const uint8_t* id = NULL;
        const uint8_t* issuer = NULL;
        const uint8_t* serial = NULL;
        size_t idlen = 0, issuerlen = 0, seriallen = 0;
        while (k < kend) {
            uint8_t tag;
            const uint8_t* body;
            size_t bodylen;
            if (!ct_der_any(&k, kend, &tag, &body, &bodylen)) return false;
            if (tag == 0x80) {
                id = body;
                idlen = bodylen;
            } else if (tag == 0xA1) {
                issuer = body;
                issuerlen = bodylen;
            } else if (tag == 0x82) {
                serial = body;
                seriallen = bodylen;
            }
        }

        bool labels = issuer != NULL || serial != NULL;
        if (id) {
            if (labels) {
                ct_buf_str(b, CT_EXT_INDENT "keyid:");
                ct_put_hex(b, id, idlen, 0, 0, true);
            } else {
                ct_put_hex(b, id, idlen, 16, 0, true);
            }
        }
        if (issuer) { // GeneralNames: only directory names [4] are shown
            const uint8_t *g = issuer, *gend = issuer + issuerlen;
            while (g < gend) {
                uint8_t tag;
                const uint8_t* name;
                size_t namelen;
                if (!ct_der_any(&g, gend, &tag, &name, &namelen)) return false;
                if (tag != 0xA4) continue;

                const uint8_t* dn = name;
                const uint8_t* seq;
                size_t seqlen;
                if (!tlsuv__der_next(&dn, name + namelen, 0x30, &seq, &seqlen)) return false;
                ct_buf_str(b, CT_EXT_INDENT "DirName:");
                if (!ct_put_name(b, seq, seqlen, true)) return false;
                ct_buf_str(b, "\n");
            }
        }
        if (serial) {
            ct_buf_str(b, CT_EXT_INDENT "serial:");
            ct_put_hex(b, serial, seriallen, 0, 0, true);
        }
    } else if (strcmp(oid, "2.5.29.19") == 0) { // basic constraints
        if (!tlsuv__der_next(&p, end, 0x30, &item, &itemlen)) return false;
        const uint8_t *c = item, *cend = item + itemlen;
        const uint8_t* f;
        size_t flen;
        bool ca = false;
        if (c < cend && *c == 0x01) {
            if (!tlsuv__der_next(&c, cend, 0x01, &f, &flen) || flen != 1) return false;
            ca = f[0] != 0;
        }
        ct_buf_str(b, ca ? CT_EXT_INDENT "CA:TRUE" : CT_EXT_INDENT "CA:FALSE");
        unsigned long long pathlen;
        if (c < cend) {
            if (!tlsuv__der_next(&c, cend, 0x02, &f, &flen) || !ct_der_uint(f, flen, &pathlen)) return false;
            ct_buf_printf(b, ", pathlen:%llu", pathlen);
        }
        ct_buf_str(b, "\n");
    } else if (strcmp(oid, "2.5.29.15") == 0) { // key usage
        if (!tlsuv__der_next(&p, end, 0x03, &item, &itemlen) || itemlen < 1) return false;
        ct_buf_str(b, CT_EXT_INDENT);
        bool first = true;
        for (size_t bit = 0; bit < sizeof(CT_KEY_USAGES) / sizeof(CT_KEY_USAGES[0]); bit++) {
            if (1 + bit / 8 < itemlen && (item[1 + bit / 8] & (0x80 >> (bit % 8)))) {
                if (!first) ct_buf_str(b, ", ");
                ct_buf_str(b, CT_KEY_USAGES[bit]);
                first = false;
            }
        }
        ct_buf_str(b, "\n");
    } else if (strcmp(oid, "2.5.29.37") == 0) { // extended key usage
        if (!tlsuv__der_next(&p, end, 0x30, &item, &itemlen)) return false;
        const uint8_t *k = item, *kend = item + itemlen;
        ct_buf_str(b, CT_EXT_INDENT);
        bool first = true;
        while (k < kend) {
            const uint8_t* o;
            size_t olen;
            char dotted[64];
            if (!tlsuv__der_next(&k, kend, 0x06, &o, &olen) || !ct_oid_dotted(o, olen, dotted, sizeof(dotted))) return false;
            const char* name = dotted;
            for (size_t i = 0; i < sizeof(ct_ext_key_usages) / sizeof(ct_ext_key_usages[0]); i++) {
                if (strcmp(dotted, ct_ext_key_usages[i].oid) == 0) {
                    name = ct_ext_key_usages[i].name;
                    break;
                }
            }
            if (!first) ct_buf_str(b, ", ");
            ct_buf_str(b, name);
            first = false;
        }
        ct_buf_str(b, "\n");
    } else if (strcmp(oid, "2.5.29.17") == 0) { // subject alternative name
        if (!tlsuv__der_next(&p, end, 0x30, &item, &itemlen)) return false;
        const uint8_t *g = item, *gend = item + itemlen;
        ct_buf_str(b, CT_EXT_INDENT);
        bool first = true;
        while (g < gend) {
            uint8_t tag;
            const uint8_t* name;
            size_t namelen;
            if (!ct_der_any(&g, gend, &tag, &name, &namelen)) return false;

            if (!first) ct_buf_str(b, ", ");
            first = false;
            switch (tag) {
                case 0x81:
                    ct_buf_str(b, "email:");
                    tlsuv__buf_put(b, name, namelen);
                    break;
                case 0x82:
                    ct_buf_str(b, "DNS:");
                    tlsuv__buf_put(b, name, namelen);
                    break;
                case 0x86:
                    ct_buf_str(b, "URI:");
                    tlsuv__buf_put(b, name, namelen);
                    break;
                case 0x87:
                    ct_buf_str(b, "IP Address:");
                    if (namelen == 4) {
                        ct_buf_printf(b, "%u.%u.%u.%u", name[0], name[1], name[2], name[3]);
                    } else if (namelen == 16) {
                        for (size_t i = 0; i < 16; i += 2) {
                            ct_buf_printf(b, i ? ":%X" : "%X", (name[i] << 8) | name[i + 1]);
                        }
                    } else {
                        ct_buf_str(b, "<invalid>");
                    }
                    break;
                case 0xA4: { // directoryName
                    const uint8_t* dn = name;
                    const uint8_t* seq;
                    size_t seqlen;
                    ct_buf_str(b, "DirName:");
                    if (!tlsuv__der_next(&dn, name + namelen, 0x30, &seq, &seqlen) || !ct_put_name(b, seq, seqlen, true)) {
                        return false;
                    }
                    break;
                }
                default:
                    ct_buf_str(b, "<unsupported>");
            }
        }
        ct_buf_str(b, "\n");
    } else {
        // not decoded: the raw value as OpenSSL shows it (ASN1_STRING_print)
        ct_buf_str(b, CT_EXT_INDENT);
        for (size_t i = 0; i < n; i++) {
            char c = (v[i] >= ' ' && v[i] <= '~') || v[i] == '\n' || v[i] == '\r' ? (char)v[i] : '.';
            tlsuv__buf_put(b, &c, 1);
        }
        ct_buf_str(b, "\n");
    }
    return true;
}

static const struct {
    const char* oid;
    const char* name;
} ct_ext_names[] = {
    {"2.5.29.14", "X509v3 Subject Key Identifier"},
    {"2.5.29.35", "X509v3 Authority Key Identifier"},
    {"2.5.29.19", "X509v3 Basic Constraints"},
    {"2.5.29.15", "X509v3 Key Usage"},
    {"2.5.29.37", "X509v3 Extended Key Usage"},
    {"2.5.29.17", "X509v3 Subject Alternative Name"},
};

// extensions [3] EXPLICIT SEQUENCE OF SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
//                                                  extnValue OCTET STRING }
static bool ct_put_extensions(struct tlsuv_buf* b, const uint8_t* exts, size_t len) {
    const uint8_t *p = exts, *end = exts + len;
    const uint8_t* list;
    size_t listlen;
    if (!tlsuv__der_next(&p, end, 0x30, &list, &listlen)) return false;

    ct_buf_str(b, "        X509v3 extensions:\n");
    p = list;
    end = list + listlen;
    while (p < end) {
        const uint8_t* ext;
        size_t extlen;
        if (!tlsuv__der_next(&p, end, 0x30, &ext, &extlen)) return false;

        const uint8_t *e = ext, *eend = ext + extlen;
        const uint8_t *oid, *flag, *value;
        size_t oidlen, flaglen, valuelen;
        bool critical = false;
        if (!tlsuv__der_next(&e, eend, 0x06, &oid, &oidlen)) return false;
        if (e < eend && *e == 0x01) {
            if (!tlsuv__der_next(&e, eend, 0x01, &flag, &flaglen) || flaglen != 1) return false;
            critical = flag[0] != 0;
        }
        if (!tlsuv__der_next(&e, eend, 0x04, &value, &valuelen)) return false;

        char dotted[64];
        if (!ct_oid_dotted(oid, oidlen, dotted, sizeof(dotted))) return false;
        const char* name = dotted;
        for (size_t i = 0; i < sizeof(ct_ext_names) / sizeof(ct_ext_names[0]); i++) {
            if (strcmp(dotted, ct_ext_names[i].oid) == 0) {
                name = ct_ext_names[i].name;
                break;
            }
        }
        ct_buf_printf(b, "            %s: %s\n", name, critical ? "critical" : "");
        if (!ct_put_ext_value(b, dotted, value, valuelen)) {
            ct_buf_str(b, CT_EXT_INDENT "<invalid>\n");
        }
    }
    return true;
}

//   TBSCertificate ::= SEQUENCE { [0] version DEFAULT v1, serialNumber, signature, issuer,
//                                 validity SEQUENCE { notBefore, notAfter }, subject,
//                                 subjectPublicKeyInfo, [1] issuerUID, [2] subjectUID,
//                                 [3] extensions }
// returns NUL terminated text, or NULL if the certificate cannot be read
static char* tlsuv__cert_der_to_text(const uint8_t* der, size_t derlen) {
    struct tlsuv_buf out = {0};
    bool ok = false;

    const uint8_t *p = der, *end = der + derlen;
    const uint8_t *item, *serial, *issuer, *validity, *subject, *spki;
    size_t itemlen, seriallen, issuerlen, validitylen, subjectlen, spkilen;
    if (!tlsuv__der_next(&p, end, 0x30, &item, &itemlen)) goto done; // Certificate
    p = item;
    end = item + itemlen;
    if (!tlsuv__der_next(&p, end, 0x30, &item, &itemlen)) goto done; // tbsCertificate
    p = item;
    end = item + itemlen;

    unsigned long long version = 0;
    if (p < end && *p == 0xA0) {
        const uint8_t* v;
        size_t vlen;
        if (!tlsuv__der_next(&p, end, 0xA0, &item, &itemlen)) goto done;
        const uint8_t* i = item;
        if (!tlsuv__der_next(&i, item + itemlen, 0x02, &v, &vlen) || !ct_der_uint(v, vlen, &version)) goto done;
    }
    if (!tlsuv__der_next(&p, end, 0x02, &serial, &seriallen)) goto done;
    if (!tlsuv__der_next(&p, end, 0x30, &item, &itemlen)) goto done; // signature algorithm
    if (!tlsuv__der_next(&p, end, 0x30, &issuer, &issuerlen)) goto done;
    if (!tlsuv__der_next(&p, end, 0x30, &validity, &validitylen)) goto done;
    if (!tlsuv__der_next(&p, end, 0x30, &subject, &subjectlen)) goto done;
    if (!tlsuv__der_next(&p, end, 0x30, &spki, &spkilen)) goto done;

    ct_buf_printf(&out, "        Version: %llu (0x%llx)\n", version + 1, version);
    ct_put_serial(&out, serial, seriallen);
    ct_buf_str(&out, "        Issuer: ");
    if (!ct_put_name(&out, issuer, issuerlen, false)) goto done;
    ct_buf_str(&out, "\n        Validity\n            Not Before: ");

    const uint8_t* t = validity;
    const uint8_t* tend = validity + validitylen;
    uint8_t tag;
    if (!ct_der_any(&t, tend, &tag, &item, &itemlen) || !ct_put_time(&out, tag, item, itemlen)) goto done;
    ct_buf_str(&out, "\n            Not After : ");
    if (!ct_der_any(&t, tend, &tag, &item, &itemlen) || !ct_put_time(&out, tag, item, itemlen)) goto done;

    ct_buf_str(&out, "\n        Subject: ");
    if (!ct_put_name(&out, subject, subjectlen, false)) goto done;
    ct_buf_str(&out, "\n        Subject Public Key Info:\n");
    // ct_put_public_key wants the SubjectPublicKeyInfo contents
    if (!ct_put_public_key(&out, spki, spkilen)) goto done;

    while (p < end) { // issuerUID, subjectUID, extensions
        uint8_t utag;
        if (!ct_der_any(&p, end, &utag, &item, &itemlen)) goto done;
        if (utag == 0xA3 && !ct_put_extensions(&out, item, itemlen)) goto done;
    }
    ok = true;

done:
    if (!ok) {
        tlsuv__free(out.data);
        return NULL;
    }
    tlsuv__buf_put(&out, "", 1); // NUL
    return (char*)out.data;
}

#undef CT_EXT_INDENT

#endif // TLSUV_CERT_TEXT_H
