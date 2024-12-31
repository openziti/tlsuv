//
// Created by Eugene Kobyakov on 1/12/24.
//

#include "context.h"
#include "tlsuv/tls_engine.h"
#include "um_debug.h"
#include "util.h"
#include "tlsuv/tlsuv.h"

#include <b64/cdecode.h>

#include <Security/Security.h>
#include <Security/SecKeychain.h>
#include <Security/SecureTransport.h>
#include <Security/SecImportExport.h>

static tls_context ctx_api;
static struct tlsuv_private_key_s sec_key_api;
static struct tlsuv_public_key_s pub_key_api;

static int load_file(const char *path, char **content, size_t *l);
static SecKeyAlgorithm get_hash_algo(enum hash_algo algo, CFStringRef key_type);

static void cert_free(struct tlsuv_certificate_s *);
static int cert_to_pem(const struct tlsuv_certificate_s *, int chain, char **pem, size_t *pem_len);
static int cert_expiration(const struct tlsuv_certificate_s *, struct tm *exp);
static int cert_verify(const struct tlsuv_certificate_s *, enum hash_algo hashAlgo,
                       const char *string, size_t i1,
                       const char *string1, size_t i2);

static struct tlsuv_certificate_s sec_cert_api = {
        .free = cert_free,
        .to_pem = cert_to_pem,
        .get_expiration = cert_expiration,
        .verify = cert_verify,
};


const char* applesec_error(OSStatus code) {
    static char errorbuf[1024];
    CFStringRef err = SecCopyErrorMessageString(code, NULL);
    CFStringGetCString(err, errorbuf, sizeof(errorbuf), kCFStringEncodingUTF8);
    return errorbuf;

}

tls_context* new_applesec_ctx(const char* ca, size_t ca_len) {
    struct sectransport_ctx *ctx = calloc(1, sizeof(*ctx));
    ctx->api = ctx_api;

    if (ca && ca_len > 0) {
        SecExternalItemType type = 0;
        CFArrayRef certs = NULL;

        CFDataRef bundle = CFDataCreate(kCFAllocatorDefault, ca, ca_len);
        OSStatus rc = SecItemImport(bundle, NULL, NULL, &type, 0, NULL, NULL, &ctx->ca_bundle);

        if (rc != errSecSuccess) {
            CFRelease(bundle);

            uv_fs_t req;
            uv_file ca_file;
            if (uv_fs_stat(NULL, &req, ca, NULL) == 0) {
                uv_buf_t ca_buf = uv_buf_init(malloc(req.statbuf.st_size), req.statbuf.st_size);
                uv_fs_req_cleanup(&req);

                ca_file = uv_fs_open(NULL, &req, ca, 0, 0, NULL);
                uv_fs_req_cleanup(&req);

                size_t len = uv_fs_read(NULL, &req, ca_file, &ca_buf, 1, 0, NULL);
                uv_fs_req_cleanup(&req);

                uv_fs_close(NULL, &req, ca_file, NULL);
                bundle = CFDataCreate(kCFAllocatorDefault, ca_buf.base, len);

                rc = SecItemImport(bundle, NULL, NULL, &type, 0, NULL, NULL, &ctx->ca_bundle);
                CFRelease(bundle);
                free(ca_buf.base);
            }
            uv_fs_req_cleanup(&req);
        }

        if (rc != errSecSuccess) {
            UM_LOG(WARN, "failed to load CA bundle: %d/%s", rc, applesec_error(rc));
        }
    }

    return &ctx->api;
}

void tls_free_ctx(tls_context *ctx) {
    free(ctx);
}

static const char *tls_lib_version(void) {
    static char version[64] = {0};
    if (*version == 0) {
        CFBundleRef secBundle = CFBundleGetBundleWithIdentifier(CFSTR("com.apple.security"));
        CFDictionaryRef info = CFBundleGetInfoDictionary(secBundle);
        CFStringRef v1 = CFDictionaryGetValue(info, CFSTR("CFBundleShortVersionString"));
        CFStringRef v2  = CFDictionaryGetValue(info, CFSTR("CFBundleVersion"));

        CFMutableStringRef v = CFStringCreateMutable(kCFAllocatorDefault, 64);
        CFStringAppend(v, CFBundleGetIdentifier(secBundle));
        CFStringAppend(v, CFSTR(" "));
        CFStringAppend(v, v1);
        CFStringAppend(v, CFSTR("/"));
        CFStringAppend(v, v2);

        CFStringGetCString(v, version, sizeof(version), kCFStringEncodingASCII);
        CFRelease(v);
    }
    return version;
}

static int gen_key(tlsuv_private_key_t *key_ref) {
    CFErrorRef err = NULL;
    const void *keys[] = {
            kSecAttrKeyType,
            kSecAttrKeySizeInBits,
    };
    const void *values[] = {
            kSecAttrKeyTypeECSECPrimeRandom,
            CFSTR("256"),
    };
    int nattrs = sizeof(keys)/sizeof(keys[0]);
    CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault,
                                               keys, values, nattrs,
                                               NULL, NULL);

    SecKeyRef k = SecKeyCreateRandomKey(attrs, &err);
    if (err == NULL) {
        struct sectransport_priv_key *pk = calloc(1, sizeof(*pk));
        pk->key = k;
        pk->key_type = CFDictionaryGetValue(attrs, kSecAttrKeyType);
        pk->api = sec_key_api;
        *key_ref = &(pk->api);
    } else {
        UM_LOG(ERR, "failed to generate key");
    }

    CFRelease(attrs);
    int rc = err ? -1 : 0;
    return rc;
}
#define PEM_PRIV_KEY_START "-----BEGIN PRIVATE KEY-----\n"
#define PEM_PRIV_KEY_END "-----END PRIVATE KEY-----"

static int load_key(tlsuv_private_key_t *key_ref, const char *keystr, size_t len) {
    char *key_buf = NULL;
    size_t keylen;
    if (load_file(keystr, &key_buf, &keylen) != 0) {
        key_buf = (char*)keystr;
        keylen = len;
    }
    
    CFDataRef keyData = NULL;
    if (strncmp(key_buf, PEM_PRIV_KEY_START, strlen(PEM_PRIV_KEY_START)) == 0) {
        const char *p = key_buf + strlen(PEM_PRIV_KEY_START);
        const char *e = strstr(p, PEM_PRIV_KEY_END);
        size_t b64_len = e - p;
        size_t dec_len = base64_decode_maxlength(b64_len);
        char *decoded = tlsuv__malloc(dec_len);
        base64_decodestate b64 = {};
        dec_len = base64_decode_block(p, b64_len, decoded, &b64);
        keyData = CFDataCreate(kCFAllocatorDefault, (uint8_t *)p, (CFIndex)b64_len);
        tlsuv__free(decoded);
    }

    CFMutableDictionaryRef keyDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 5, NULL, NULL);
    CFDictionaryAddValue(keyDict, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionaryAddValue(keyDict, kSecAttrKeyType, kSecAttrKeyTypeEC);

    CFErrorRef err = NULL;
    SecKeyRef pKey = SecKeyCreateWithData(keyData, keyDict, &err);
    CFStringRef errdesc = CFErrorCopyDescription(err);
    CFStringRef reason = CFErrorCopyFailureReason(err);
    UM_LOG(WARN, "fallback load failed: %s", applesec_error(CFErrorGetCode(err)));
    CFArrayRef items = NULL;

    SecExternalItemType type = kSecItemTypeUnknown;
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, key_buf, keylen);
    SecItemImportExportFlags flags = kSecKeyNoAccessControl;
    const void *usage[] = {
        kSecAttrCanDecrypt,
        kSecAttrCanSign,
    };
    const void *atts[] = {
            kSecAttrIsExtractable,
    };

    SecItemImportExportKeyParameters params = {
            .keyAttributes = CFArrayCreate(kCFAllocatorDefault, atts, 1, NULL),
            .keyUsage = CFArrayCreate(kCFAllocatorDefault, usage, 2, NULL),
    };
    uint32_t fmt = kSecFormatPEMSequence;
    OSStatus rc = SecItemImport(data, NULL, &fmt, &type, kSecItemPemArmour, NULL, NULL, &items);
    if (rc) {
        UM_LOG(WARN, "fallback load failed: %s", applesec_error(rc));
    }
    if (rc == 0 && type == kSecItemTypePrivateKey) {
        SecKeyRef k = CFArrayGetValueAtIndex(items, 0);
        CFDictionaryRef attrs = SecKeyCopyAttributes(k);
        SecKeyRef p = SecKeyCopyPublicKey(k);
        if (p == NULL) {
            // for some keys Apple security framework loads private key by fails to compute public
            // reloading it with a different method seems to work (nice work Apple!)
            CFDataRef kd = SecKeyCopyExternalRepresentation(k, NULL);
            if (kd) {
                CFErrorRef err = NULL;
                SecKeyRef k1 = SecKeyCreateWithData(kd, attrs, &err);
                if (err) {
                    UM_LOG(WARN, "fallback load failed: %s", applesec_error(CFErrorGetCode(err)));
                    CFRelease(err);
                } else {
                    k = k1;
                }
                CFRelease(kd);
            }
        } else {
            CFRetain(k);
            CFRelease(p);
        }


        struct sectransport_priv_key *pk = calloc(1, sizeof(*pk));
        pk->key = k;
        pk->key_type = CFDictionaryGetValue(attrs, kSecAttrKeyType);
        pk->api = sec_key_api;
        pk->pem = data;

        *key_ref = &(pk->api);

        CFRelease(attrs);
    }

    CFRelease(items);
    if (key_buf != keystr) {
        free(key_buf);
    }
    return rc == 0 ? 0 : -1;
}

static int load_cert(tlsuv_certificate_t *cert, const char *certstr, size_t len) {
    char *cert_buf = NULL;
    size_t cert_len;
    if (load_file(certstr, &cert_buf, &cert_len) != 0) {
        cert_buf = (char*)certstr;
        cert_len = len;
    }

    SecExternalItemType type = kSecItemTypeCertificate;
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, cert_buf, cert_len);

    CFArrayRef items = NULL;
    OSStatus rc = SecItemImport(data, NULL, NULL, &type, 0, NULL, NULL, &items);

    if (cert_buf != certstr) {
        free(cert_buf);
    }
    if (rc == 0) {
        struct sectransport_cert *c = tlsuv__calloc(1, sizeof(*c));
        c->api = sec_cert_api;
        c->chain = items;
        *cert = &c->api;
    }
    CFRelease(data);
    return rc == 0 ? 0 : -1;
}

static int tls_set_own_cert(tls_context *ctx, tlsuv_private_key_t pk, tlsuv_certificate_t cert) {
    if (ctx == NULL) return -1;
    struct sectransport_ctx *c = (struct sectransport_ctx *) ctx;

    if(c->key) CFRelease(c->key);
    if(c->cert) CFRelease(c->cert);

    if (pk) {
        struct sectransport_pub_key *key = container_of(pk, struct sectransport_pub_key, api);
        c->key = CFRetain(key->key);
    }

    if (cert) {
        struct sectransport_cert *cer = container_of(cert, struct sectransport_cert, api);
        c->cert = CFRetain(cer->chain);
    }
    return 0;
}

static int parse_pkcs7_certs(tlsuv_certificate_t *c, const char *pkcs7, size_t len) {

    char *decoded = tlsuv__malloc(base64_decode_maxlength(len));
    base64_decodestate b64_state = {};
    size_t decoded_len = base64_decode_block(pkcs7, len, decoded, &b64_state);

    CFErrorRef error;
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, decoded, (CFIndex)decoded_len);
    CFArrayRef items = NULL;
    uint32_t format = kSecFormatPKCS7;
    uint32_t type = kSecItemTypeCertificate;
    OSStatus rc = SecItemImport(data, NULL, &format, &type, 0, NULL, NULL, &items);

    if (rc == ERR_SUCCESS) {
        struct sectransport_cert *cert = tlsuv__calloc(1, sizeof(*cert));
        cert->api = sec_cert_api;
        cert->chain = items;
        *c = &cert->api;
    }
    CFRelease(data);
    tlsuv__free(decoded);

    return rc == ERR_SUCCESS ? 0 : -1;
}

static tls_context ctx_api = {
        .version = tls_lib_version,
//        .strerror = (const char *(*)(long)) tls_error,
        .new_engine = new_engine,
        .free_ctx = tls_free_ctx,
//        .free_cert = tls_free_cert,
        .set_own_cert = tls_set_own_cert,
//        .set_cert_verify = tls_set_cert_verify,
//        .verify_signature =  tls_verify_signature,
        .parse_pkcs7_certs = parse_pkcs7_certs,
//        .write_cert_to_pem = write_cert_pem,
        .generate_key = gen_key,
        .load_key = load_key,
//        .load_pkcs11_key = load_pkcs11_key,
//        .generate_pkcs11_key = gen_pkcs11_key,
        .load_cert = load_cert,
//       .generate_csr_to_pem = generate_csr,
};

static void privkey_free(struct tlsuv_private_key_s *pk) {
    struct sectransport_priv_key *key = container_of(pk, struct sectransport_priv_key, api);
    CFRelease(key->key);
    free(key);
}

static int privkey_to_pem(struct tlsuv_private_key_s *pk, char **pem, size_t *pemlen) {
    struct sectransport_priv_key *key = container_of(pk, struct sectransport_priv_key, api);
    CFDataRef data = key->pem;

    if (data == NULL) {
        OSStatus rc = SecItemExport(key->key, kSecFormatPEMSequence, kSecItemPemArmour, NULL, &data);

        if (rc != 0) {
            UM_LOG(WARN, "failed to export key as PEM: %s", applesec_error(rc));
            return -1;
        }
    }

    CFIndex size = CFDataGetLength(data);
    *pem = calloc(1, size + 1);
    memcpy(*pem, CFDataGetBytePtr(data), size);
    *pemlen = size;
    if (data != key->pem) {
        CFRelease(data);
    }
    return 0;
}
static struct tlsuv_public_key_s * privkey_pubkey(struct tlsuv_private_key_s *pk) {
    struct sectransport_priv_key *key = container_of(pk, struct sectransport_priv_key, api);
    SecKeyRef pub = SecKeyCopyPublicKey(key->key);
    assert(pub);

    struct sectransport_pub_key *pubkey = calloc(1, sizeof (*pubkey));
    pubkey->api = pub_key_api;
    pubkey->key = pub;
    pubkey->key_type = key->key_type;
    return &pubkey->api;
}
static int privkey_sign(struct tlsuv_private_key_s *pk, enum hash_algo algo, 
                        const char *data, size_t datalen,
                        char *hash, size_t *hashlen) {
    struct sectransport_priv_key *key = container_of(pk, struct sectransport_priv_key, api);
    SecKeyAlgorithm algorithm = get_hash_algo(algo, key->key_type);
    CFDataRef d = CFDataCreate(kCFAllocatorDefault, data, datalen);
    CFErrorRef err = NULL;
    CFDataRef h = SecKeyCreateSignature(key->key, algorithm, d, &err);
    if (err == NULL) {
        *hashlen = CFDataGetLength(h);
        memcpy(hash, CFDataGetBytePtr(h), *hashlen);
        CFRelease(h);
    }
    CFRelease(d);
    return err ? -1 : 0;
}
static int privkey_get_cert(struct tlsuv_private_key_s *, tlsuv_certificate_t *){}
static int privkey_store_cert(struct tlsuv_private_key_s *, tlsuv_certificate_t){}
static struct tlsuv_private_key_s sec_key_api = {
        .free = privkey_free,
        .to_pem = privkey_to_pem,
        .pubkey = privkey_pubkey,
        .sign = privkey_sign,
        .get_certificate = privkey_get_cert,
        .store_certificate = privkey_store_cert,
};


static void pubkey_free(struct tlsuv_public_key_s *pk) {
    struct sectransport_pub_key *key = container_of(pk, struct sectransport_pub_key, api);
    CFRelease(key->key);
    free(key);
}

static int pubkey_to_pem(struct tlsuv_public_key_s *pk, char **pem, size_t *pemlen) {
    struct sectransport_pub_key *key = container_of(pk, struct sectransport_pub_key, api);
    CFDataRef data;
    OSStatus rc = SecItemExport(key->key, kSecFormatPEMSequence, kSecItemPemArmour, NULL, &data);

    if (rc != 0) {
        UM_LOG(WARN, "failed to export key as PEM: %s", applesec_error(rc));
        return -1;
    }

    CFIndex size = CFDataGetLength(data);
    *pem = calloc(1, size + 1);
    memcpy(*pem, CFDataGetBytePtr(data), size);
    *pemlen = size;
    CFRelease(data);
    return 0;
}

static int pubkey_verify(struct tlsuv_public_key_s *pub,
                         enum hash_algo algo, const char *data, size_t datalen,
                         const char *hash, size_t hashlen) {
    struct sectransport_pub_key *key = container_of(pub, struct sectransport_pub_key, api);
    CFErrorRef err = NULL;
    SecKeyAlgorithm algorithm = get_hash_algo(algo, key->key_type);
    CFDataRef d = CFDataCreate(kCFAllocatorDefault, data, datalen);
    CFDataRef h = CFDataCreate(kCFAllocatorDefault, hash, hashlen);
    Boolean v = SecKeyVerifySignature(key->key, algorithm, d, h, &err);

    CFRelease(d);
    CFRelease(h);
    return v ? 0 : -1;
}

static struct tlsuv_public_key_s pub_key_api = {
        .free = pubkey_free,
//        .to_pem = pubkey_to_pem,
        .verify = pubkey_verify,
};

static int load_file(const char *path, char **content, size_t *l) {
    uv_fs_t req;
    uv_file file;
    int rc = uv_fs_stat(NULL, &req, path, NULL);
    if (rc != 0) {
        return rc;
    }

    uv_buf_t buf = uv_buf_init(malloc(req.statbuf.st_size), req.statbuf.st_size);
    uv_fs_req_cleanup(&req);

    file = uv_fs_open(NULL, &req, path, 0, 0, NULL);
    uv_fs_req_cleanup(&req);
    if (file < 0) {
        free(buf.base);
        return file;
    }

    int len = uv_fs_read(NULL, &req, file, &buf, 1, 0, NULL);
    uv_fs_req_cleanup(&req);

    if (len < 0) {
        free(buf.base);
        return len;
    }

    uv_fs_close(NULL, &req, file, NULL);
    *content = buf.base;
    *l = len;
    uv_fs_req_cleanup(&req);
    return 0;
}

static SecKeyAlgorithm get_hash_algo(enum hash_algo algo, CFStringRef key_type) {
    SecKeyAlgorithm algorithm = NULL;
    if (key_type == kSecAttrKeyTypeECSECPrimeRandom) {
        switch (algo) {
            case hash_SHA256:
                algorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
                break;
            case hash_SHA384:
                algorithm = kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA384;
                break;
            case hash_SHA512:
                algorithm = kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA512;
                break;
        }
    } else if (key_type == kSecAttrKeyTypeRSA) {
        switch (algo) {
            case hash_SHA256:
                algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
                break;
            case hash_SHA384:
                algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384;
                break;
            case hash_SHA512:
                algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512;
                break;
        }

    }
    return algorithm;
}

void cert_free(struct tlsuv_certificate_s *c) {
    if (c == NULL) return;

    struct sectransport_cert *cert = container_of(c, struct sectransport_cert, api);
    CFRelease(cert->chain);
    tlsuv__free(cert);
}
int cert_to_pem(const struct tlsuv_certificate_s *c, int chain, char **pem, size_t *pem_len) {
    struct sectransport_cert *cert = container_of(c, struct sectransport_cert, api);
    CFTypeRef exportItem = chain ? cert->chain : CFArrayGetValueAtIndex(cert->chain, 0);
    CFDataRef exportData = NULL;
    OSStatus rc = SecItemExport(exportItem, kSecFormatPEMSequence, 0, NULL, &exportData);
    if (rc == ERR_SUCCESS) {
        CFIndex len = CFDataGetLength(exportData);
        *pem = tlsuv__calloc(1, len + 1);
        CFDataGetBytes(exportData, CFRangeMake(0, len), (uint8_t*) *pem);
        CFRelease(exportData);
        return 0;
    }
    return -1;
}
int cert_expiration(const struct tlsuv_certificate_s *c, struct tm *exp) {
    struct sectransport_cert *cert = container_of(c, struct sectransport_cert, api);

}
int cert_verify(const struct tlsuv_certificate_s *c, enum hash_algo hashAlgo,
                       const char *string, size_t i1,
                       const char *string1, size_t i2) {
    struct sectransport_cert *cert = container_of(c, struct sectransport_cert, api);

}