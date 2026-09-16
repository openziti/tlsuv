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

#ifndef TLSUV_ENGINE_H
#define TLSUV_ENGINE_H

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum tls_handshake_st {
    TLS_HS_BEFORE,
    TLS_HS_CONTINUE,
    TLS_HS_COMPLETE,
    TLS_HS_ERROR
} tls_handshake_state;

enum TLS_RESULT {
    TLS_OK = 0,
    TLS_ERR = -1,
    TLS_EOF = -2,
    TLS_AGAIN = -3,

    TLS_MORE_AVAILABLE = -4,
    TLS_HAS_WRITE = -5,
};

enum hash_algo {
    hash_SHA256,
    hash_SHA384,
    hash_SHA512
};

#ifdef _WIN32

#ifndef _WIN32_WINNT
# define _WIN32_WINNT   0x0a00
#endif
#include <winsock2.h>
typedef SOCKET tlsuv_sock_t;
#else
#include <stdint.h>
typedef int tlsuv_sock_t;
#endif

#if !defined(_SSIZE_T_) && !defined(_SSIZE_T_DEFINED)
typedef intptr_t ssize_t;
# if !defined SSIZE_MAX
#  define SSIZE_MAX INTPTR_MAX
# endif
# define _SSIZE_T_
# define _SSIZE_T_DEFINED
#endif

typedef struct tlsuv_engine_s *tlsuv_engine_t;
typedef struct tlsuv_certificate_s *tlsuv_certificate_t;

typedef void* io_ctx;
typedef ssize_t (*io_read)(io_ctx, char *buf, size_t len);
typedef ssize_t (*io_write)(io_ctx, const char *buf, size_t len);

struct tlsuv_engine_s {

    /**
     * set TLS engine abstract IO
     * @param self engine
     * @param ctx IO object passed into [io_read] and [io_write] callbacks
     * @param read_fn read callback, called when TLS engine requires input SSL bytes
     * @param write_fn write callback, called when TLS engine requires output SSL bytes
     */
    void (*set_io)(tlsuv_engine_t self, io_ctx ctx, io_read read_fn, io_write write_fn);

    /**
     * sets TLS engine file descriptor IO (usually socket)
     * @param self engine
     * @param fd file descriptor
     */
    void (*set_io_fd)(tlsuv_engine_t self, tlsuv_sock_t fd);

    /**
     * set ALPN protocols.
     *
     * On a client engine this is the list of protocols offered to the server.
     * On a server engine (see tls_context_s::new_server_engine()) this is the list
     * of *supported* protocols: the first entry that the client also offered is
     * selected. When there is no overlap the handshake completes without ALPN.
     *
     * @param self
     * @param protocols
     * @param len
     */
    void (*set_protocols)(tlsuv_engine_t self, const char **protocols, int len);

    tls_handshake_state (*handshake_state)(tlsuv_engine_t self);

    /**
     * Initiates/continues TLS handshake.
     * @param self
     */
    tls_handshake_state (*handshake)(tlsuv_engine_t self);

    /**
     * Returns negotiated ALPN
     * @param self
     */
    const char* (*get_alpn)(tlsuv_engine_t self);

    /**
     * Generate TSL close notify.
     * @param self
     */
    int (*close)(tlsuv_engine_t self);

    /**
      * writes application data into ssl stream
      * @param self engine instance
      * @param data
      * @param data_len
      * @return number of written bytes or error
      */
    int (*write)(tlsuv_engine_t self, const char *data, size_t data_len);

    /**
     * read application bytes from ssl stream.
     * @param self engine instance
     * @param out buffer for application data
     * @param out_bytes number of bytes received
     * @param maxout size of out buffer
     * @return [TLS_OK] - successful read, no more data for reading
     *         [TLS_MORE_AVAILABLE] - successful read, more data available for reading
     *         [TLS_AGAIN] - no more data is available from underlying IO
     *         [TLS_EOF] - peer send close notify
     *         [TLS_ERR] - TLS engine encountered a TLS error
     */
    int (*read)(tlsuv_engine_t self, char *out, size_t *out_bytes, size_t maxout);

    const char* (*strerror)(tlsuv_engine_t engine);

    /**
     * resets state of the engine so it can be used on the next connection.
     * @param self engine instance
     */
    int (*reset)(tlsuv_engine_t self);

    /**
     * frees the engine
     * @param self engine instance
     */
    void (*free)(tlsuv_engine_t self);

    /**
     * Retrieves the peer certificate chain after a completed handshake.
     *
     * On a server engine this is the client certificate. Client certificates are
     * optional, so a successful handshake does not imply that one is present.
     * On a client engine this is the server certificate.
     *
     * The returned handle is owned by the caller: release it with cert->free(cert).
     *
     * Optional: may be NULL when the TLS backend does not implement it, so always
     * check before calling.
     *
     * @param self engine
     * @param cert (out) receives the certificate handle, set to NULL on failure
     * @return 0 on success, [TLS_ERR] if the peer presented no certificate,
     *         the handshake has not completed, or the operation is unsupported
     */
    int (*get_peer_cert)(tlsuv_engine_t self, tlsuv_certificate_t *cert);
};

typedef struct tls_context_s tls_context;
typedef struct tlsuv_public_key_s *tlsuv_public_key_t;
typedef struct tlsuv_private_key_s *tlsuv_private_key_t;

#define TLSUV_CERT_API                                                              \
    void (*free)(struct tlsuv_certificate_s * cert);                                \
    int (*to_pem)(const struct tlsuv_certificate_s * cert, int full, char **pem, size_t *pemlen);   \
    int (*get_expiration)(const struct tlsuv_certificate_s * cert, struct tm *);          \
    const char* (*get_text)(const struct tlsuv_certificate_s * cert);                     \
    int (*verify)(const struct tlsuv_certificate_s * cert, enum hash_algo md,             \
                  const char *data, size_t datalen, const char *sig, size_t siglen);

#define TLSUV_PUBKEY_API                                                           \
    void (*free)(struct tlsuv_public_key_s * pubkey);                              \
    int (*to_pem)(struct tlsuv_public_key_s * pubkey, char **pem, size_t *pemlen); \
    int (*verify)(struct tlsuv_public_key_s * pubkey, enum hash_algo md,           \
                  const char *data, size_t datalen, const char *sig, size_t siglen);

#define TLSUV_PRIVKEY_API                                                            \
    void (*free)(struct tlsuv_private_key_s * privkey);                              \
    int (*sign)(struct tlsuv_private_key_s * privkey, enum hash_algo md,             \
                const char *data, size_t datalen, char *sig, size_t *siglen);        \
    struct tlsuv_public_key_s *(*pubkey)(struct tlsuv_private_key_s * privkey);      \
    int (*to_pem)(struct tlsuv_private_key_s * privkey, char **pem, size_t *pemlen); \
    int (*get_certificate)(struct tlsuv_private_key_s * privkey, tlsuv_certificate_t * cert);   \
    int (*store_certificate)(struct tlsuv_private_key_s *privkey, tlsuv_certificate_t cert);

struct tlsuv_public_key_s {
    TLSUV_PUBKEY_API
};

struct tlsuv_private_key_s {
    TLSUV_PRIVKEY_API
};

struct tlsuv_certificate_s {
    TLSUV_CERT_API
};

enum tls_fips_status {
    TLS_FIPS_UNSUPPORTED = -1, /* backend has no FIPS mode, or cannot report it */
    TLS_FIPS_DISABLED = 0, /* backend supports FIPS, but it is not active */
    TLS_FIPS_ENABLED = 1, /* FIPS validated crypto is in effect */
};

struct tls_context_s {
    /* creates new TLS engine for a host */
    tlsuv_engine_t (*new_engine)(tls_context *ctx, const char *host);

    void (*free_ctx)(tls_context *ctx);

    /**
     * set new CA bundle on TLS context
     * @param ctx TLS context
     * @param ca CA bundle (PEM or file)
     * @param ca_len length of CA bundle
     */
    int (*set_ca_bundle)(tls_context *ctx, const char *ca, size_t ca_len);

    /**
     * \brief set client certificate credentials.
     *
     * (Optional): if you bring your own engine this is probably not needed.
     * This method is provided to set client/server side cert on the default TLS context.
     *
     * @param ctx TLS context
     * @param key private key, use NULL to clear client auth
     * @param cert x509 certificate corresponding to the key,
     *        may be NULL if private key implementation provides certificate (pkcs11)
     *
     * @return 0 for success, -1 on error (mismatched key/cert, or cert is not provided)
     */
    int (*set_own_cert)(tls_context *ctx, tlsuv_private_key_t key, tlsuv_certificate_t cert);

    /**
     * Allows partial chain matching.
     *
     * Causes intermediate certificates in the trust store to be treated as trust-anchors,
     * in the same way as the self-signed root CA certificates.
     * @param ctx
     * @param allow
     * @return 0 for success, err code if not supported
     */
    int (*allow_partial_chain)(tls_context *ctx, int allow);

    /**
     * Sets custom peer cert validation function.
     *
     * certificate handle passed into verification callback can be used to verify signature by calling verify_signature()
     * callback function must return 0 for success, and any other value for failure
     *
     * The same callback validates server certificates on client engines and
     * *client* certificates on server engines; it cannot tell the two roles apart.
     * Note it is not invoked at all when a client presents no certificate, so it
     * cannot be used to reject an anonymous client -- use
     * tlsuv_engine_s::get_peer_cert() after the handshake for that.
     *
     * @param ctx TLS implementation
     * @param verify_f verification callback, receives opaque(implementation specific) certificate handle and custom data
     * @param v_ctx custom data passed into verification callback
     * \see tls_context_api::verify_signature()
     */
    void (*set_cert_verify)(tls_context *ctx,
            int (*verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx), void *v_ctx);

    /**
     * Parses certificate chain in base64 encoded PKCS#7 format
     * @param chain
     * @param pkcs7
     * @param pkcs7len
     * @returns 0 on success, or error code
     */
    int (*parse_pkcs7_certs)(tlsuv_certificate_t *chain, const char *pkcs7, size_t pkcs7len);

    /**
     * Load X509 certificate from a file or in-memory PEM
     * @param cert Certificate handle
     * @param buf certificate source string
     * @param buflen length of certificate string
     * @returns 0 on success or error code
     */
    int (*load_cert)(tlsuv_certificate_t *cert, const char *buf, size_t buflen);

    /**
     * generate private key.
     * caller should call tls_context_api::free_key() to clear memory associated with the key
     * @param pk (out) address where tls_private_key handle will be stored.
     * @returns 0 on success, or error code
     */
    int (*generate_key)(tlsuv_private_key_t *pk);

    /**
     * generate private key on a PKCS#11 token.
     * caller should call tls_context_api::free_key() to clear memory associated with the key
     * @param pk (out) address where tls_private_key handle will be stored.
     * @returns 0 on success, or error code
     */
    int (*generate_pkcs11_key)(tlsuv_private_key_t *pk, const char *pkcs11driver, const char *slot, const char *pin, const char *label);

    /**
     * loads private key from file, or PEM/DER buffer.
     * caller should call tls_context_api::free_key() to clear memory associated with the key
     * @param pk (out) address where tls_private_key handle will be stored.
     * @param keydata key source. it can be PEM/DER buffer or path to private key file
     * @param keydatalen length of keydata
     * @returns 0 on success, or error code
     */
    int (*load_key)(tlsuv_private_key_t *pk, const char* keydata, size_t keydatalen);

    int (*load_pkcs11_key)(tlsuv_private_key_t *pk, const char* pkcs11driver, const char *slot, const char *pin, const char *id, const char *label);

    int (*generate_keychain_key)(tlsuv_private_key_t *pk, const char *id);
    int (*load_keychain_key)(tlsuv_private_key_t *pk, const char *name);
    int (*remove_keychain_key)(const char *name);

    /**
     * Create x509 signing request in PEM format
     * @param pk private key used for request
     * @param pem (out) address where allocated buffer pointer will be get stored
     * @param pemlen size of produced PEM
     * @param ... NULL terminated subject name pairs
     * @returns 0 on success, or error code
     */
    int (*generate_csr_to_pem)(tlsuv_private_key_t pk, char **pem, size_t *pemlen, ...);

    /**
     * Get error message for given code
     * @param code error code
     */
    const char *(*strerror)(long code);

    /**
     * Get TLS implementation and version
     */
     const char *(*version)();

    /**
     * Creates a new server-side (accept) TLS engine.
     *
     * The application owns the accepted connection and drives the handshake with
     * handshake()/handshake_state() exactly as for a client engine; IO is attached
     * with set_io()/set_io_fd(). No hostname verification is performed, and the
     * client's SNI is ignored.
     *
     * Requires server credentials: set_own_cert() must have been called on this
     * context, otherwise NULL is returned.
     *
     *
     * The context must be fully configured before any server engine is created.
     *
     * Not implemented yet:
     * SNI based certificate selection, session ticket key
     * management, a client-certificate-*required* mode, and there is no
     * tlsuv_stream_t listen/accept path.
     *
     * mTLS is not implemented. Client certificates are not requested or validated.
     *
     * Optional: may be NULL when the TLS backend has no server support.
     *
     * @param ctx TLS context
     * @return new server engine, or NULL on error / when unsupported
     */
    tlsuv_engine_t (*new_server_engine)(tls_context *ctx);

    /**
     * Reports whether the TLS backend is operating in FIPS mode.
     *
     * this method must be implemented by every backend and is never NULL,
     * so a compliance check cannot be silently skipped.
     * Backends with no FIPS mode of their own report [TLS_FIPS_UNSUPPORTED].
     *
     * @param ctx TLS context
     * @param module (out, optional) buffer receiving the name and version of the
     *        FIPS module, e.g. "OpenSSL FIPS Provider 3.1.2". May be NULL, and
     *        modulelen may be 0. The result is NUL terminated and truncated to
     *        fit. It is only filled in when [TLS_FIPS_ENABLED] is returned and
     *        the backend can identify its module, and is set to "" otherwise.
     * @param modulelen size of the module buffer
     * @return one of [enum tls_fips_status]
     */
    enum tls_fips_status (*fips_status)(tls_context* ctx, char* module, size_t modulelen);
};

typedef tls_context *(*tls_context_factory)(const char* ca, size_t ca_len);

void set_default_tls_impl(tls_context_factory impl);

tls_context *default_tls_context(const char *ca, size_t ca_len);

#ifdef __cplusplus
}
#endif
#endif//TLSUV_ENGINE_H
