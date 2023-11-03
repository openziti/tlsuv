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

#if _WIN32
#include <uv/win.h>
#pragma comment (lib, "crypt32.lib")
#else
#include <uv/unix.h>
#endif

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

typedef struct tlsuv_engine_s *tlsuv_engine_t;

typedef void* io_ctx;
typedef ssize_t (*io_read)(io_ctx, char *buf, size_t len);
typedef ssize_t (*io_write)(io_ctx, const char *buf, size_t len);

struct tlsuv_engine_s {

    /**
     * set TLS engine abstract IO
     * @param self engine
     * @param io_ctx IO object passed into [io_read] and [io_write] callbacks
     * @param io_read read callback, called when TLS engine requires input SSL bytes
     * @param io_write write callback, called when TLS engine requires output SSL bytes
     */
    void (*set_io)(tlsuv_engine_t self, io_ctx, io_read, io_write);

    /**
     * sets TLS engine file descriptor IO (usually socket)
     * @param self engine
     * @param fd file descriptor
     */
    void (*set_io_fd)(tlsuv_engine_t self, uv_os_fd_t fd);

    /**
     * set requested ALPN protocols
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
      * @param engine
      * @param data
      * @param data_len
      * @return number of written bytes or error
      */
    int (*write)(tlsuv_engine_t self, const char *data, size_t data_len);

    /**
     * read application bytes from ssl stream.
     * @param engine
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
     * @param engine
     */
    int (*reset)(tlsuv_engine_t self);

    /**
     * frees the engine
     * @param self
     */
    void (*free)(tlsuv_engine_t self);
};

typedef struct tls_context_s tls_context;
typedef struct tlsuv_public_key_s *tlsuv_public_key_t;
typedef struct tlsuv_private_key_s *tlsuv_private_key_t;
typedef void *tls_cert;

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
    int (*get_certificate)(struct tlsuv_private_key_s * privkey, tls_cert * cert);   \
    int (*store_certificate)(struct tlsuv_private_key_s *privkey, tls_cert cert);

struct tlsuv_public_key_s {
    TLSUV_PUBKEY_API
};

struct tlsuv_private_key_s {
    TLSUV_PRIVKEY_API
};

struct tls_context_s {
    /* creates new TLS engine for a host */
    tlsuv_engine_t (*new_engine)(void *ctx, const char *host);

    void (*free_ctx)(tls_context *ctx);

    void (*free_cert)(tls_cert *cert);

    /**
     * \brief set client certfificate credentials.
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
    int (*set_own_cert)(tls_context *ctx, tlsuv_private_key_t key, tls_cert cert);

    /**
     * Sets custom server cert validation function.
     *
     * certificate handle passed into verification callback can be used to verify signature by calling verify_signature()
     * callback function must return 0 for success, and any other value for failure
     * @param ctx TLS implementation
     * @param verify_f verification callback, receives opaque(implementation specific) certificate handle and custom data
     * @param v_ctx custom data passed into verification callback
     * \see tls_context_api::verify_signature()
     */
    void (*set_cert_verify)(tls_context *ctx, int (*verify_f)(tls_cert cert, void *v_ctx), void *v_ctx);

    /**
     * verify signature using supplied TLS certificate handle
     * @param cert
     * @param algo
     * @param data
     * @param datalen
     * @param sig
     * @param siglen
     */
    int (*verify_signature)(tls_cert cert, enum hash_algo algo, const char *data, size_t datalen, const char *sig,
                            size_t siglen);

    /**
     * Parses certificate chain in base64 encoded PKCS#7 format
     * @param chain
     * @param pkcs7
     * @param pkcs7len
     * @returns 0 on success, or error code
     */
    int (*parse_pkcs7_certs)(tls_cert *chain, const char *pkcs7, size_t pkcs7len);

    /**
     * Generate PEM representation of the TLS certificate or chain.
     *
     * PEM buffer is allocated and returned. It is the caller responsibily to free memory associated with it.
     * @param cert TLS certificate handle
     * @param full_chain output whole chain
     * @param pem (out) address where allocated buffer pointer will be get stored
     * @param pemlen size of produced PEM
     * @returns 0 on success, or error code
     */
    int (*write_cert_to_pem)(tls_cert cert, int full_chain, char **pem, size_t *pemlen);

    /**
     * Load X509 certificate from a file or in-memory PEM
     * @param cert Certificate handle
     * @param buf certificate source string
     * @param buflen length of certificate string
     * @returns 0 on success or error code
     */
    int (*load_cert)(tls_cert *cert, const char *buf, size_t buflen);

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

};

typedef tls_context *(*tls_context_factory)(const char* ca, size_t ca_len);

void set_default_tls_impl(tls_context_factory impl);

tls_context *default_tls_context(const char *ca, size_t ca_len);

#ifdef __cplusplus
}
#endif
#endif//TLSUV_ENGINE_H
