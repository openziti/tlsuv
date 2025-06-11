//
// Created by eugen on 6/11/2025.
//

#include "engine.h"

#include <sspi.h>
#include <schannel.h>
#include <stdint.h>

#include "../alloc.h"
#include "../um_debug.h"

static void init_sec_buffer(SecBuffer *buffer, unsigned long BufType,
                          void *BufDataPtr, unsigned long BufByteSize);

static void init_sec_buffer_desc(SecBufferDesc *desc, SecBuffer *BufArr,
                              unsigned long NumArrElem);
static void engine_free(tlsuv_engine_t e) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)e;
    tlsuv__free(engine);
}

static void engine_set_io(tlsuv_engine_t self, io_ctx ctx, io_read read_fn, io_write write_fn) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;
    engine->io = ctx;
    engine->read_fn = read_fn;
    engine->write_fn = write_fn;
}

static ssize_t socket_read(io_ctx io, char *buf, size_t len) {
    SOCKET sock = (SOCKET)io;
    int read = recv(sock, buf, (int)len, 0);
    if (read == SOCKET_ERROR) {
        read = WSAGetLastError();
    }
    return read;
}

static ssize_t socket_write(io_ctx io, const char *buf, size_t len) {
    SOCKET sock = (SOCKET)io;
    int read = send(sock, buf, (int)len, 0);
    if (read == SOCKET_ERROR) {
        read = WSAGetLastError();
    }
    return read;
}

static void engine_set_io_fd(tlsuv_engine_t self, tlsuv_sock_t fd) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;
    engine->io = (io_ctx)fd;
    engine->read_fn = socket_read;
    engine->write_fn = socket_write;
}

static tls_handshake_state engine_handshake_state(tlsuv_engine_t self) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;
    if (engine->handshake_st == TLS_HS_BEFORE) {
        UM_LOG(INFO, "starting TLS handshake");
    }
    return engine->handshake_st;
}

static tls_handshake_state engine_handshake(tlsuv_engine_t self) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;
    u_long req_flags = SCH_USE_STRONG_CRYPTO;
    u_long ret_flags = 0;
    SecBuffer outbuf;
    SecBufferDesc outbuf_desc = {};
    init_sec_buffer(&outbuf, SECBUFFER_EMPTY, NULL, 0);
    init_sec_buffer_desc(&outbuf_desc, &outbuf, 1);
    SECURITY_STATUS rc = InitializeSecurityContextA(
        &engine->cred_handle, NULL, engine->hostname,
        req_flags, 0, 0,
        NULL, // TODO(backend->use_alpn ? &inbuf_desc : NULL),
        0, &engine->ctxt_handle,
        &outbuf_desc, &ret_flags, NULL);
    switch (rc) {
    case SEC_I_CONTINUE_NEEDED:
        engine->handshake_st = TLS_HS_CONTINUE;
        break;
    case SEC_E_OK:
        engine->handshake_st = TLS_HS_COMPLETE;
        break;
    default:
        UM_LOG(ERR, "handshake result: 0x%lX", rc);
        engine->handshake_st = TLS_HS_ERROR;
    }
    return engine->handshake_st;
}

static void engine_set_protocols(tlsuv_engine_t self, const char **protocols, int len) {

}

static const char* engine_get_protocol(tlsuv_engine_t self) {
    return NULL;
}

static struct tlsuv_engine_s api = {
    .set_io = engine_set_io,
    .set_io_fd = engine_set_io_fd,
    .set_protocols = engine_set_protocols,
    .handshake_state = engine_handshake_state,
    .handshake = engine_handshake,
    .get_alpn = engine_get_protocol,
    .close = NULL,
    .write = NULL,
    .read = NULL,
    .strerror = NULL,
    .reset = NULL,
    .free = engine_free,
};

struct win32crypto_engine_s* new_win32engine(const char* hostname) {
    struct win32crypto_engine_s *engine = tlsuv__calloc(1, sizeof(*engine));
    engine->api = api;
    engine->handshake_st = TLS_HS_BEFORE;
    engine->hostname = tlsuv__strdup(hostname);

    SCHANNEL_CRED credentials = {
        .dwVersion = SCHANNEL_CRED_VERSION,
        .dwFlags = SCH_USE_STRONG_CRYPTO
        | SCH_CRED_AUTO_CRED_VALIDATION  // automatically validate server certificate
        | SCH_CRED_NO_DEFAULT_CREDS,     // no client certificate authentication
        .grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT,
    };

    SECURITY_STATUS rc = AcquireCredentialsHandleA(NULL,
                              (TCHAR *)(UNISP_NAME),
                              SECPKG_CRED_OUTBOUND, NULL,
                              &credentials, NULL, NULL,
                              &engine->cred_handle,
                              NULL);
    return engine;
}


static void init_sec_buffer(SecBuffer *buffer, unsigned long BufType,
                          void *BufDataPtr, unsigned long BufByteSize)
{
    buffer->cbBuffer = BufByteSize;
    buffer->BufferType = BufType;
    buffer->pvBuffer = BufDataPtr;
}

static void init_sec_buffer_desc(SecBufferDesc *desc, SecBuffer *BufArr,
                              unsigned long NumArrElem)
{
    desc->ulVersion = SECBUFFER_VERSION;
    desc->pBuffers = BufArr;
    desc->cBuffers = NumArrElem;
}