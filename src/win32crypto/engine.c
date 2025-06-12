//
// Created by eugen on 6/11/2025.
//

#include "engine.h"

#include <sspi.h>
#include <schannel.h>
#include <stdint.h>

#include "../alloc.h"
#include "../um_debug.h"

extern const char* win32_error(DWORD code);

static void engine_free(tlsuv_engine_t e) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)e;
    tlsuv__free(engine->hostname);
    tlsuv__free(engine->protocols);
    tlsuv__free(engine->alpn);
    DeleteSecurityContext(&engine->ctxt_handle);
    FreeCredentialsHandle(&engine->cred_handle);
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
    u_long req_flags =
            ISC_REQ_USE_SUPPLIED_CREDS |
            ISC_REQ_ALLOCATE_MEMORY |
            ISC_REQ_CONFIDENTIALITY |
            ISC_REQ_REPLAY_DETECT |
            ISC_REQ_SEQUENCE_DETECT |
            ISC_REQ_STREAM;
    u_long ret_flags = 0;
    SecBuffer outbuf = {
            .pvBuffer = engine->outbound,
            .cbBuffer = sizeof(engine->outbound),
            .BufferType = SECBUFFER_TOKEN,
    };
    SecBufferDesc outbuf_desc = {
            .cBuffers = 1,
            .pBuffers = &outbuf,
            .ulVersion = SECBUFFER_VERSION,
    };

    SecBuffer inbuf = {
            .pvBuffer = engine->inbound + engine->inbound_len,
            .cbBuffer = sizeof(inbuf) - engine->inbound_len,
            .BufferType = SECBUFFER_TOKEN,
    };
    SecBufferDesc inbuf_desc = {
            .cBuffers = 1,
            .pBuffers = &inbuf,
            .ulVersion = SECBUFFER_VERSION,
    };

    if (engine->status == SEC_I_CONTINUE_NEEDED || engine->status == SEC_E_INCOMPLETE_MESSAGE) {
        size_t read = engine->read_fn(engine->io,
                                      engine->inbound + engine->inbound_len,
                                      sizeof(engine->inbound) - engine->inbound_len);
        if (read > 0) {
            engine->inbound_len += read;
            UM_LOG(ERR, "read %zd bytes of handshake data", read);
            inbuf.cbBuffer = (unsigned long)engine->inbound_len;
            inbuf.pvBuffer = engine->inbound;
        } else {
            UM_LOG(ERR, "failed to read handshake data: %zd", read);
            engine->handshake_st = TLS_HS_ERROR;
            return engine->handshake_st;
        }
    }

    if (engine->protocols) {
        memcpy(inbuf.pvBuffer, engine->protocols, engine->protocols_len);
        inbuf.BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
        inbuf.cbBuffer = engine->protocols_len;
    }

    PCtxtHandle ctx = engine->handshake_st == TLS_HS_BEFORE ? NULL : &engine->ctxt_handle;

    TimeStamp ts;
    SECURITY_STATUS rc = InitializeSecurityContextA(
        &engine->cred_handle, ctx, ctx ? NULL : engine->hostname,
        req_flags, 0, 0,
        ctx || engine->protocols ? &inbuf_desc : NULL,
        0, ctx ? NULL : &engine->ctxt_handle,
        &outbuf_desc, &ret_flags, &ts);

    UM_LOG(ERR, "handshake result: 0x%lX/%s", rc, win32_error(rc));

    engine->status = rc;
    tlsuv__free(engine->protocols);
    engine->protocols = NULL;

    if (inbuf.BufferType == SECBUFFER_EXTRA) {
        UM_LOG(ERR, "extra data in handshake buffer: %lu bytes", inbuf.cbBuffer);
    } else {
        engine->inbound_len = 0;
    }

    switch (rc) {
        case SEC_E_OK:
            engine->handshake_st = TLS_HS_COMPLETE;
            break;
        case SEC_I_CONTINUE_NEEDED:
            engine->handshake_st = TLS_HS_CONTINUE;
            break;
        case SEC_E_INCOMPLETE_MESSAGE:
            engine->handshake_st = TLS_HS_CONTINUE;
            break;
        default:
            UM_LOG(ERR, "handshake result: 0x%lX", rc);
            engine->handshake_st = TLS_HS_ERROR;
            break;
    }

    if (outbuf.pvBuffer && outbuf.cbBuffer > 0) {
        if (engine->write_fn) {
            ssize_t written = engine->write_fn(engine->io, outbuf.pvBuffer, outbuf.cbBuffer);
            if (written < outbuf.cbBuffer) {
                UM_LOG(ERR, "failed to write handshake data: %zd", written);
                engine->handshake_st = TLS_HS_ERROR;
            }
        }
    }
    return engine->handshake_st;
}

static void engine_set_protocols(tlsuv_engine_t self, const char **protocols, int len) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;
    tlsuv__free(engine->protocols);
    engine->protocols = NULL;
    engine->protocols_len = 0;

    if (len <= 0 || protocols == NULL) {
        return;
    }
    u_int ext = SecApplicationProtocolNegotiationExt_ALPN;
    u_short proto_sz = 0;
    for (int i = 0; i < len; ++i) {
        proto_sz += strlen(protocols[i]) + 1;
    }
    u_int sz = sizeof(sz) + sizeof(ext) + sizeof(u_short) + proto_sz; // ext_len + ext + proto_sz;

    char alpn[64];
    size_t offset = 0;

    *(u_int*)&(alpn[offset]) = (u_int)(sizeof(ext) + sizeof(proto_sz) + proto_sz);
    offset += sizeof(u_int);

    *(u_int*)&(alpn[offset]) = ext;
    offset += sizeof(ext);

    *(u_short*)&(alpn[offset]) = proto_sz;
    offset += sizeof(proto_sz);

    for (int i = 0; i < len; ++i) {
        size_t proto_len = strlen(protocols[i]);
        alpn[offset++] = (char)proto_len;
        memcpy(&alpn[offset], protocols[i], proto_len);
        offset += proto_len;
    }
    engine->protocols = tlsuv__malloc(sz);
    memcpy(engine->protocols, alpn, sz);
    engine->protocols_len = sz;
}

static const char* engine_get_protocol(tlsuv_engine_t self) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;

    if (engine->alpn) {
        return engine->alpn;
    }

    SecPkgContext_ApplicationProtocol alpn = {0};
    if (QueryContextAttributesA(&engine->ctxt_handle, SECPKG_ATTR_APPLICATION_PROTOCOL, &alpn) != SEC_E_OK) {
        UM_LOG(ERR, "failed to get ALPN: %s", win32_error(GetLastError()));
        return NULL;
    }

    if (alpn.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success) {
        engine->alpn = tlsuv__malloc(alpn.ProtocolIdSize + 1);
        memcpy(engine->alpn, alpn.ProtocolId, alpn.ProtocolIdSize);
        engine->alpn[alpn.ProtocolIdSize] = '\0';
    }

    return engine->alpn;
}

static int engine_close(tlsuv_engine_t self) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;
    DWORD shut = SCHANNEL_SHUTDOWN;
    SECURITY_STATUS rc;
    rc = ApplyControlToken(&engine->ctxt_handle, &(SecBufferDesc){
        .cBuffers = 1,
        .pBuffers = &(SecBuffer){
            .pvBuffer = &shut,
            .cbBuffer = sizeof(shut),
            .BufferType = SECBUFFER_TOKEN
        },
        .ulVersion = SECBUFFER_VERSION
    });

    char buf[256];
    SecBuffer outbuf = {
        .pvBuffer = buf,
        .cbBuffer = sizeof(buf),
        .BufferType = SECBUFFER_TOKEN,
    };
    SecBufferDesc outbuf_desc = {
        .cBuffers = 1,
        .pBuffers = &outbuf,
        .ulVersion = SECBUFFER_VERSION,
    };

    u_long flags;
    rc = InitializeSecurityContextA(
        &engine->cred_handle, &engine->ctxt_handle, engine->hostname,
        ISC_REQ_STREAM | ISC_REQ_CONFIDENTIALITY,
        0, 0, NULL, 0,
        &engine->ctxt_handle, &outbuf_desc, &flags, NULL);
    UM_LOG(ERR, "close result: 0x%lX flags: 0x%lX", rc, flags);
    if (rc == SEC_E_OK || rc == SEC_I_CONTINUE_NEEDED) {
        if (outbuf.cbBuffer > 0 && engine->write_fn) {
            ssize_t written = engine->write_fn(engine->io, outbuf.pvBuffer, outbuf.cbBuffer);
            if (written < outbuf.cbBuffer) {
                UM_LOG(ERR, "failed to write close data: %zd", written);
                return -1;
            }
        }
    } else {
        UM_LOG(ERR, "failed to close TLS connection: %s", win32_error(GetLastError()));
        return -1;
    }
    return 0;
}

static struct tlsuv_engine_s api = {
    .set_io = engine_set_io,
    .set_io_fd = engine_set_io_fd,
    .set_protocols = engine_set_protocols,
    .handshake_state = engine_handshake_state,
    .handshake = engine_handshake,
    .get_alpn = engine_get_protocol,
    .close = engine_close,
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