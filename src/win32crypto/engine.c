
#define SCHANNEL_USE_BLACKLISTS
#include <ntdef.h>

#include "engine.h"

#include <sspi.h>
#include <schannel.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>

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
        DWORD err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return TLS_AGAIN;

        UM_LOG(ERR, "socket read error: %s", win32_error(err));
        return TLS_ERR;
    }
    if (read == 0) {
        return TLS_EOF;
    }
    return read;
}

static ssize_t socket_write(io_ctx io, const char *buf, size_t len) {
    SOCKET sock = (SOCKET)io;
    int count = send(sock, buf, (int)len, 0);
    if (count == SOCKET_ERROR) {
        DWORD err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return TLS_AGAIN;
        }

        return TLS_ERR;
    }
    return count;
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
        UM_LOG(VERB, "starting TLS handshake");
    }
    return engine->handshake_st;
}

static SECURITY_STATUS verify_server_cert(struct win32crypto_engine_s *engine) {
    CERT_CONTEXT *server_cert = NULL;
    SECURITY_STATUS rc;
    HCERTCHAINENGINE verifier = NULL;
    const CERT_CHAIN_CONTEXT *server_chain = NULL;
    CERT_CHAIN_PARA params = {
            .cbSize = sizeof(CERT_CHAIN_PARA),
    };

    rc = QueryContextAttributes(&engine->ctxt_handle, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &server_cert);
    if (rc != SEC_E_OK) {
        UM_LOG(ERR, "failed to get server cert: 0x%lX/%s", rc, win32_error(GetLastError()));
        return rc;
    }

    CERT_CHAIN_ENGINE_CONFIG cfg = {
            .cbSize = sizeof(cfg),
            .hExclusiveRoot = engine->ca,
    };

    CertCreateCertificateChainEngine(&cfg, &verifier);

    if (!CertGetCertificateChain(
            verifier, server_cert,
            NULL, NULL,
            &params, 0, NULL,
            &server_chain)) {
        rc = (SECURITY_STATUS)GetLastError();
        UM_LOG(ERR, "failed to get certificate chain: 0x%lX/%s", rc, win32_error(rc));
    }

    return rc;
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
            UM_LOG(VERB, "read %zd bytes of handshake data", read);
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

    UM_LOG(VERB, "handshake result: 0x%lX/%s", rc, win32_error(rc));

    engine->status = rc;
    tlsuv__free(engine->protocols);
    engine->protocols = NULL;

    if (inbuf.BufferType == SECBUFFER_EXTRA) {
        UM_LOG(VERB, "extra data in handshake buffer: %lu bytes", inbuf.cbBuffer);
    } else {
        engine->inbound_len = 0;
    }

    switch (rc) {
        case SEC_E_OK:
            engine->handshake_st = TLS_HS_COMPLETE;
            if (engine->ca) {
                rc = verify_server_cert(engine);
            }
            if (rc != SEC_E_OK) {
                UM_LOG(ERR, "failed to verify server certificate: 0x%lX/%s", rc, win32_error(GetLastError()));
                engine->handshake_st = TLS_HS_ERROR;
                return engine->handshake_st;
            }
            QueryContextAttributesA(&engine->ctxt_handle, SECPKG_ATTR_STREAM_SIZES, &engine->sizes);
            break;
        case SEC_I_CONTINUE_NEEDED:
        case SEC_E_INCOMPLETE_MESSAGE:
            engine->handshake_st = TLS_HS_CONTINUE;
            break;
        default:
            UM_LOG(ERR, "handshake result: 0x%lX/%s", rc, win32_error(rc));
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
    ApplyControlToken(&engine->ctxt_handle, &(SecBufferDesc){
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

static int engine_flush(struct win32crypto_engine_s *engine) {
    if (engine->outbound_len == 0) return 0;

    DWORD err = 0;
    size_t written = 0;
    char *p = engine->outbound;
    while (written < engine->outbound_len) {
        ssize_t rc = engine->write_fn(engine->io, p, engine->outbound + engine->outbound_len - p);
        if (rc > 0) {
            p += rc;
            written += rc;
            UM_LOG(INFO, "wrote %zd bytes of outbound data", rc);
            continue;
        }

        err = WSAGetLastError();
        break;
    }

    if (written == engine->outbound_len) {
        engine->outbound_len = 0;
        UM_LOG(INFO, "flushed %zu bytes of outbound data", written);
        return 0;
    }

    if (written > 0) {
        UM_LOG(ERR, "partial write: %zu of %zu bytes, error: %s", written, engine->outbound_len, win32_error(err));
        memmove(engine->outbound, engine->outbound + written, engine->outbound_len - written);
        engine->outbound_len -= written;
        return 0;
    }

    if (err == WSAEWOULDBLOCK || err == WSAEINTR) {
        UM_LOG(INFO, "write would block or interrupted, retrying later");
        return TLS_AGAIN;
    }
    return TLS_ERR;
}

static int engine_write(tlsuv_engine_t self, const char *data, size_t data_len) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;
    int flush = engine_flush(engine);
    if (flush != 0) {
        return flush;
    }

    if (engine->outbound_len > 0) {
        return TLS_AGAIN;
    }

    size_t sent = 0;
    const char *p = data;
    size_t p_len = data_len > engine->sizes.cbMaximumMessage ? engine->sizes.cbMaximumMessage : data_len;

    // setup buffers for encryption
    SecBuffer bufs[4] = {
        { .BufferType = SECBUFFER_STREAM_HEADER },
        { .BufferType = SECBUFFER_DATA },
        { .BufferType = SECBUFFER_STREAM_TRAILER },
        { .BufferType = SECBUFFER_EMPTY }
    };
    bufs[0].pvBuffer = engine->outbound;
    bufs[0].cbBuffer = engine->sizes.cbHeader;
    bufs[1].pvBuffer = (char*)bufs[0].pvBuffer + bufs[0].cbBuffer;
    bufs[1].cbBuffer = p_len;
    memcpy(bufs[1].pvBuffer, p, p_len);
    bufs[2].pvBuffer = (char*)bufs[1].pvBuffer + bufs[1].cbBuffer;
    bufs[2].cbBuffer = engine->sizes.cbTrailer;

    SecBufferDesc bufferDesc = {
        .cBuffers = 4,
        .pBuffers = bufs,
        .ulVersion = SECBUFFER_VERSION,
    };

    SECURITY_STATUS rc = EncryptMessage(&engine->ctxt_handle, 0, &bufferDesc, 0);
    if (rc != SEC_E_OK) {
        UM_LOG(ERR, "failed to encrypt message: 0x%lX/%s", rc, win32_error(rc));
        return -1;
    }
    sent += p_len;
    engine->outbound_len += bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
    engine_flush(engine);
    return (int)sent;
}

static int engine_read(tlsuv_engine_t self, char *data, size_t *out, size_t max) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;
    char *p = data;

    // copy any leftover data from previous read
    if (engine->decoded_len > 0) {
        size_t len = engine->decoded_len > max ? max : engine->decoded_len;
        memcpy(p, engine->decoded, len);
        p += len;
        engine->decoded_len -= len;
        if (engine->decoded_len > 0) {
            memmove(engine->decoded, engine->decoded + len, engine->decoded_len);
        }
    }
    if (p - data == max) {
        *out = max;
        return engine->decoded_len > 0 ? TLS_MORE_AVAILABLE : 0;
    }
    
    assert(engine->decoded_len == 0);

    bool eof = false;
    do {
        ssize_t read = engine->read_fn(engine->io, engine->inbound + engine->inbound_len,
                                       sizeof(engine->inbound) - engine->outbound_len);
        if (read > 0) {
            engine->inbound_len += read;
            UM_LOG(VERB, "read %zd bytes of TLS data", read);
        }

        if (engine->inbound_len == 0) {
            *out = p - data;
            return read > 0 ? TLS_OK : (int)read;
        }

        SecBuffer bufs[4] = {
                {.BufferType = SECBUFFER_DATA},
                {.BufferType = SECBUFFER_EMPTY},
                {.BufferType = SECBUFFER_EMPTY},
                {.BufferType = SECBUFFER_EMPTY}
        };
        bufs[0].pvBuffer = engine->inbound;
        bufs[0].cbBuffer = engine->inbound_len;

        SecBufferDesc desc = {SECBUFFER_VERSION, 4, bufs};
        SECURITY_STATUS rc = DecryptMessage(&engine->ctxt_handle, &desc, 0, NULL);
        UM_LOG(VERB, "decrypt message: 0x%lX/%s", rc, win32_error(rc));

        if (rc == SEC_E_OK) {
            assert(bufs[0].BufferType == SECBUFFER_STREAM_HEADER);
            assert(bufs[1].BufferType == SECBUFFER_DATA);
            assert(bufs[2].BufferType == SECBUFFER_STREAM_TRAILER);

            size_t len = bufs[1].cbBuffer > (max - (p - data)) ? max - (p - data) : bufs[1].cbBuffer;
            memcpy(p, bufs[1].pvBuffer, len);
            p += len;

            memcpy(engine->decoded, (char *) bufs[1].pvBuffer + len, bufs[1].cbBuffer - len);
            engine->decoded_len = bufs[1].cbBuffer - len;

            size_t consumed = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
            assert(consumed <= engine->inbound_len);
            memmove(engine->inbound, engine->inbound + consumed, engine->inbound_len - consumed);
            engine->inbound_len -= consumed;
        } else if (rc == SEC_E_INCOMPLETE_MESSAGE) {
            break;
        } else if (rc == SEC_I_CONTEXT_EXPIRED) {
            size_t consumed = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
            assert(consumed <= engine->inbound_len);
            memmove(engine->inbound, engine->inbound + consumed, engine->inbound_len - consumed);
            engine->inbound_len -= consumed;
            eof = true;
        } else {
            UM_LOG(ERR, "failed to decrypt message: 0x%lX/%s", rc, win32_error(rc));
            return TLS_ERR;
        }

    } while (!eof && p - data < max);
    *out = p - data;

    if (engine->decoded_len > 0) return TLS_MORE_AVAILABLE;
    if (engine->inbound_len > 0) return TLS_AGAIN;
    if (eof) return TLS_EOF;
    return TLS_OK;
}

static const char* engine_strerror(tlsuv_engine_t self) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;
    return win32_error(engine->status);
}
static struct tlsuv_engine_s api = {
    .set_io = engine_set_io,
    .set_io_fd = engine_set_io_fd,
    .set_protocols = engine_set_protocols,
    .handshake_state = engine_handshake_state,
    .handshake = engine_handshake,
    .get_alpn = engine_get_protocol,
    .close = engine_close,
    .write = engine_write,
    .read = engine_read,
    .strerror = engine_strerror,
    .reset = NULL,
    .free = engine_free,
};

struct win32crypto_engine_s *new_win32engine(const char *hostname, HCERTSTORE ca, PCCERT_CONTEXT own_cert)
{
    struct win32crypto_engine_s *engine = tlsuv__calloc(1, sizeof(*engine));
    engine->api = api;
    engine->handshake_st = TLS_HS_BEFORE;
    engine->hostname = hostname ? tlsuv__strdup(hostname) : NULL;

    DWORD flags = SCH_CRED_NO_DEFAULT_CREDS;
    if (ca == NULL || ca == INVALID_HANDLE_VALUE) {
        flags |= SCH_CRED_AUTO_CRED_VALIDATION;
    } else {
        engine->ca = ca;
        flags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    }

    NCRYPT_KEY_HANDLE kh = 0;
    DWORD ks = sizeof(kh);
    if (own_cert)
        CertGetCertificateContextProperty(own_cert, CERT_NCRYPT_KEY_HANDLE_PROP_ID, &kh, &ks);

    PCCERT_CONTEXT certs[1] = { own_cert, };
    SCHANNEL_CRED credentials = {
        .dwVersion = SCHANNEL_CRED_VERSION,
        .dwFlags = flags,
        .grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT,
        .cCreds = own_cert ? 1 : 0,
        .paCred = certs,
    };

    SECURITY_STATUS rc = AcquireCredentialsHandleA(NULL,
                              (TCHAR *)(UNISP_NAME),
                              SECPKG_CRED_OUTBOUND, NULL,
                              &credentials, NULL, NULL,
                              &engine->cred_handle,
                              NULL);
    UM_LOG(INFO, "rc = 0x%lX/%s", rc, win32_error(rc));
    return engine;
}