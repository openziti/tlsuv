// Copyright (c) 2025. NetFoundry Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
//         https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//

#include <windows.h>
#include "engine.h"

#define SCHANNEL_USE_BLACKLISTS
#include <sspi.h>
#include <schannel.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>

#include "../alloc.h"
#include "../um_debug.h"

#include "cert.h"

static void engine_free(tlsuv_engine_t e) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)e;
    tlsuv__free(engine->hostname);
    tlsuv__free(engine->protocols);
    if (SecIsValidHandle(&engine->ctxt_handle))
        DeleteSecurityContext(&engine->ctxt_handle);
    if (SecIsValidHandle(&engine->cred_handle))
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

        LOG_ERROR(ERR, err, "socket read error");
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

static int verify_cert_ca(const struct tlsuv_certificate_s * c, void *v_ctx) {
    struct win32crypto_engine_s *engine = v_ctx;
    win32_cert_t *cert = (win32_cert_t*)c;

    PCCERT_CONTEXT peer_cert = CertDuplicateCertificateContext(cert->cert);
    do {
        DWORD check = CERT_STORE_SIGNATURE_FLAG;
        PCCERT_CONTEXT local_iss = CertGetIssuerCertificateFromStore(engine->ca, peer_cert, NULL, &check);
        if (local_iss) {
            CertFreeCertificateContext(peer_cert);
            CertFreeCertificateContext(local_iss);
            return 0;
        }

        check = 0;
        peer_cert = CertGetIssuerCertificateFromStore(peer_cert->hCertStore, peer_cert, peer_cert, &check);
    } while (peer_cert);

    return -1;
}

static SECURITY_STATUS verify_server_cert(struct win32crypto_engine_s *engine)
{
    PCCERT_CONTEXT server_cert = NULL;
    SECURITY_STATUS rc;

    rc = QueryContextAttributes(&engine->ctxt_handle, SECPKG_ATTR_REMOTE_CERT_CHAIN, &server_cert);
    if (rc != SEC_E_OK) {
        LOG_LAST_ERROR(ERR, "failed to get server cert");
        return rc;
    }

    tlsuv_certificate_t crt = (tlsuv_certificate_t)win32_new_cert(server_cert, server_cert->hCertStore);
    int verified = engine->cert_verify_f(crt, engine->verify_ctx);
    crt->free(crt);
    return  verified == 0 ? ERROR_SUCCESS : TRUST_E_FAIL;
}

static tls_handshake_state engine_handshake(tlsuv_engine_t self) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;

    if (engine->handshake_st == TLS_HS_COMPLETE ||
        engine->handshake_st == TLS_HS_ERROR)
        return engine->handshake_st;

    u_long req_flags =
            ISC_REQ_USE_SUPPLIED_CREDS |
            ISC_REQ_CONFIDENTIALITY |
            ISC_REQ_REPLAY_DETECT |
            ISC_REQ_SEQUENCE_DETECT |
            ISC_REQ_STREAM;
    u_long ret_flags = 0;
    SecBuffer outbuf[3] = {
        { .BufferType = SECBUFFER_TOKEN, .pvBuffer = engine->outbound, .cbBuffer = sizeof(engine->outbound) },
        { .BufferType = SECBUFFER_EMPTY },
        { .BufferType = SECBUFFER_EMPTY },
    };
    SecBufferDesc outbuf_desc = { SECBUFFER_VERSION, 2, outbuf };

    SecBuffer inbuf[2] = { };
    inbuf[0].cbBuffer = engine->inbound_len;
    inbuf[0].pvBuffer = engine->inbound;
    inbuf[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc inbuf_desc = { SECBUFFER_VERSION, 2, inbuf };

    if (engine->status == SEC_I_CONTINUE_NEEDED ||
        engine->status == SEC_E_INCOMPLETE_MESSAGE) {
        ssize_t read = engine->read_fn(engine->io,
                                      engine->inbound + engine->inbound_len,
                                      sizeof(engine->inbound) - engine->inbound_len);
        if (read > 0) {
            engine->inbound_len += read;
            UM_LOG(VERB, "read %zd bytes of handshake data", read);
            inbuf[0].cbBuffer = (unsigned long)engine->inbound_len;
            inbuf[0].pvBuffer = engine->inbound;
        } else {
            UM_LOG(ERR, "failed to read handshake data: %zd", read);
            engine->handshake_st = TLS_HS_ERROR;
            return engine->handshake_st;
        }
    }

    if (engine->handshake_st == TLS_HS_BEFORE && engine->protocols) {
        memcpy(inbuf[0].pvBuffer, engine->protocols, engine->protocols_len);
        inbuf[0].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
        inbuf[0].cbBuffer = engine->protocols_len;
    } else if (engine->inbound_len > 0) {
        inbuf[0].BufferType = SECBUFFER_TOKEN;
        inbuf[0].pvBuffer = engine->inbound;
        inbuf[0].cbBuffer = engine->inbound_len;
    }

    PCtxtHandle ctx = engine->handshake_st == TLS_HS_BEFORE ? NULL : &engine->ctxt_handle;

    UM_LOG(TRACE, "processing %d bytes", inbuf[0].cbBuffer);
    SECURITY_STATUS rc = InitializeSecurityContextA(
        &engine->cred_handle, ctx, ctx ? NULL : engine->hostname,
        req_flags, 0, 0,
        ctx || engine->protocols ? &inbuf_desc : NULL,
        0,
        ctx ? NULL : &engine->ctxt_handle,
        &outbuf_desc, &ret_flags, NULL);

    if (rc < 0) {
      LOG_ERROR(VERB, rc, "handshake result");
    }

    engine->status = rc;

    if (inbuf[1].BufferType == SECBUFFER_EXTRA) {
        UM_LOG(VERB, "extra data in handshake buffer: %lu bytes", inbuf[1].cbBuffer);
        size_t consumed = engine->inbound_len - inbuf[1].cbBuffer;
        memmove(engine->inbound, engine->inbound + consumed, engine->inbound_len - consumed);
        engine->inbound_len -= consumed;
    } else if (rc != SEC_E_INCOMPLETE_MESSAGE) {
        engine->inbound_len = 0;
    }

    switch (rc) {
        case SEC_E_OK:
            engine->handshake_st = TLS_HS_COMPLETE;
            if (engine->cert_verify_f) {
                rc = verify_server_cert(engine);
            }
            if (rc != SEC_E_OK) {
                LOG_ERROR(ERR, rc, "failed to verify server certificate");
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
            LOG_ERROR(ERR, rc, "handshake failed");
            engine->handshake_st = TLS_HS_ERROR;
            break;
    }

    if (outbuf[0].cbBuffer > 0) {
        assert (engine->write_fn);

        ssize_t written = engine->write_fn(engine->io, outbuf[0].pvBuffer, outbuf[0].cbBuffer);
        UM_LOG(VERB, "HS wrote %zd", written);
        if (written < outbuf[0].cbBuffer) {
            UM_LOG(ERR, "failed to write handshake data: %zd", written);
            engine->handshake_st = TLS_HS_ERROR;
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

    if (engine->protocols == NULL) {
        return "";
    }

    if (engine->alpn.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success) {
        return engine->alpn.ProtocolId;
    }

    if (QueryContextAttributesA(&engine->ctxt_handle, SECPKG_ATTR_APPLICATION_PROTOCOL, &engine->alpn) != SEC_E_OK) {
        LOG_LAST_ERROR(ERR, "failed to get ALPN");
        return NULL;
    }

    if (engine->alpn.ProtoNegoStatus != SecApplicationProtocolNegotiationStatus_None) {
        return engine->alpn.ProtocolId;
    }

    return "";
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
    if (rc != ERROR_SUCCESS) {
        LOG_ERROR(ERR, rc, "close result flags[0x%lX]", flags);
    }
    if (rc == SEC_E_OK || rc == SEC_I_CONTINUE_NEEDED) {
        if (outbuf.cbBuffer > 0 && engine->write_fn) {
            ssize_t written = engine->write_fn(engine->io, outbuf.pvBuffer, outbuf.cbBuffer);
            if (written < outbuf.cbBuffer) {
                UM_LOG(ERR, "failed to write close data: %zd", written);
                return -1;
            }
        }
    } else {
        LOG_LAST_ERROR(ERR, "failed to close TLS connection");
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
            UM_LOG(VERB, "wrote %zd bytes of outbound data", rc);
            continue;
        }

        err = WSAGetLastError();
        break;
    }

    if (written == engine->outbound_len) {
        engine->outbound_len = 0;
        UM_LOG(VERB, "flushed %zu bytes of outbound data", written);
        return 0;
    }

    if (written > 0) {
        LOG_ERROR(VERB, err, "partial write: %zu of %zu bytes", written, engine->outbound_len);
        memmove(engine->outbound, engine->outbound + written, engine->outbound_len - written);
        engine->outbound_len -= written;
        return 0;
    }

    if (err == WSAEWOULDBLOCK || err == WSAEINTR) {
        UM_LOG(VERB, "write would block or interrupted, retrying later");
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
        LOG_ERROR(ERR, rc, "failed to encrypt message");
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
                            sizeof(engine->inbound) - engine->inbound_len);
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
        LOG_ERROR(VERB, rc, "decrypt message");

        if (rc == SEC_E_OK) {
            assert(bufs[0].BufferType == SECBUFFER_STREAM_HEADER);
            assert(bufs[1].BufferType == SECBUFFER_DATA);
            assert(bufs[2].BufferType == SECBUFFER_STREAM_TRAILER);

            size_t len = bufs[1].cbBuffer > (max - (p - data)) ?
                max - (p - data) : bufs[1].cbBuffer;
            memcpy(p, bufs[1].pvBuffer, len);
            p += len;

            memcpy(engine->decoded, (char *) bufs[1].pvBuffer + len, bufs[1].cbBuffer - len);
            engine->decoded_len = bufs[1].cbBuffer - len;

            size_t consumed = engine->inbound_len -
                (bufs[3].BufferType == SECBUFFER_EXTRA ? bufs[3].cbBuffer : 0);
            assert(consumed <= engine->inbound_len);
            memmove(engine->inbound, engine->inbound + consumed, engine->inbound_len - consumed);
            engine->inbound_len -= consumed;
        } else if (rc == SEC_E_INCOMPLETE_MESSAGE) {
            break;
        } else if (rc == SEC_I_CONTEXT_EXPIRED) {
            size_t consumed = engine->inbound_len -
                (bufs[3].BufferType == SECBUFFER_EXTRA ? bufs[3].cbBuffer : 0);
            assert(consumed <= engine->inbound_len);
            memmove(engine->inbound, engine->inbound + consumed, engine->inbound_len - consumed);
            engine->inbound_len -= consumed;
            eof = true;
        } else {
            LOG_ERROR(ERR, rc, "failed to decrypt message");
            return TLS_ERR;
        }

    } while (!eof && p - data < max);
    *out = p - data;

    if (engine->decoded_len > 0) return TLS_MORE_AVAILABLE;
    if (engine->inbound_len > 0) return TLS_AGAIN;
    if (eof) return TLS_EOF;
    return TLS_OK;
}

static int engine_reset (tlsuv_engine_t self) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;

    memset(engine->inbound, 0, sizeof(engine->inbound));
    memset(engine->outbound, 0, sizeof(engine->outbound));
    memset(engine->decoded, 0, sizeof(engine->decoded));
    engine->inbound_len = 0;
    engine->outbound_len = 0;
    engine->decoded_len = 0;

    engine->status = 0;
    engine->handshake_st = TLS_HS_BEFORE;
    memset(&engine->sizes, 0, sizeof(engine->sizes));
    memset(&engine->alpn, 0, sizeof(engine->alpn));

    if (SecIsValidHandle(&engine->ctxt_handle))
        DeleteSecurityContext(&engine->ctxt_handle);

    SecInvalidateHandle(&engine->ctxt_handle);
    return 0;
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
    .reset = engine_reset,
    .free = engine_free,
};

struct win32crypto_engine_s *new_win32engine(
    const char *hostname, HCERTSTORE ca, PCCERT_CONTEXT own_cert,
    int (*cert_verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx),
    void *verify_ctx)
{
    struct win32crypto_engine_s *engine = tlsuv__calloc(1, sizeof(*engine));
    engine->api = api;
    engine->handshake_st = TLS_HS_BEFORE;
    engine->hostname = hostname ? tlsuv__strdup(hostname) : NULL;

    char subj[256] = {};
    if (own_cert) {
        CertNameToStrA(X509_ASN_ENCODING, &own_cert->pCertInfo->Subject, CERT_NAME_ATTR_TYPE, subj, sizeof(subj));
    }
    UM_LOG(INFO, "creating client engine host[%s] subject[%s]", engine->hostname, subj);

    engine->ca = ca;
    DWORD flags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MEMORY_STORE_CERT ;
    if ((ca == NULL || ca == INVALID_HANDLE_VALUE) && cert_verify_f == NULL) {
        flags |= SCH_CRED_AUTO_CRED_VALIDATION;
    } else if (cert_verify_f) {
        engine->cert_verify_f = cert_verify_f;
        engine->verify_ctx = verify_ctx;
        flags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    } else {
        engine->cert_verify_f = verify_cert_ca;
        engine->verify_ctx = engine;
        flags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    }

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
    if (rc != ERROR_SUCCESS) {
        LOG_ERROR(ERR, rc, "AcquireCredentialsHandleA result");
    }
    return engine;
}