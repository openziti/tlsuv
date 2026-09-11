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

static const char* hs_name(int c) {
    switch (c) {
        case 0: return "HelloRequest";
        case 1: return "ClientHello";
        case 2: return "ServerHello";
        case 4: return "NEWSESSION_TICKET";
        case 11: return "CERTIFICATE";
        case 12: return "SERVER_KEY_EXCHANGE";
        case 13: return "CERTIFICATE_REQUEST";
        case 14: return "SERVER_DONE";
        case 15: return "CERTIFICATE_VERIFY";
        case 16: return "CLIENT_KEY_EXCHANGE";
        case 20: return "FINISHED";
        default:
            return "UNKNOWN";
    }
}

static inline void log_tls_message(struct win32crypto_engine_s *e, const char *marker, const char *msg, size_t msg_len) {
    const u_char *m = (u_char*)msg;
    while(m - (u_char*)msg < msg_len) {
        u_char mt = *m++;
        m += 2;
        size_t rec_len = (*m++) << 8;
        rec_len += *m++;
        const char *t = "unknown";
        switch (mt) {
            case 20: t = "change_cipher"; break;
            case 21: t = "alert"; break;
            case 22: t = "handshake"; break;
            case 23: t = "data"; break;
            default:
                UM_LOG(TRACE, "%s tls[%p] skipping record[%d] len[%zd]", marker, e, mt, rec_len);
                m += rec_len;
                continue;
        }
        const char *complete="";
        if (m + rec_len > (u_char *)msg + msg_len) complete = " incomplete";
        if (mt == 22) {
            u_char hs = *m;
            UM_LOG(TRACE, "%s tls[%p] %s[%d] len[%zd]%s %s", marker, e, t, mt, rec_len, complete, hs_name(hs));
        } else {
            UM_LOG(TRACE, "%s tls[%p] %s[%d] len[%zd]%s", marker, e, t, mt, rec_len, complete);
        }
        m += rec_len;
    }
}

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

// Retrieves the peer certificate chain. On a server the peer is the client, and
// SEC_E_NO_CREDENTIALS means it presented no certificate.
static SECURITY_STATUS get_peer_chain(struct win32crypto_engine_s* engine, PCCERT_CONTEXT* chain) {
    *chain = NULL;
    if (engine->handshake_st != TLS_HS_COMPLETE) {
        return SEC_E_INVALID_HANDLE;
    }
    return QueryContextAttributes(&engine->ctxt_handle, SECPKG_ATTR_REMOTE_CERT_CHAIN, chain);
}

static SECURITY_STATUS verify_peer_cert(struct win32crypto_engine_s* engine) {
    PCCERT_CONTEXT peer_cert = NULL;
    SECURITY_STATUS rc = get_peer_chain(engine, &peer_cert);
    if (rc != SEC_E_OK) {
        // client certificates are optional: a client that sent none still
        // completes the handshake, and there is nothing to run the callback on
        if (engine->is_server && rc == SEC_E_NO_CREDENTIALS) {
            UM_LOG(VERB, "client did not present a certificate");
            return SEC_E_OK;
        }
        LOG_ERROR(ERR, rc, "failed to get peer cert");
        return rc;
    }

    tlsuv_certificate_t crt = (tlsuv_certificate_t)win32_new_cert(peer_cert, peer_cert->hCertStore);
    int verified = engine->cert_verify_f(crt, engine->verify_ctx);
    crt->free(crt);
    return  verified == 0 ? ERROR_SUCCESS : TRUST_E_FAIL;
}

static int engine_get_peer_cert(tlsuv_engine_t self, tlsuv_certificate_t* cert) {
    struct win32crypto_engine_s* engine = (struct win32crypto_engine_s*)self;
    *cert = NULL;

    PCCERT_CONTEXT peer_cert = NULL;
    SECURITY_STATUS rc = get_peer_chain(engine, &peer_cert);
    if (rc != SEC_E_OK || peer_cert == NULL) {
        LOG_ERROR(VERB, rc, "no peer certificate");
        return TLS_ERR;
    }

    *cert = (tlsuv_certificate_t)win32_new_cert(peer_cert, peer_cert->hCertStore);
    return 0;
}

static tls_handshake_state handshake_1(struct win32crypto_engine_s *engine) {
    assert(engine);
    assert(engine->write_fn);
    assert(engine->handshake_st == TLS_HS_BEFORE);

    u_long ret_flags = 0;
    u_long req_flags =
            ISC_REQ_USE_SUPPLIED_CREDS |
            ISC_REQ_CONFIDENTIALITY |
            ISC_REQ_REPLAY_DETECT |
            ISC_REQ_SEQUENCE_DETECT |
            ISC_REQ_STREAM;

    SecBuffer in_buf;
    SecBufferDesc in_buf_desc = { .ulVersion = SECBUFFER_VERSION };
    SecBufferDesc *in_buf_desc_p = NULL;

    char out[16 * 1024];
    SecBuffer out_buf = {
            .BufferType = SECBUFFER_TOKEN,
            .pvBuffer = out,
            .cbBuffer = sizeof(out),
    };
    SecBufferDesc out_buf_desc = {
            .ulVersion = SECBUFFER_VERSION,
            .pBuffers = &out_buf,
            .cBuffers = 1,
    };

    if (engine->protocols) {
        in_buf.BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
        in_buf.pvBuffer = engine->protocols;
        in_buf.cbBuffer = engine->protocols_len;

        in_buf_desc.cBuffers = 1;
        in_buf_desc.pBuffers = &in_buf;
        in_buf_desc_p = &in_buf_desc;
    }

    engine->status = InitializeSecurityContextA(
            &engine->cred_handle, NULL, engine->hostname,
            req_flags, 0, 0,
            in_buf_desc_p,
            0,
            &engine->ctxt_handle,
            &out_buf_desc, &ret_flags, NULL);

    // the only expected status
    if (engine->status == SEC_I_CONTINUE_NEEDED) {
        log_tls_message(engine, ">>>", out_buf.pvBuffer, out_buf.cbBuffer);
        ssize_t wr = engine->write_fn(engine->io, out_buf.pvBuffer, out_buf.cbBuffer);
        if (wr != out_buf.cbBuffer) {
            UM_LOG(ERR, "failed to write client hello[%zd]: %zd", out_buf.cbBuffer, wr);
            engine->handshake_st = TLS_HS_ERROR;
        } else {
            engine->handshake_st = TLS_HS_CONTINUE;
        }
        return engine->handshake_st;
    }

    engine->handshake_st = TLS_HS_ERROR;
    return TLS_HS_ERROR;
}

static tls_handshake_state engine_handshake(tlsuv_engine_t self) {
    struct win32crypto_engine_s *engine = (struct win32crypto_engine_s *)self;
    assert(engine);
    assert(engine->read_fn);
    assert(engine->write_fn);

    if (engine->handshake_st == TLS_HS_COMPLETE ||
        engine->handshake_st == TLS_HS_ERROR)
        return engine->handshake_st;

    // a client speaks first; a server has nothing to say until it hears a
    // ClientHello, so it falls through to the read below
    if (!engine->is_server && engine->handshake_st == TLS_HS_BEFORE) {
        return handshake_1(engine);
    }

    // the security context is created by the first call that processes input,
    // which for a server engine is the ClientHello
    bool first = !SecIsValidHandle(&engine->ctxt_handle);

    u_long req_flags;
    if (engine->is_server) {
        req_flags =
            ASC_REQ_CONFIDENTIALITY |
            ASC_REQ_REPLAY_DETECT |
            ASC_REQ_SEQUENCE_DETECT |
            ASC_REQ_EXTENDED_ERROR |
            ASC_REQ_STREAM;
        if (engine->request_client_cert) {
            // requests, but does not require: a client that sends no certificate
            // still completes the handshake
            req_flags |= ASC_REQ_MUTUAL_AUTH;
        }
    } else {
        req_flags =
            ISC_REQ_USE_SUPPLIED_CREDS |
            ISC_REQ_CONFIDENTIALITY |
            ISC_REQ_REPLAY_DETECT |
            ISC_REQ_SEQUENCE_DETECT |
            ISC_REQ_STREAM;
    }
    u_long ret_flags = 0;

    // read only when there is nothing buffered to work with, or when the last
    // call reported the buffered record is still short
    if (engine->inbound_len == 0 || engine->status == SEC_E_INCOMPLETE_MESSAGE) {
        size_t space = sizeof(engine->inbound) - engine->inbound_len;
        if (space == 0) {
            UM_LOG(ERR, "handshake message larger than %zu bytes", sizeof(engine->inbound));
            engine->handshake_st = TLS_HS_ERROR;
            return engine->handshake_st;
        }

        UM_LOG(VERB, "trying to read");
        ssize_t read = engine->read_fn(engine->io,
                                       engine->inbound + engine->inbound_len,
                                       space);
        if (read > 0) {
            engine->inbound_len += read;
            UM_LOG(TRACE, "read %zd bytes of handshake data", read);
        } else if (read == TLS_AGAIN) {
            // the peer has not sent its next flight yet, try again later
            engine->handshake_st = TLS_HS_CONTINUE;
            return engine->handshake_st;
        } else {
            UM_LOG(ERR, "failed to read handshake data: %zd", read);
            engine->handshake_st = TLS_HS_ERROR;
            return engine->handshake_st;
        }
    }

    SecBuffer inbuf[3] = { {
                                   .BufferType = SECBUFFER_TOKEN,
                                   .pvBuffer = engine->inbound,
                                   .cbBuffer = (unsigned long)engine->inbound_len,
        },
        {
            .BufferType = SECBUFFER_EMPTY,
            .pvBuffer = NULL,
            .cbBuffer = 0,
        },
        {
            .BufferType = SECBUFFER_EMPTY,
                                   .pvBuffer = NULL,
                                   .cbBuffer = 0,
                           }};

    SecBufferDesc inbuf_desc = { SECBUFFER_VERSION, 2, inbuf };

    // a server advertises its supported protocols with the call that processes
    // the ClientHello; Schannel picks the one to answer with
    if (engine->is_server && first && engine->protocols) {
        inbuf[2].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
        inbuf[2].pvBuffer = engine->protocols;
        inbuf[2].cbBuffer = (unsigned long)engine->protocols_len;
        inbuf_desc.cBuffers = 3;
    }

    char alert_buf[1024];
    SecBuffer outbuf[3] = {
        {.BufferType = SECBUFFER_TOKEN, .pvBuffer = engine->outbound, .cbBuffer = sizeof(engine->outbound)},
        {.BufferType = SECBUFFER_ALERT, .pvBuffer = alert_buf, .cbBuffer = sizeof(alert_buf) },
            { .BufferType = SECBUFFER_EMPTY },
    };
    SecBufferDesc outbuf_desc = { SECBUFFER_VERSION, 2, outbuf };

    UM_LOG(TRACE, "processing %d bytes", inbuf[0].cbBuffer);
    log_tls_message(engine, "<<<", inbuf[0].pvBuffer, inbuf[0].cbBuffer);
    if (engine->is_server) {
        engine->status = AcceptSecurityContext(
            &engine->cred_handle,
            first ? NULL : &engine->ctxt_handle,
            &inbuf_desc,
            req_flags, 0,
            first ? &engine->ctxt_handle : NULL,
            &outbuf_desc, &ret_flags, NULL);
    } else {
        engine->status = InitializeSecurityContextA(
            &engine->cred_handle, &engine->ctxt_handle, NULL,
            req_flags, 0, 0,
            &inbuf_desc,
            0,
            NULL,
            &outbuf_desc, &ret_flags, NULL);
    }

    if (engine->status == SEC_E_INCOMPLETE_MESSAGE) {
        UM_LOG(VERB, "TLS message incomplete");
        engine->handshake_st = TLS_HS_CONTINUE;
        return TLS_HS_CONTINUE;
    }

    if (inbuf[1].BufferType == SECBUFFER_EXTRA) {
        UM_LOG(VERB, "leftover data in handshake buffer: %lu bytes", inbuf[1].cbBuffer);
        size_t consumed = engine->inbound_len - inbuf[1].cbBuffer;
        memmove(engine->inbound, engine->inbound + consumed, engine->inbound_len - consumed);
        engine->inbound_len -= consumed;
    } else {
        engine->inbound_len = 0;
    }

    switch (engine->status) {
        case SEC_E_OK:
            engine->handshake_st = TLS_HS_COMPLETE;
            break;
        case SEC_I_CONTINUE_NEEDED:
            engine->handshake_st = TLS_HS_CONTINUE;
            break;
        default:
            LOG_ERROR(ERR, engine->status, "handshake failed");
            engine->handshake_st = TLS_HS_ERROR;
            break;
    }

    // flush before verifying: the peer needs this flight to finish its own
    // handshake, and an alert produced above has to reach it too
    for (int i = 0; i < 3; i++) {
        if (outbuf[i].BufferType == SECBUFFER_TOKEN && outbuf[i].cbBuffer > 0) {
            log_tls_message(engine, ">>>", outbuf[i].pvBuffer, outbuf[i].cbBuffer);
            ssize_t written = engine->write_fn(engine->io, outbuf[i].pvBuffer, outbuf[i].cbBuffer);
            UM_LOG(VERB, "HS wrote %zd", written);
            if (written < outbuf[i].cbBuffer) {
                UM_LOG(ERR, "failed to write handshake data: %zd", written);
                engine->handshake_st = TLS_HS_ERROR;
            }
        }
    }

    if (engine->handshake_st == TLS_HS_COMPLETE) {
        if (engine->cert_verify_f &&
            (engine->status = verify_peer_cert(engine)) != SEC_E_OK) {
            LOG_ERROR(ERR, engine->status, "failed to verify peer certificate");
            engine->handshake_st = TLS_HS_ERROR;
            return engine->handshake_st;
        }
        QueryContextAttributesA(&engine->ctxt_handle, SECPKG_ATTR_STREAM_SIZES, &engine->sizes);
    }
    return engine->handshake_st;
}

static void engine_set_protocols(tlsuv_engine_t self, const char** protocols, int len) {
    struct win32crypto_engine_s* engine = (struct win32crypto_engine_s*)self;
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
        return (const char*)engine->alpn.ProtocolId;
    }

    SECURITY_STATUS rc = QueryContextAttributesA(&engine->ctxt_handle,
                                                 SECPKG_ATTR_APPLICATION_PROTOCOL, &engine->alpn);
    if (rc != SEC_E_OK) {
        LOG_ERROR(ERR, rc, "failed to get ALPN");
        return "";
    }

    // anything short of Success (None, or SelectedClientOnly on a client whose
    // offer the server did not acknowledge) means no protocol was negotiated
    if (engine->alpn.ProtoNegoStatus != SecApplicationProtocolNegotiationStatus_Success) {
        return "";
    }

    // ProtocolId is a fixed size array and is not NUL terminated
    if (engine->alpn.ProtocolIdSize >= sizeof(engine->alpn.ProtocolId)) {
        UM_LOG(ERR, "invalid ALPN protocol length: %d", engine->alpn.ProtocolIdSize);
        return "";
    }
    engine->alpn.ProtocolId[engine->alpn.ProtocolIdSize] = 0;
    return (const char*)engine->alpn.ProtocolId;
}

static int engine_close(tlsuv_engine_t self) {
    struct win32crypto_engine_s* engine = (struct win32crypto_engine_s*)self;
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
    if (engine->is_server) {
        rc = AcceptSecurityContext(
            &engine->cred_handle, &engine->ctxt_handle, NULL,
            ASC_REQ_STREAM | ASC_REQ_CONFIDENTIALITY,
            0,
            &engine->ctxt_handle, &outbuf_desc, &flags, NULL);
    } else {
        rc = InitializeSecurityContextA(
            &engine->cred_handle, &engine->ctxt_handle, engine->hostname,
            ISC_REQ_STREAM | ISC_REQ_CONFIDENTIALITY,
            0, 0, NULL, 0,
            &engine->ctxt_handle, &outbuf_desc, &flags, NULL);
    }
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
    .get_peer_cert = engine_get_peer_cert,
};

// common part of both engine flavours: allocation, and picking how the peer
// certificate gets verified (explicit callback, else the CA bundle when one is
// set, else nothing)
static struct win32crypto_engine_s* engine_alloc(
    bool is_server, HCERTSTORE ca,
    int (*cert_verify_f)(const struct tlsuv_certificate_s* cert, void* v_ctx),
    void* verify_ctx) {
    struct win32crypto_engine_s* engine = tlsuv__calloc(1, sizeof(*engine));
    engine->api = api;
    engine->is_server = is_server;
    engine->handshake_st = TLS_HS_BEFORE;

    // a zeroed handle passes SecIsValidHandle(), so mark both explicitly unset
    SecInvalidateHandle(&engine->cred_handle);
    SecInvalidateHandle(&engine->ctxt_handle);

    engine->ca = ca;
    if (cert_verify_f) {
        engine->cert_verify_f = cert_verify_f;
        engine->verify_ctx = verify_ctx;
    } else if (ca != NULL && ca != INVALID_HANDLE_VALUE) {
        engine->cert_verify_f = verify_cert_ca;
        engine->verify_ctx = engine;
    }
    return engine;
}

static void cert_subject(PCCERT_CONTEXT cert, char* subj, size_t len) {
    *subj = 0;
    if (cert) {
        CertNameToStrA(X509_ASN_ENCODING, &cert->pCertInfo->Subject, CERT_NAME_ATTR_TYPE, subj, (DWORD)len);
    }
}

struct win32crypto_engine_s* new_win32engine(
    const char* hostname, HCERTSTORE ca, PCCERT_CONTEXT own_cert,
    int (*cert_verify_f)(const struct tlsuv_certificate_s* cert, void* v_ctx),
    void* verify_ctx) {
    struct win32crypto_engine_s* engine = engine_alloc(false, ca, cert_verify_f, verify_ctx);
    engine->hostname = hostname ? tlsuv__strdup(hostname) : NULL;

    char subj[256];
    cert_subject(own_cert, subj, sizeof(subj));
    UM_LOG(INFO, "creating client engine host[%s] subject[%s]", engine->hostname, subj);

    DWORD flags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MEMORY_STORE_CERT;
    // engine_alloc() set a verifier iff there is something to verify against
    flags |= engine->cert_verify_f ? SCH_CRED_MANUAL_CRED_VALIDATION : SCH_CRED_AUTO_CRED_VALIDATION;

    PCCERT_CONTEXT certs[1] = {own_cert,};
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

struct win32crypto_engine_s *new_win32_server_engine(
    HCERTSTORE ca, PCCERT_CONTEXT own_cert,
    int (*cert_verify_f)(const struct tlsuv_certificate_s * cert, void *v_ctx),
    void *verify_ctx)
{
    if (own_cert == NULL || own_cert == INVALID_HANDLE_VALUE) {
        UM_LOG(ERR, "server engine requires server credentials");
        return NULL;
    }

    struct win32crypto_engine_s *engine = engine_alloc(true, ca, cert_verify_f, verify_ctx);
    // nothing to verify a client certificate against means there is no point
    // asking for one
    engine->request_client_cert = engine->cert_verify_f != NULL;

    char subj[256];
    cert_subject(own_cert, subj, sizeof(subj));
    UM_LOG(INFO, "creating server engine subject[%s] client_auth[%s]",
           subj, engine->request_client_cert ? "requested" : "off");

    PCCERT_CONTEXT certs[1] = { own_cert, };
    SCHANNEL_CRED credentials = {
        .dwVersion = SCHANNEL_CRED_VERSION,
        // client certificates are validated by verify_peer_cert(), not by
        // Schannel, and are never mapped to a Windows account
        .dwFlags = SCH_CRED_MEMORY_STORE_CERT |
                   SCH_CRED_MANUAL_CRED_VALIDATION |
                   SCH_CRED_NO_SYSTEM_MAPPER,
        .grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER,
        .cCreds = 1,
        .paCred = certs,
    };

    SECURITY_STATUS rc = AcquireCredentialsHandleA(NULL,
                              (TCHAR *)(UNISP_NAME),
                              SECPKG_CRED_INBOUND, NULL,
                              &credentials, NULL, NULL,
                              &engine->cred_handle,
                              NULL);
    if (rc != ERROR_SUCCESS) {
        // TLS 1.3 server support needs the newer SCH_CREDENTIALS structure on
        // some Windows versions; fall back to TLS 1.2 rather than fail outright
        LOG_ERROR(WARN, rc, "AcquireCredentialsHandleA(TLS1.2+TLS1.3) result");
        credentials.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
        rc = AcquireCredentialsHandleA(NULL,
                                       (TCHAR *)(UNISP_NAME),
                                       SECPKG_CRED_INBOUND, NULL,
                                       &credentials, NULL, NULL,
                                       &engine->cred_handle,
                                       NULL);
    }

    if (rc != ERROR_SUCCESS) {
        LOG_ERROR(ERR, rc, "failed to acquire server credentials");
        engine_free(&engine->api);
        return NULL;
    }
    return engine;
}