// Copyright (c) 2026. NetFoundry Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//         https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Proof that the win32crypto backend verifies the peer certificate chain against
// the trusted CA bundle: it must reject a certificate the trusted CA did not
// sign. Each case runs a real TLS handshake in this process, over an in-memory
// transport, with a tlsuv win32crypto client that trusts a CA bundle and no
// verify callback (so the backend's own chain check, verify_cert_ca, runs).
//
// The certificates are minted at test time with OpenSSL so validity windows and
// signatures can be controlled exactly. Ported from the ziti-sdk-c reference
// test "win32crypto verifies the peer chain against the CA bundle".

#include <catch2/catch_all.hpp>

#include <tlsuv/tls_engine.h>

#include <cstring>
#include <deque>
#include <memory>
#include <string>

#if defined(TEST_win32crypto)

#include <windows.h>
#include <ncrypt.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

namespace {

// ------------------------------------------------------------ in-memory transport
struct mem_pipe {
    std::deque<char> buf;
};

struct mem_endpoint {
    mem_pipe *in;
    mem_pipe *out;
};

ssize_t mem_read(io_ctx c, char *out, size_t len) {
    auto *p = static_cast<mem_endpoint *>(c)->in;
    if (p->buf.empty()) return TLS_AGAIN;
    size_t n = std::min(len, p->buf.size());
    std::copy_n(p->buf.begin(), n, out);
    p->buf.erase(p->buf.begin(), p->buf.begin() + (long) n);
    return (ssize_t) n;
}

ssize_t mem_write(io_ctx c, const char *in, size_t len) {
    auto *ep = static_cast<mem_endpoint *>(c);
    ep->out->buf.insert(ep->out->buf.end(), in, in + len);
    return (ssize_t) len;
}

// runs both engines until each completes or one fails
void run_handshake(tlsuv_engine_t clt, tlsuv_engine_t srv, tls_handshake_state &cs, tls_handshake_state &ss) {
    cs = TLS_HS_CONTINUE;
    ss = TLS_HS_CONTINUE;
    for (int i = 0; i < 100 && !(cs == TLS_HS_COMPLETE && ss == TLS_HS_COMPLETE); i++) {
        cs = clt->handshake(clt);
        ss = srv->handshake(srv);
        if (cs == TLS_HS_ERROR || ss == TLS_HS_ERROR) break;
    }
}

int reject_client_cert(const struct tlsuv_certificate_s *, void *ctx) {
    return *static_cast<int *>(ctx);
}

// ------------------------------------------------------------------- OpenSSL helpers
struct pkey_deleter { void operator()(EVP_PKEY *k) const { EVP_PKEY_free(k); } };
using pkey_ptr = std::unique_ptr<EVP_PKEY, pkey_deleter>;

struct x509_deleter { void operator()(X509 *x) const { X509_free(x); } };
using x509_ptr = std::unique_ptr<X509, x509_deleter>;

pkey_ptr gen_key() {
    pkey_ptr k{EVP_EC_gen("P-256")};
    REQUIRE(k);
    return k;
}

void add_ext(X509 *x, X509 *issuer, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer ? issuer : x, x, nullptr, nullptr, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    REQUIRE(ext != nullptr);
    X509_add_ext(x, ext, -1);
    X509_EXTENSION_free(ext);
}

std::string to_pem(X509 *x) {
    BIO *out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(out, x);
    char *data = nullptr;
    long len = BIO_get_mem_data(out, &data);
    std::string pem(data, (size_t) len);
    BIO_free(out);
    return pem;
}

std::string to_pem(EVP_PKEY *k) {
    BIO *out = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(out, k, nullptr, nullptr, 0, nullptr, nullptr);
    char *data = nullptr;
    long len = BIO_get_mem_data(out, &data);
    std::string pem(data, (size_t) len);
    BIO_free(out);
    return pem;
}

// Mints a certificate for `key` with subject CN=`subject`, issuer CN=`issuer_cn`,
// signed with `signer` (whose cert is `signer_cert`, or NULL for self-signed), CA
// flag `ca`, valid from now+not_before_days to now+not_after_days. SKI/AKID are
// added so a multi-certificate chain links up by name for CryptoAPI.
x509_ptr issue_cert(EVP_PKEY *key, const char *subject, const char *issuer_cn,
                    EVP_PKEY *signer, X509 *signer_cert, bool ca,
                    long not_before_days, long not_after_days) {
    x509_ptr x{X509_new()};
    X509_set_version(x.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x.get()), (long) (uintptr_t) key & 0x7fffffff);
    X509_gmtime_adj(X509_getm_notBefore(x.get()), not_before_days * 86400);
    X509_gmtime_adj(X509_getm_notAfter(x.get()), not_after_days * 86400);
    X509_set_pubkey(x.get(), key);
    X509_NAME *sub = X509_get_subject_name(x.get());
    X509_NAME_add_entry_by_txt(sub, "CN", MBSTRING_ASC, (const unsigned char *) subject, -1, -1, 0);
    X509_NAME *iss = X509_get_issuer_name(x.get());
    X509_NAME_add_entry_by_txt(iss, "CN", MBSTRING_ASC, (const unsigned char *) issuer_cn, -1, -1, 0);
    add_ext(x.get(), nullptr, NID_subject_key_identifier, "hash");
    add_ext(x.get(), signer_cert, NID_authority_key_identifier, "keyid:always");
    add_ext(x.get(), nullptr, NID_basic_constraints, ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    add_ext(x.get(), nullptr, NID_subject_alt_name, "DNS:localhost");
    add_ext(x.get(), nullptr, NID_ext_key_usage, "serverAuth,clientAuth");
    add_ext(x.get(), nullptr, NID_key_usage,
            ca ? "critical,digitalSignature,keyCertSign" : "critical,digitalSignature,keyEncipherment");
    REQUIRE(X509_sign(x.get(), signer, EVP_sha256()) > 0);
    return x;
}

// set_own_cert persists the identity key into the user key store under the base64
// of the certificate's key id; delete it so the test is reentrant.
void delete_persisted_key(X509 *x) {
    const ASN1_OCTET_STRING *ski = X509_get0_subject_key_id(x);
    if (ski == nullptr) return;
    DWORD len = 0;
    CryptBinaryToStringW(ASN1_STRING_get0_data(ski), (DWORD) ASN1_STRING_length(ski),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &len);
    std::wstring name(len, L'\0');
    CryptBinaryToStringW(ASN1_STRING_get0_data(ski), (DWORD) ASN1_STRING_length(ski),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, name.data(), &len);
    name.resize(len);
    for (auto &ch : name) if (ch == L'/') ch = L'_';
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS) {
        if (NCryptOpenKey(prov, &key, name.c_str(), 0, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
            NCryptDeleteKey(key, 0);
        }
        NCryptFreeObject(prov);
    }
}

// A client that trusts `bundle_pem`, against a server presenting `server_cert_pem`
// (a certificate, or several concatenated) with private key `server_key_pem`.
// Returns the client's final handshake state.
tls_handshake_state client_handshake_with(const std::string &bundle_pem,
                                          const std::string &server_key_pem,
                                          const std::string &server_cert_pem) {
    tls_context *srv = default_tls_context(nullptr, 0);
    tlsuv_private_key_t key = nullptr;
    tlsuv_certificate_t cert = nullptr;
    REQUIRE(srv->load_key(&key, server_key_pem.c_str(), server_key_pem.size()) == 0);
    REQUIRE(srv->load_cert(&cert, server_cert_pem.c_str(), server_cert_pem.size()) == 0);
    REQUIRE(srv->set_own_cert(srv, key, cert) == 0);

    // a CA bundle and no verify callback: the backend's own chain check runs
    tls_context *clt = default_tls_context(bundle_pem.c_str(), bundle_pem.size());

    tlsuv_engine_t srv_eng = srv->new_server_engine(srv);
    tlsuv_engine_t clt_eng = clt->new_engine(clt, "localhost");
    REQUIRE(srv_eng != nullptr);
    REQUIRE(clt_eng != nullptr);

    mem_pipe c2s, s2c;
    mem_endpoint clt_ep{&s2c, &c2s};
    mem_endpoint srv_ep{&c2s, &s2c};
    clt_eng->set_io(clt_eng, &clt_ep, mem_read, mem_write);
    srv_eng->set_io(srv_eng, &srv_ep, mem_read, mem_write);

    tls_handshake_state cs, ss;
    run_handshake(clt_eng, srv_eng, cs, ss);

    clt_eng->free(clt_eng);
    srv_eng->free(srv_eng);
    cert->free(cert);
    key->free(key);
    clt->free_ctx(clt);
    srv->free_ctx(srv);
    return cs;
}

bool is_win32crypto() {
    tls_context *probe = default_tls_context(nullptr, 0);
    bool w = strstr(probe->version(), "win32crypto") != nullptr;
    probe->free_ctx(probe);
    return w;
}

// Mints a certificate but forces its serial number to `serial` (an ASN1_INTEGER
// copied from another certificate), so a forgery can carry a bundle certificate's
// exact issuer DN and serial. Otherwise identical to issue_cert.
x509_ptr forge_with_serial(EVP_PKEY *key, const char *subject, const char *issuer_cn,
                           EVP_PKEY *signer, X509 *signer_cert, bool ca, const ASN1_INTEGER *serial) {
    x509_ptr x{X509_new()};
    X509_set_version(x.get(), 2);
    X509_set_serialNumber(x.get(), (ASN1_INTEGER *) serial);
    X509_gmtime_adj(X509_getm_notBefore(x.get()), -86400);
    X509_gmtime_adj(X509_getm_notAfter(x.get()), 365L * 86400);
    X509_set_pubkey(x.get(), key);
    X509_NAME *sub = X509_get_subject_name(x.get());
    X509_NAME_add_entry_by_txt(sub, "CN", MBSTRING_ASC, (const unsigned char *) subject, -1, -1, 0);
    X509_NAME *iss = X509_get_issuer_name(x.get());
    X509_NAME_add_entry_by_txt(iss, "CN", MBSTRING_ASC, (const unsigned char *) issuer_cn, -1, -1, 0);
    add_ext(x.get(), nullptr, NID_subject_key_identifier, "hash");
    add_ext(x.get(), signer_cert, NID_authority_key_identifier, "keyid:always");
    add_ext(x.get(), nullptr, NID_basic_constraints, ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    add_ext(x.get(), nullptr, NID_subject_alt_name, "DNS:localhost");
    add_ext(x.get(), nullptr, NID_ext_key_usage, "serverAuth,clientAuth");
    add_ext(x.get(), nullptr, NID_key_usage,
            ca ? "critical,digitalSignature,keyCertSign" : "critical,digitalSignature,keyEncipherment");
    REQUIRE(X509_sign(x.get(), signer, EVP_sha256()) > 0);
    return x;
}

// A CryptoAPI certificate context for an OpenSSL X509 (caller frees the context).
PCCERT_CONTEXT to_ctx(X509 *x) {
    unsigned char *der = nullptr;
    int len = i2d_X509(x, &der);
    REQUIRE(len > 0);
    PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING, der, (DWORD) len);
    OPENSSL_free(der);
    return ctx;
}

// Mints an end-entity certificate with an explicit EKU string (e.g. "clientAuth").
x509_ptr issue_leaf_eku(EVP_PKEY *key, const char *subject, const char *san,
                        EVP_PKEY *signer, X509 *signer_cert, const char *eku) {
    x509_ptr x{X509_new()};
    X509_set_version(x.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x.get()), (long) (uintptr_t) key & 0x7fffffff);
    X509_gmtime_adj(X509_getm_notBefore(x.get()), -86400);
    X509_gmtime_adj(X509_getm_notAfter(x.get()), 365L * 86400);
    X509_set_pubkey(x.get(), key);
    X509_NAME *sub = X509_get_subject_name(x.get());
    X509_NAME_add_entry_by_txt(sub, "CN", MBSTRING_ASC, (const unsigned char *) subject, -1, -1, 0);
    X509_NAME *iss = X509_get_issuer_name(x.get());
    X509_NAME_add_entry_by_txt(iss, "CN", MBSTRING_ASC, (const unsigned char *) "TestCA", -1, -1, 0);
    add_ext(x.get(), nullptr, NID_subject_key_identifier, "hash");
    add_ext(x.get(), signer_cert, NID_authority_key_identifier, "keyid:always");
    add_ext(x.get(), nullptr, NID_basic_constraints, "critical,CA:FALSE");
    add_ext(x.get(), nullptr, NID_subject_alt_name, san);
    add_ext(x.get(), nullptr, NID_ext_key_usage, eku);
    add_ext(x.get(), nullptr, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    REQUIRE(X509_sign(x.get(), signer, EVP_sha256()) > 0);
    return x;
}

// A self-signed CA and the client bundle that trusts it. Reused by most cases.
struct ca_fixture {
    pkey_ptr key = gen_key();
    x509_ptr cert = issue_cert(key.get(), "TestCA", "TestCA", key.get(), nullptr, true, -1, 3650);
    std::string bundle = to_pem(cert.get());
};

} // namespace

TEST_CASE("win32crypto rejects a certificate the trusted CA did not sign", "[verify][win32crypto]") {
    if (!is_win32crypto()) {
        SKIP("not a win32crypto build");
    }

    ca_fixture ca;

    SECTION("control: a leaf the CA signed, in date, is accepted") {
        pkey_ptr leaf = gen_key();
        x509_ptr cert = issue_cert(leaf.get(), "localhost", "TestCA",
                                   ca.key.get(), ca.cert.get(), false, -1, 365);
        CHECK(client_handshake_with(ca.bundle, to_pem(leaf.get()), to_pem(cert.get())) == TLS_HS_COMPLETE);
        delete_persisted_key(cert.get());
    }

    SECTION("forged leaf: attacker key signs a leaf naming the CA as issuer, rejected") {
        pkey_ptr attacker = gen_key();
        pkey_ptr leaf = gen_key();
        // issuer name says TestCA, but the signature is the attacker's, not the CA's
        x509_ptr cert = issue_cert(leaf.get(), "localhost", "TestCA",
                                   attacker.get(), nullptr, false, -1, 365);
        CHECK(client_handshake_with(ca.bundle, to_pem(leaf.get()), to_pem(cert.get())) == TLS_HS_ERROR);
        delete_persisted_key(cert.get());
    }

    SECTION("expired leaf the CA signed is rejected") {
        pkey_ptr leaf = gen_key();
        x509_ptr cert = issue_cert(leaf.get(), "localhost", "TestCA",
                                   ca.key.get(), ca.cert.get(), false, -30, -1);
        CHECK(client_handshake_with(ca.bundle, to_pem(leaf.get()), to_pem(cert.get())) == TLS_HS_ERROR);
        delete_persisted_key(cert.get());
    }

    SECTION("not-yet-valid leaf the CA signed is rejected") {
        pkey_ptr leaf = gen_key();
        x509_ptr cert = issue_cert(leaf.get(), "localhost", "TestCA",
                                   ca.key.get(), ca.cert.get(), false, 1, 365);
        CHECK(client_handshake_with(ca.bundle, to_pem(leaf.get()), to_pem(cert.get())) == TLS_HS_ERROR);
        delete_persisted_key(cert.get());
    }

    SECTION("forged CA copy: attacker CA with the real CA's subject, rejected") {
        pkey_ptr attacker = gen_key();
        pkey_ptr leaf = gen_key();
        // a CA certificate carrying the real CA's subject name but the attacker's key,
        // self-signed by the attacker, then used to sign the leaf
        x509_ptr fake_ca = issue_cert(attacker.get(), "TestCA", "TestCA",
                                      attacker.get(), nullptr, true, -1, 3650);
        x509_ptr leaf_cert = issue_cert(leaf.get(), "localhost", "TestCA",
                                        attacker.get(), fake_ca.get(), false, -1, 365);
        std::string chain = to_pem(leaf_cert.get()) + to_pem(fake_ca.get());
        CHECK(client_handshake_with(ca.bundle, to_pem(leaf.get()), chain) == TLS_HS_ERROR);
        delete_persisted_key(leaf_cert.get());
    }

    SECTION("leaf-as-issuer: a real CA-signed end-entity cannot sign another leaf, rejected") {
        // a legitimately CA-signed end-entity certificate (CA:FALSE), such as any
        // enrolled identity, is presented as an intermediate that signs a fake leaf.
        // The second hop of the chain walk must still verify signatures.
        pkey_ptr ee = gen_key();
        pkey_ptr leaf = gen_key();
        x509_ptr ee_cert = issue_cert(ee.get(), "enrolled-identity", "TestCA",
                                      ca.key.get(), ca.cert.get(), false, -1, 365);
        x509_ptr leaf_cert = issue_cert(leaf.get(), "localhost", "enrolled-identity",
                                        ee.get(), ee_cert.get(), false, -1, 365);
        std::string chain = to_pem(leaf_cert.get()) + to_pem(ee_cert.get());
        CHECK(client_handshake_with(ca.bundle, to_pem(leaf.get()), chain) == TLS_HS_ERROR);
        delete_persisted_key(leaf_cert.get());
    }

    SECTION("regression: leaf plus a real intermediate chaining to the bundle root, accepted") {
        pkey_ptr inter = gen_key();
        pkey_ptr leaf = gen_key();
        x509_ptr inter_cert = issue_cert(inter.get(), "TestSubCA", "TestCA",
                                         ca.key.get(), ca.cert.get(), true, -1, 3650);
        x509_ptr leaf_cert = issue_cert(leaf.get(), "localhost", "TestSubCA",
                                        inter.get(), inter_cert.get(), false, -1, 365);
        std::string chain = to_pem(leaf_cert.get()) + to_pem(inter_cert.get());
        CHECK(client_handshake_with(ca.bundle, to_pem(leaf.get()), chain) == TLS_HS_COMPLETE);
        delete_persisted_key(leaf_cert.get());
    }

    SECTION("regression: partial chain, bundle holds only the intermediate, accepted") {
        pkey_ptr inter = gen_key();
        pkey_ptr leaf = gen_key();
        x509_ptr inter_cert = issue_cert(inter.get(), "TestSubCA", "TestCA",
                                         ca.key.get(), ca.cert.get(), true, -1, 3650);
        x509_ptr leaf_cert = issue_cert(leaf.get(), "localhost", "TestSubCA",
                                        inter.get(), inter_cert.get(), false, -1, 365);
        std::string bundle = to_pem(inter_cert.get());
        CHECK(client_handshake_with(bundle, to_pem(leaf.get()), to_pem(leaf_cert.get())) == TLS_HS_COMPLETE);
        delete_persisted_key(leaf_cert.get());
    }
}

// The same verifier defends the server: a client presenting an attacker-signed
// certificate naming the bundle CA must be rejected by a mutual-TLS server.
TEST_CASE("win32crypto server rejects a client cert the trusted CA did not sign", "[verify][win32crypto]") {
    if (!is_win32crypto()) {
        SKIP("not a win32crypto build");
    }

    ca_fixture ca;

    // server identity: a leaf the CA signed
    pkey_ptr srv_leaf = gen_key();
    x509_ptr srv_cert = issue_cert(srv_leaf.get(), "localhost", "TestCA",
                                   ca.key.get(), ca.cert.get(), false, -1, 365);
    std::string srv_key_pem = to_pem(srv_leaf.get());
    std::string srv_cert_pem = to_pem(srv_cert.get());

    auto run = [&](const std::string &clt_key_pem, const std::string &clt_cert_pem) -> tls_handshake_state {
        tls_context *srv = default_tls_context(ca.bundle.c_str(), ca.bundle.size());
        tlsuv_private_key_t sk = nullptr; tlsuv_certificate_t sc = nullptr;
        REQUIRE(srv->load_key(&sk, srv_key_pem.c_str(), srv_key_pem.size()) == 0);
        REQUIRE(srv->load_cert(&sc, srv_cert_pem.c_str(), srv_cert_pem.size()) == 0);
        REQUIRE(srv->set_own_cert(srv, sk, sc) == 0);

        tls_context *clt = default_tls_context(ca.bundle.c_str(), ca.bundle.size());
        tlsuv_private_key_t ck = nullptr; tlsuv_certificate_t cc = nullptr;
        REQUIRE(clt->load_key(&ck, clt_key_pem.c_str(), clt_key_pem.size()) == 0);
        REQUIRE(clt->load_cert(&cc, clt_cert_pem.c_str(), clt_cert_pem.size()) == 0);
        REQUIRE(clt->set_own_cert(clt, ck, cc) == 0);

        tlsuv_engine_t srv_eng = srv->new_server_engine(srv);
        tlsuv_engine_t clt_eng = clt->new_engine(clt, "localhost");
        REQUIRE(srv_eng != nullptr);
        REQUIRE(clt_eng != nullptr);

        mem_pipe c2s, s2c;
        mem_endpoint clt_ep{&s2c, &c2s};
        mem_endpoint srv_ep{&c2s, &s2c};
        clt_eng->set_io(clt_eng, &clt_ep, mem_read, mem_write);
        srv_eng->set_io(srv_eng, &srv_ep, mem_read, mem_write);

        tls_handshake_state cs, ss;
        run_handshake(clt_eng, srv_eng, cs, ss);

        clt_eng->free(clt_eng); srv_eng->free(srv_eng);
        cc->free(cc); ck->free(ck); sc->free(sc); sk->free(sk);
        clt->free_ctx(clt); srv->free_ctx(srv);
        return ss;
    };

    SECTION("a client the CA signed is accepted") {
        pkey_ptr clt_leaf = gen_key();
        x509_ptr clt_cert = issue_cert(clt_leaf.get(), "client", "TestCA",
                                       ca.key.get(), ca.cert.get(), false, -1, 365);
        CHECK(run(to_pem(clt_leaf.get()), to_pem(clt_cert.get())) == TLS_HS_COMPLETE);
        delete_persisted_key(clt_cert.get());
    }

    SECTION("a forged client cert naming the CA as issuer is rejected") {
        pkey_ptr attacker = gen_key();
        pkey_ptr clt_leaf = gen_key();
        x509_ptr clt_cert = issue_cert(clt_leaf.get(), "client", "TestCA",
                                       attacker.get(), nullptr, false, -1, 365);
        CHECK(run(to_pem(clt_leaf.get()), to_pem(clt_cert.get())) == TLS_HS_ERROR);
        delete_persisted_key(clt_cert.get());
    }

    delete_persisted_key(srv_cert.get());
}

// Settles an open review question: does the fix's "certificate is itself in the bundle" shortcut
// (CertFindCertificateInStore with CERT_FIND_EXISTING) match the full encoding, or only issuer name
// and serial? If it matched only issuer+serial, a forgery copying a bundle certificate's issuer DN
// and serial with an attacker key would be trusted. Both the direct probe and the handshake must
// reject it.
TEST_CASE("win32crypto does not trust an issuer+serial copy of a bundle certificate", "[verify][win32crypto]") {
    if (!is_win32crypto()) {
        SKIP("not a win32crypto build");
    }
    ca_fixture ca;
    pkey_ptr attacker = gen_key();
    // forged leaf carrying the real CA's issuer DN and exact serial, attacker key, attacker-signed
    x509_ptr forged = forge_with_serial(attacker.get(), "localhost", "TestCA",
                                        attacker.get(), nullptr, false,
                                        X509_get0_serialNumber(ca.cert.get()));

    // direct probe of CERT_FIND_EXISTING semantics on this Windows build
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING, 0, 0, nullptr);
    REQUIRE(store != nullptr);
    PCCERT_CONTEXT ca_ctx = to_ctx(ca.cert.get());
    PCCERT_CONTEXT forged_ctx = to_ctx(forged.get());
    REQUIRE(ca_ctx != nullptr);
    REQUIRE(forged_ctx != nullptr);
    CertAddCertificateContextToStore(store, ca_ctx, CERT_STORE_ADD_ALWAYS, nullptr);
    PCCERT_CONTEXT found = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
                                                      CERT_FIND_EXISTING, forged_ctx, nullptr);
    bool matched = (found != nullptr);
    INFO("CERT_FIND_EXISTING matched an issuer+serial copy (attacker key): " << (matched ? "YES" : "no"));
    if (found) CertFreeCertificateContext(found);
    CertFreeCertificateContext(forged_ctx);
    CertFreeCertificateContext(ca_ctx);
    CertCloseStore(store, 0);
    // CERT_FIND_EXISTING must compare the full encoding, not just issuer+serial
    CHECK_FALSE(matched);

    // end-to-end: the shortcut must not let the forgery through
    CHECK(client_handshake_with(ca.bundle, to_pem(attacker.get()), to_pem(forged.get())) == TLS_HS_ERROR);
    delete_persisted_key(forged.get());
}

// Documents two preexisting gaps that verify_cert_ca does not close (same advisory, separate
// findings): it never checks the peer hostname, and it never checks the extended key usage. Both
// are expected to be accepted on main and on this fix; a behaviour-based fix that adds an SSL policy
// check would flip these to rejected.
TEST_CASE("win32crypto verify_cert_ca checks neither hostname nor EKU", "[verify][win32crypto]") {
    if (!is_win32crypto()) {
        SKIP("not a win32crypto build");
    }
    ca_fixture ca;

    SECTION("a valid CA-signed leaf for a different hostname is accepted") {
        pkey_ptr leaf = gen_key();
        // client connects to "localhost"; this leaf is only valid for other.example
        x509_ptr cert = issue_leaf_eku(leaf.get(), "other.example", "DNS:other.example",
                                       ca.key.get(), ca.cert.get(), "serverAuth,clientAuth");
        auto st = client_handshake_with(ca.bundle, to_pem(leaf.get()), to_pem(cert.get()));
        INFO("wrong-hostname leaf handshake state (2=COMPLETE,3=ERROR): " << (int) st);
        CHECK(st == TLS_HS_COMPLETE);
        delete_persisted_key(cert.get());
    }

    SECTION("a clientAuth-only leaf presented as a server certificate is accepted") {
        pkey_ptr leaf = gen_key();
        x509_ptr cert = issue_leaf_eku(leaf.get(), "localhost", "DNS:localhost",
                                       ca.key.get(), ca.cert.get(), "clientAuth");
        auto st = client_handshake_with(ca.bundle, to_pem(leaf.get()), to_pem(cert.get()));
        INFO("clientAuth-only server cert handshake state (2=COMPLETE,3=ERROR): " << (int) st);
        CHECK(st == TLS_HS_COMPLETE);
        delete_persisted_key(cert.get());
    }
}

#endif // TEST_win32crypto
