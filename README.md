TLSUV = TLS + libUV
----

## Overview
TLSUV is a cross-platform library allowing asynchronous TLS communication. 
This is done by combinining [libuv](https://github.com/libuv/libuv) with one of the supported TLS libraries:
[OpenSSL](https://www.openssl.org/), [BoringSSL](https://boringssl.googlesource.com/boringssl/),
[Windows crypto](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/),
[Apple Network.framework](https://developer.apple.com/documentation/network), or
[mbedTLS](https://github.com/mbedtls/mbedtls)
(see [TLS backends](#tls-backends) for what each of them supports, and below for using other TLS implementations)

API is attempted to be consistent with [libuv API](http://docs.libuv.org/en/v1.x/api.html)

## Supported Platforms
* Linux
* Darwin/MacOS
* Windows

## Using in your project
The simplest way to integrate `tlsuv` in your project is to include it in your CMake build 
with [`FetchContent`](https://cmake.org/cmake/help/latest/module/FetchContent.html)

```cmake
    FetchContent_Declare(tlsuv
            GIT_REPOSITORY https://github.com/openziti/tlsuv.git
        GIT_TAG v0.40.0 # use latest release version
            )
    FetchContent_MakeAvailable(tlsuv)

    target_link_libraries(your_app PRIVATE tlsuv)
```

## Selectable Features
The TLS implementation is selected with `-DTLSUV_TLSLIB=<backend>` during the CMake configuration step: `openssl`
(the default, except on Windows), `boringssl`, `mbedtls`, `applesec` (macOS and iOS only), or `win32crypto`
(the default on Windows). See [TLS backends](#tls-backends) for what each of them supports and
[Dependencies](#dependencies) for what they require.

HTTP support is a selectable feature (ON by default) and can be disabled by adding `-DTLSUV_HTTP=OFF` during CMake 
configuration step. This will also reduce dependencies list.

## Dependencies
TLSUV depends on the following libraries:

| Library                                                                         | Notes                                                            |
|---------------------------------------------------------------------------------|------------------------------------------------------------------|
| [libuv](https://github.com/libuv/libuv)                                         |                                                                  | 
| TLS - the following are supported                                               | Some features are only available with some of them, see [TLS backends](#tls-backends) |
| - [OpenSSL](https://github.com/openssl/openssl)                                 | default TLS implementation except for Windows                    |
| - [BoringSSL](https://boringssl.googlesource.com/boringssl/)                    | use `TLSUV_TLSLIB=boringssl`                                     |
| - [Windows crypto](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/) | default TLS implementation on Windows                            | 
| - [Apple Network.framework](https://developer.apple.com/documentation/network)  | use `TLSUV_TLSLIB=applesec`, macOS and iOS only                  |
| - [mbedTLS](https://github.com/mbedtls/mbedtls)                                 | use `TLSUV_TLSLIB=mbedtls` does not support PKCS#11 or keychains |
| [llhttp](https://github.com/nodejs/llhttp)                                      | only with HTTP enabled                                           |
| [zlib](https://github.com/madler/zlib)                                          | only with HTTP enabled                                           |


CMake configuration process will attempt to resolve the above dependencies via `find_package()` it is up to consuming project
to provide them.
 

## Features
* client TLS: asynchronous TLS streams over TCP
* server TLS: accept TLS connections with `tlsuv_listener_t`
* HTTP and websocket clients
* flexible TLS engine support
* [pkcs#11](https://en.wikipedia.org/wiki/PKCS_11) support with default(OpenSSL) engine
* keys stored in the platform keychain (see [TLS backends](#tls-backends))

### Client TLS
`tlsuv_stream_t` is a `uv_stream_t`-like handle: initialize it, connect (the TLS handshake completes before the
connect callback), then read and write as with any libuv stream. A `NULL` TLS context selects the default one, which
trusts the system CA store. See [`sample/sample.c`](sample/sample.c).

```c
tlsuv_stream_t clt;
tlsuv_stream_init(loop, &clt, NULL);
tlsuv_stream_connect(&req, &clt, "example.com", 443, on_connect); // uv_connect_cb
// in on_connect: tlsuv_stream_read_start(&clt, alloc_cb, read_cb); tlsuv_stream_write(&wr, &clt, &buf, write_cb);
```

### Server TLS
`tlsuv_listener_t` ([`tlsuv/listener.h`](include/tlsuv/listener.h)) provides libuv-style listen/accept: it accepts TCP
connections, completes the TLS handshake on each, and hands the application a `tlsuv_stream_t`.
See [`sample/echo-server.c`](sample/echo-server.c) for a complete example.

```c
static tlsuv_stream_t *on_accept(tlsuv_listener_t *l, const struct sockaddr *peer, int status) {
    if (status != 0) return NULL; // accepting failed, see below
    return tlsuv_stream_new();    // NULL refuses the connection
}

static void on_handshake(tlsuv_stream_t *clt, int status) {
    if (status != 0) { tlsuv_stream_close(clt, on_closed); return; } // a failed stream stays open
    tlsuv_stream_read_start(clt, alloc_cb, read_cb);
}

tlsuv_listener_t *l = tlsuv_listener_new();
tlsuv_listener_init(loop, l, tls); // tls: set_own_cert() already called
tlsuv_listener_bind(l, (const struct sockaddr *) &addr, 0);
tlsuv_listener_start_listen(l, 128, on_accept, on_handshake);
```

`on_accept` is also called with a non-zero `status` (and `peer == NULL`) when accepting fails. `UV_EMFILE`/`UV_ENFILE`
means the process is out of descriptors. On POSIX the listener then sheds the connections that were waiting, using a
spare descriptor, and keeps listening; on Windows, or if it has no spare descriptor, it stops. For any other error the
listener has stopped. Either way `tlsuv_listener_start_listen()` resumes a stopped listener, and returns `UV_EALREADY`
if it is still listening.
If `on_accept` returns a stream for a failure, it is initialised and `on_handshake` is called with the same error code
(close the stream there as for any failed handshake).

Once bound, the listener is also a libuv handle: cast it to `uv_handle_t *` to use `uv_unref()`, `uv_is_active()`,
`uv_walk()` and the other read-only calls. Underneath it is a `UV_POLL` handle, not a `uv_stream_t`, so `uv_listen()`
and `uv_accept()` do not apply. Close it with `tlsuv_listener_close()`, not `uv_close()`; its `close_cb` receives the
listener as a `uv_handle_t *` (same address, cast it back), after the socket has been closed.

Requires a backend with `new_server_engine` (not mbedtls); `tlsuv_listener_init()` returns `UV_ENOTSUP` otherwise.

### HTTP and websocket clients
[`tlsuv/http.h`](include/tlsuv/http.h) and [`tlsuv/websocket.h`](include/tlsuv/websocket.h) provide HTTP(S) and
websocket clients on top of the same streams (enabled by default, see [Selectable Features](#selectable-features)).
See the [`um-curl`](sample/um-curl.c), [`http-ping`](sample/http-ping.c) and [`ws-client`](sample/ws-client.c) samples.

## TLS backends
The TLS implementation is chosen when configuring the build with `-DTLSUV_TLSLIB=<backend>`.
The default is `openssl`, except on Windows where it is `win32crypto`. `mbedtls` has the fewest features
and is listed last as the least preferred choice.

| | `openssl` | `boringssl` | `win32crypto` | `applesec` | `mbedtls` |
|---|:---:|:---:|:---:|:---:|:---:|
| **General** | | | | | |
| Library | [OpenSSL](https://www.openssl.org/) | [BoringSSL](https://boringssl.googlesource.com/boringssl/) | Windows crypto ([Schannel](https://learn.microsoft.com/en-us/windows/win32/secauthn/secure-channel), [CNG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)) | Apple [Network.framework](https://developer.apple.com/documentation/network), [Security.framework](https://developer.apple.com/documentation/security) | [mbedTLS](https://github.com/mbedtls/mbedtls) |
| Platforms | Linux, macOS, Windows, Android | Linux, macOS, Android | Windows | macOS, iOS (opt-in) | Linux, macOS, Windows |
| ALPN | ✅ | ✅ | ✅ | ✅ | ✅ |
| FIPS status reporting | ✅ | ✅ | ✅ | ✅ | ✅ |
| Restrict to FIPS-approved algorithms (`require_fips`) | ✅ | ✅ [^8] | ✅ [^9] | ✅ [^10] | ✅ [^11] |
| Custom certificate verification callback | ✅ | ✅ | ✅ | ✅ | ✅ |
| Replace the CA bundle (`set_ca_bundle`) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Accept partial certificate chains | ✅ | ✅ | ❌ | ❌ | ❌ |
| Peer certificate after handshake (`get_peer_cert`) | ✅ | ✅ | ✅ | ✅ | ❌ |
| Key generation, CSR generation | ✅ | ✅ | ✅ | ✅ | ✅ |
| [PKCS#11](https://en.wikipedia.org/wiki/PKCS_11) keys | ✅ | ❌ | ❌ | ❌ | ❌ |
| Keys in the platform keychain (`*_keychain_key`) | ✅ [^2] | ✅ [^2] | ✅ [^3] | ❌ | ❌ |
| **Client** | | | | | |
| Client connections (stream, HTTP, WebSocket) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Client certificate and key (`set_own_cert`) | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Server** | | | | | |
| Server connections (`new_server_engine`) | ✅ | ✅ | ✅ | ✅ | ❌ |
| Server requires a client certificate | ✅ [^1] | ✅ [^1] | ✅ [^1] | ✅ [^1] | ❌ |
| Server sends the acceptable client CAs hint | ✅ [^4] | ✅ [^4] | ❌ [^5] | ❌ [^6] | ❌ |
| **Protocol** | | | | | |
| TLS 1.3 | ✅ | ✅ | ✅ [^7] | ✅ | ✅ |
| TLS 1.2 and 1.3 only (no older protocol versions) | ✅ | ✅ | ✅ | ✅ | ✅ |

[^1]: Only when the context has an explicit CA bundle (`set_ca_bundle`) or a verification callback
(`set_cert_verify`). The system CA store is never used for client certificates, and a client that presents none
(or an untrusted one) fails the handshake. The callback takes precedence over the bundle.
[^2]: Needs a keychain: the built-in one on Apple platforms, or one the application registers with
`tlsuv_set_keychain()` (for example one backed by the Android Keystore). Register it before creating a TLS context,
contexts created earlier have no keychain support. Generated keychain keys are EC. RSA keychain keys sign with
PKCS#1 v1.5 (TLS 1.2) or RSA-PSS (TLS 1.3); for RSA-PSS the keychain is asked to sign the already padded block
(`RSA_NO_PADDING`), so it has to support that.
[^3]: Windows CNG key storage, no registration needed.
[^4]: The CA names of the bundle, so clients can pick a matching identity. Only with a CA bundle (not with a
verification callback alone). It is a hint: validation never depends on it.
[^5]: Left to Schannel: whether and which issuers it sends is a system-wide setting (`SendTrustedIssuerList`,
off by default since Windows Server 2012), not controlled by the bundle.
[^6]: Network.framework has no public API for it.
[^7]: Windows 11 and Windows Server 2022 or later. Older Windows versions negotiate TLS 1.2.
[^8]: Applied through BoringSSL's own FIPS compliance policy, which also allows `rsa_pkcs1_sha512`. Keychain keys sign
only with signature algorithms from that policy.
[^9]: Partial. Schannel can only disable algorithms. Protocols below TLS 1.2 are always disabled. With `require_fips`,
AES-CBC, ChaCha20-Poly1305, SHA-1 digests and finite-field DH are also disabled, and the restricted credentials also set
`SCH_USE_STRONG_CRYPTO` (Schannel drops known-weak algorithms; this is not FIPS enforcement). Curves, signature
algorithms and static-RSA key exchange are not enforced and follow the operating system policy. If Schannel rejects the
restricted credentials (for example `SCH_CREDENTIALS` itself, which needs Windows 10 1809 / Server 2019 or later), there
is no fallback to unrestricted credentials: server engines are not created and client engines fail the handshake.
[^10]: Partial. Network.framework only allows choosing cipher suites: TLS 1.3 AES-GCM and TLS 1.2 ECDHE AES-GCM suites
are selected, while key-agreement groups and signature algorithms stay at the system defaults.
[^11]: Policy only, full approved set (RSA-PSS signatures only take effect in TLS 1.3, mbedTLS 3.6 does not support them
in TLS 1.2): mbedTLS has no FIPS-validated mode, so the status stays `TLS_FIPS_UNSUPPORTED`.

`require_fips` limits the algorithms negotiated in the handshake (cipher suites, key-agreement groups and signature
algorithms, as far as the backend allows). It does not constrain X.509 certificate chain validation (certificate
signatures, key sizes). The approved set is described in the `require_fips` documentation in
[tls_engine.h](include/tlsuv/tls_engine.h).

Every member of the [TLS engine interfaces](include/tlsuv/tls_engine.h) that a backend does not provide is `NULL`,
so check before calling.

## TLS engine support (BYFE - Bring Your Favorite Engine)
If either of two TLS library options are not working for, there is a mechanism to dynamically provide TLS implementation.

For example, you're already using another TLS library for your project, there is a way to use it inside _tlsuv_.
Two API [interfaces are defined](include/tlsuv/tls_engine.h) for that purpose:

- `tls_context` is roughly equivalent to `mbedtls_ssl_config` or `SSL_CTX`in OpenSSL and is used to create instances
of `tls_engine` for individual connections
- `tls_engine` is an object for handling handshake and encryption for a single connection.
Similar in purpose to `mbedtls_ssl_ctx` or `SSL` in OpenSSL

Both interfaces carry optional members that may be `NULL` when an implementation does not provide them,
so always check before calling; the [TLS backends](#tls-backends) table shows which backend provides what.
Server support is engine-level here: a context may provide `new_server_engine()`, which the application can use with
its own listening socket and accept loop. For a ready-made accept loop see
[Server TLS](#server-tls).

## Building standalone 
See [development](HACKING.md) instruction for building this project standalone 
for checking out samples, or contributing.


## Getting Help

------------
Please use these community resources for getting help. We use GitHub [issues](https://github.com/openziti/tlsuv/issues)
for tracking bugs and feature requests and have limited bandwidth to address them.

- Read [the docs](https://docs.openziti.io/)
- Ask a question on [Discourse](https://openziti.discourse.group/)

Copyright&copy; 2018-2024. NetFoundry, Inc.
