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

## Features
* async TLS over TCP
* flexible TLS engine support
* HTTP and websocket clients
* [pkcs#11](https://en.wikipedia.org/wiki/PKCS_11) support with default(OpenSSL) engine
* keys stored in the platform keychain (see [TLS backends](#tls-backends))

## API
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
HTTP support is a selectable feature (ON by default) and can be disabled by adding `-DTLSUV_HTTP=OFF` during CMake 
configuration step. This will also reduce dependencies list.

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
| Custom certificate verification callback | ✅ | ✅ | ✅ | ✅ | ✅ |
| Replace the CA bundle (`set_ca_bundle`) | ✅ | ✅ | ✅ | ✅ | ❌ |
| Accept partial certificate chains | ✅ | ✅ | ❌ | ❌ | ❌ |
| Peer certificate after handshake (`get_peer_cert`) | ✅ [^1] | ✅ [^1] | ✅ | ✅ | ❌ |
| Key generation, CSR generation | ✅ | ✅ | ✅ | ✅ | ✅ |
| [PKCS#11](https://en.wikipedia.org/wiki/PKCS_11) keys | ✅ | ❌ | ❌ | ❌ | ❌ |
| Keys in the platform keychain (`*_keychain_key`) | ✅ [^2] | ✅ [^2] | ✅ [^3] | ❌ | ❌ |
| **Client** | | | | | |
| Client connections (stream, HTTP, WebSocket) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Client certificate and key (`set_own_cert`) | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Server** | | | | | |
| Server connections (`new_server_engine`) | ✅ | ✅ | ✅ | ✅ | ❌ |
| Server asks for a client certificate | ❌ | ❌ | ✅ [^4] | ❌ | ❌ |

[^1]: Client connections only: server engines of this backend do not request client certificates, so they
have no peer certificate and leave `get_peer_cert` `NULL`.
[^2]: Needs a keychain: the built-in one on Apple platforms, or one the application registers with
`tlsuv_set_keychain()` (for example one backed by the Android Keystore). Register it before creating a TLS context,
contexts created earlier have no keychain support. Generated keychain keys are EC. RSA keychain keys sign with
PKCS#1 v1.5, which limits them to TLS 1.2 with `boringssl`.
[^3]: Windows CNG key storage, no registration needed.
[^4]: Only when a certificate verification callback is set, and the client may still connect without one.

Every member of the [TLS engine interfaces](include/tlsuv/tls_engine.h) that a backend does not provide is `NULL`,
so check before calling.

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
Server support is engine-level: the application owns the listening socket and the accept loop, and
`tlsuv_stream_t` has no listen/accept API.

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