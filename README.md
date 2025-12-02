TLSUV = TLS + libUV
----

## Overview
TLSUV is a cross-platform library allowing asynchronous TLS communication. 
This is done by combinining [libuv](https://github.com/libuv/libuv) with [mbedTLS](https://github.com/ARMmbed/mbedtls.git) 
or [OpenSSL](https://www.openssl.org/)
(see below for using other TLS implementations)

## Features
* async TLS over TCP
* flexible TLS engine support
* HTTP and websocket clients
* [pkcs#11](https://en.wikipedia.org/wiki/PKCS_11) support with default(OpenSSL) engine

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

## Dependencies
TLSUV depends on the following libraries:

| Library                                                                         | Notes                                                            |
|---------------------------------------------------------------------------------|------------------------------------------------------------------|
| [libuv](https://github.com/libuv/libuv)                                         |                                                                  | 
| TLS - the following are supported                                               | Some features are only available with OpenSSL                    |
| - [OpenSSL](https://github.com/openssl/openssl)                                 | default TLS implementation except for Windows                    |
| - [Windows crypto](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/) | default TLS implementation on Windows                            | 
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