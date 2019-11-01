UV-MBED
----

## Overview
UV-MBED is a cross-platform library allowing asynchronous TLS communication. 
This is done by combinining [libuv](https://github.com/libuv/libuv) with [mbedTLS](https://github.com/ARMmbed/mbedtls.git)
(see below for using other TLS implementations)

## Features
* async TLS over TCP
* Flexible TLS engine support
* [pkcs#11](https://en.wikipedia.org/wiki/PKCS_11) support with default(mbedTLS) engine

## API
API is attempted to be consistent with [libuv API](http://docs.libuv.org/en/v1.x/api.html)

## Suuported Platforms
* Linux
* Darwin/MacOS
* Windows

## TLS engine support (BYFE - Bring Your Favorite Engine)
If using mbedTLS does not work for you,
for example you're already using another TLS library for your project, there is a way to use it inside _uv-mbed_.
Two API [interfaces are defined](include/uv_mbed/tls_engine.h) for that purpose:

- `tls_context` is roughly equivalent to `mbedtls_ssl_config` or `SSL_CTX`in OpenSSL and is used to create instances
of `tls_engine` for individual connections
- `tls_engine` is an object for handling handshake and encryption for a single connection.
Similar in purpose to `mbedtls_ssl_ctx` or `SSL` in OpenSSL

## Build
* Dependencies (libuv, and mbedTLS) are specified as [git submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules).
Make sure to get them with `$ git submodule update --init --recursive`
* We use [Cmake](https://cmake.org) as our build system.
Any of the standard generators(`makefile`, [`ninja`](https://ninja-build.org/))
should be working fine, let us know if you see any issues.

#### Windows
Building on windows:
* ensure cmake is on your path
* cd to root of checkout
* mkdir build
* cd build
* after checking out the project - open a visual studio command prompt
    * if vs 2017 issue: `cmake -G "Visual Studio 15 2017" .. -DCMAKE_INSTALL_INCLUDEDIR=include`
    * if vs 2019 issue: `cmake -G "Visual Studio 16 2019" .. -DCMAKE_INSTALL_INCLUDEDIR=include`
* test building with cmake/msbuild:
    * `cmake --build . --config Debug`
* execute the sample application and verify the output looks like the following (note: exe is at sample\Debug\sample.exe)

        c:\git\uv-mbed\2017>sample\Debug\sample.exe
        request sent 0
        HTTP/1.1 301 Moved Permanently
        Location: https://www.google.com/
        Content-Type: text/html; charset=UTF-8
        Date: Fri, 24 May 2019 05:30:28 GMT
        Expires: Sun, 23 Jun 2019 05:30:28 GMT
        Cache-Control: public, max-age=2592000
        Server: gws
        Content-Length: 220
        X-XSS-Protection: 0
        X-Frame-Options: SAMEORIGIN
        Alt-Svc: quic=":443"; ma=2592000; v="46,44,43,39"
        Connection: close

        <HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
        <TITLE>301 Moved</TITLE></HEAD><BODY>
        <H1>301 Moved</H1>
        The document has moved
        <A HREF="https://www.google.com/">here</A>.
        </BODY></HTML>
        =====================
        connection closed
        mbed is closed



