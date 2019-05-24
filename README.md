## Overview
UV-MBED is a cross-platform library allowing asynchronous TLS communication. 
This is done by combinining [libuv](https://github.com/libuv/libuv) with [mbedTLS](https://github.com/ARMmbed/mbedtls.git)

### Features
* async TLS over TCP

### API
API is attempted to be consistent with [libuv API](http://docs.libuv.org/en/v1.x/api.html)

### Suuported Platforms
* Linux
* Darwin/MacOS
* Windows


#### Windows
Building on windows:
* ensure cmake is on your path
* cd to root of checkout
* mkdir build
* cd build
* after checking out the project - open a visual studio command prompt
** if vs 2017 issue: cmake -G "Visual Studio 15 2017" .. -DCMAKE_INSTALL_INCLUDEDIR=include
** if vs 2019 issue: cmake -G "Visual Studio 16 2019" .. -DCMAKE_INSTALL_INCLUDEDIR=include
* test building with cmake/msbuild: 
** cmake --build . --config Debug
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



