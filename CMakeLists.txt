CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

PROJECT("uv-mbed"
        LANGUAGES C
        VERSION 0.5.0
        )

#sample is off by default
option(ENABLE_UM_SAMPLES "Build samples." OFF)

option(ENABLE_UM_TESTS "Build tests." ON)

add_subdirectory(deps)

set(uv_mbed_sources
        src/uv_mbed.c
        src/bio.c
        src/engine_mbedtls.c
        src/http.c
        src/tcp_src.c
        src/um_debug.c
        src/um_debug.h
        src/websocket.c
        src/http_req.c
        src/tls_link.c
        src/base64.c
        )

set(p11_sources
        src/p11/p11_mbedtls/mbed_p11.c
        src/p11/p11_mbedtls/p11_ecdsa.c
        src/p11/p11_mbedtls/p11_rsa.c)

add_library(uv_mbed STATIC
        ${uv_mbed_sources}
        ${p11_sources}
        )

set_property(TARGET uv_mbed PROPERTY C_STANDARD 99)

target_include_directories(uv_mbed
        PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/p11
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/libuv/src
        )

target_link_libraries(uv_mbed
        PUBLIC http-parser
        PUBLIC uv_a
        PUBLIC uv_link
        PUBLIC mbedtls
        PUBLIC mbedx509
        PUBLIC mbedcrypto)

if (WIN32)
    target_link_libraries(uv_mbed
            PUBLIC crypt32)

endif()

install(DIRECTORY include/uv_mbed DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS uv_mbed
        ARCHIVE DESTINATION lib)

if(ENABLE_UM_SAMPLES)
add_subdirectory(sample)
endif()

if(ENABLE_UM_TESTS)
ENABLE_TESTING()
add_subdirectory(tests)
endif()