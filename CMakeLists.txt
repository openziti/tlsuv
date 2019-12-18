CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

PROJECT("uv-mbed"
        LANGUAGES C
        VERSION 0.5.0
        )

#sample is off by default
option(ENABLE_SAMPLES "Build samples." OFF)

add_subdirectory(deps)

set(uv_mbed_sources
        src/uv_mbed.c
        src/bio.c
        src/engine_mbedtls.c
        src/http.c)

set(p11_sources
        src/p11/p11_mbedtls/mbed_p11.c
        src/p11/p11_mbedtls/p11_ecdsa.c
        src/p11/p11_mbedtls/p11_rsa.c)

add_library(uv_mbed STATIC
        ${uv_mbed_sources}
        ${p11_sources}
        )

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

install(DIRECTORY include/uv_mbed DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS uv_mbed
        ARCHIVE DESTINATION lib)

if(ENABLE_SAMPLES)
add_subdirectory(sample)
endif()

ENABLE_TESTING()
add_subdirectory(tests)
