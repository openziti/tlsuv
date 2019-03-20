CMAKE_MINIMUM_REQUIRED(VERSION 3.12)

PROJECT("uv-mbed" C)

option(ENABLE_SAMPLES "Build samples." OFF)

include_directories(
        mbedtls/include
        libuv/include)

set(ENABLE_PROGRAMS OFF)
set(ENABLE_TESTING OFF)
add_subdirectory(mbedtls)

set(BUILD_TESTING OFF)
set(ENABLE_PROGRAMS OFF)
add_subdirectory(libuv)

include_directories(include)
add_library(uv_mbed STATIC
        src/uv_mbed.c src/uv_mbed.c src/bio.c src/bio.h)

target_link_libraries(uv_mbed
        INTERFACE uv_a
        mbedtls mbedx509 mbedcrypto)

if(ENABLE_SAMPLES)
add_subdirectory(sample)
endif()