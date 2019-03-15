CMAKE_MINIMUM_REQUIRED(VERSION 3.12)

PROJECT("uv-mbed" C)

include_directories(include)
add_library(uv_mbed STATIC
        src/uv_mbed.c src/uv_mbed.c src/bio.c src/bio.h)

target_link_libraries(uv_mbed
        PUBLIC uv
        PUBLIC mbedtls mbedx509 mbedcrypto)

add_subdirectory(sample)