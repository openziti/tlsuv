CMAKE_MINIMUM_REQUIRED(VERSION 3.12)

PROJECT("uv-mbed" C)

option(ENABLE_SAMPLES "Build samples." OFF)

set(ENABLE_PROGRAMS OFF)
set(ENABLE_TESTING OFF)
add_subdirectory(mbedtls)
set_target_properties(mbedtls PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/mbedtls/include)

set(BUILD_TESTING OFF)
set(ENABLE_PROGRAMS OFF)
add_subdirectory(libuv)
set_target_properties(uv_a PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libuv/include)

add_library(uv_mbed STATIC
        src/uv_mbed.c src/uv_mbed.c src/bio.c src/bio.h)
target_include_directories(uv_mbed PUBLIC include)

target_link_libraries(uv_mbed
        PUBLIC uv_a
        PUBLIC mbedtls
        PUBLIC mbedx509
        PUBLIC mbedcrypto)


if(ENABLE_SAMPLES)
add_subdirectory(sample)
endif()