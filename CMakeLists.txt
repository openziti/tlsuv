CMAKE_MINIMUM_REQUIRED(VERSION 3.12)

PROJECT("uv-mbed"
        LANGUAGES C
        VERSION 0.5.0
        )

option(ENABLE_SAMPLES "Build samples." OFF)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory(mbedtls)
set_target_properties(mbedtls PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/mbedtls/include)

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
add_subdirectory(libuv)
set_target_properties(uv_a PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libuv/include)

add_library(uv_mbed STATIC
        include/uv_mbed/uv_mbed.h src/uv_mbed.c src/bio.c src/bio.h)

target_include_directories(uv_mbed
        PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        )

target_link_libraries(uv_mbed
        PUBLIC uv_a
        PUBLIC mbedtls
        PUBLIC mbedx509
        PUBLIC mbedcrypto)

install(DIRECTORY include/uv_mbed DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS uv_mbed
        ARCHIVE DESTINATION lib)

#if(ENABLE_SAMPLES)
add_subdirectory(sample)
#endif()
