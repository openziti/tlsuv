CMAKE_MINIMUM_REQUIRED(VERSION 3.22)

include(cmake/version.cmake)
get_version(${CMAKE_CURRENT_LIST_DIR}/version.txt ver)

PROJECT("tlsuv"
        LANGUAGES C
        VERSION ${ver}
        )

message("Project: ${PROJECT_NAME}@v${PROJECT_VERSION}")
include(cmake/project-is-top-level.cmake)
include(cmake/variables.cmake)

include(GNUInstallDirs)

set(TLSUV_TLSLIB "openssl" CACHE STRING "TLS implementation library (openssl|mbedtls)")

if(NOT (TLSUV_TLSLIB STREQUAL "openssl" OR TLSUV_TLSLIB STREQUAL "mbedtls"))
    message(FATAL_ERROR "`${TLSUV_TLSLIB}' TLS library is not supported")
endif()

cmake_dependent_option(USE_OPENSSL "Use OpenSSL" ON "TLSUV_TLSLIB STREQUAL openssl; NOT USE_MBEDTLS" OFF)
cmake_dependent_option(USE_MBEDTLS "Use mbedTLS" ON "TLSUV_TLSLIB STREQUAL mbedtls" OFF)

set(tlsuv_sources
        src/uv_mbed.c
        src/bio.c
        src/http.c
        src/tcp_src.c
        src/um_debug.c
        src/um_debug.h
        src/websocket.c
        src/http_req.c
        src/tls_link.c
        src/base64.c
        src/tls_engine.c
        src/compression.c
        src/compression.h
        )

if(USE_OPENSSL)
    set(tlsImpl openssl)
    LIST(APPEND tlsuv_sources
            src/engine_openssl.c
            )
endif()

if(USE_MBEDTLS)
    set(tlsImpl mbedtls)
    LIST(APPEND tlsuv_sources
            src/engine_mbedtls.c
            src/p11/p11_mbedtls/mbed_p11.c
            src/p11/p11_mbedtls/p11_ecdsa.c
            src/p11/p11_mbedtls/p11_rsa.c
            )
endif()

find_package(libuv CONFIG QUIET)
if (libuv_FOUND)
    if (TARGET uv_a)
        set(TLSUV_LIBUV_LIB uv_a)
    else()
        set(TLSUV_LIBUV_LIB uv)
    endif()
else()
    find_path(TLSUV_LIBUV_INCLUDE NAMES uv.h)
    find_library(TLSUV_LIBUV_LIB uv_a NAMES uv)
endif()

find_package(llhttp CONFIG REQUIRED)

add_subdirectory(deps)

add_library(tlsuv STATIC
        ${tlsuv_sources}
        )

set_property(TARGET tlsuv PROPERTY C_STANDARD 99)

target_include_directories(tlsuv
        PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/p11
        )

find_package(ZLIB REQUIRED)

target_link_libraries(tlsuv
        PRIVATE llhttp::llhttp_static
        PRIVATE ${TLSUV_LIBUV_LIB}
        PUBLIC uv_link
        PRIVATE ZLIB::ZLIB
        )
TARGET_COMPILE_DEFINITIONS(tlsuv PRIVATE TLSUV_VERSION=v${PROJECT_VERSION})
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    TARGET_COMPILE_DEFINITIONS(tlsuv PRIVATE _POSIX_C_SOURCE=200112 _GNU_SOURCE)
endif()

if (USE_MBEDTLS)
    include(deps/mbedtls.cmake)
    target_compile_definitions(tlsuv PRIVATE USE_MBEDTLS)
    target_link_libraries(tlsuv
            PRIVATE mbedtls
            )
elseif(USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    target_compile_definitions(tlsuv PRIVATE USE_OPENSSL)
    target_link_libraries(tlsuv PRIVATE OpenSSL::SSL)
endif()

if (WIN32)
    target_link_libraries(tlsuv PUBLIC crypt32)
endif()

install(DIRECTORY include/tlsuv DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS tlsuv
        ARCHIVE DESTINATION lib)


if(PROJECT_IS_TOP_LEVEL)
  option(BUILD_EXAMPLES "Build examples tree." "${tlsuv_DEVELOPER_MODE}")
  if(BUILD_EXAMPLES)
    add_subdirectory(sample)
  endif()
endif()

if(tlsuv_DEVELOPER_MODE)
ENABLE_TESTING()
set(MEMORYCHECK_SUPPRESSIONS_FILE "${CMAKE_CURRENT_LIST_DIR}/.valgrind.suppressions")
add_subdirectory(tests)
endif()