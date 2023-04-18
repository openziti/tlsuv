CMAKE_MINIMUM_REQUIRED(VERSION 3.22)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH}")

include(cmake/version.cmake)
get_version(${CMAKE_CURRENT_LIST_DIR}/version.txt ver)

PROJECT("tlsuv"
        LANGUAGES C
        VERSION ${ver}
        )

message("Project: ${PROJECT_NAME}@v${PROJECT_VERSION}")
include(cmake/project-is-top-level.cmake)
include(cmake/variables.cmake)
include(CMakeDependentOption)
include(GNUInstallDirs)

set(TLSUV_TLSLIB "openssl" CACHE STRING "TLS implementation library (openssl|mbedtls)")

if(NOT (TLSUV_TLSLIB STREQUAL "openssl" OR TLSUV_TLSLIB STREQUAL "mbedtls"))
    message(FATAL_ERROR "`${TLSUV_TLSLIB}' TLS library is not supported")
endif()

cmake_dependent_option(USE_OPENSSL "Use OpenSSL" ON "TLSUV_TLSLIB STREQUAL openssl; NOT USE_MBEDTLS" OFF)
cmake_dependent_option(USE_MBEDTLS "Use mbedTLS" ON "TLSUV_TLSLIB STREQUAL mbedtls" OFF)

set(tlsuv_sources
        src/tlsuv.c
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
        src/p11.c
        src/p11.h
        )

if(USE_OPENSSL)
    set(tlsImpl openssl)
    FILE(GLOB ssl_files src/openssl/*)
    LIST(APPEND tlsuv_sources
            ${ssl_files}
            )
endif()

if(USE_MBEDTLS)
    set(tlsImpl mbedtls)
    FILE(GLOB ssl_files src/mbedtls/*)

    LIST(APPEND tlsuv_sources
            ${ssl_files}
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

add_library(tlsuv_lib STATIC
        ${tlsuv_sources}
        )
add_library(tlsuv::tlsuv ALIAS tlsuv_lib)

include(GenerateExportHeader)
generate_export_header(
    tlsuv_lib
    BASE_NAME tlsuv
    EXPORT_FILE_NAME export/tlsuv/tlsuv_export.h
)

# just static lib for now
target_compile_definitions(tlsuv_lib PUBLIC TLSUV_STATIC_DEFINE)

set_target_properties(tlsuv_lib PROPERTIES
        C_STANDARD 99
        C_VISIBILITY_PRESET hidden
        VERSION "${PROJECT_VERSION}"
        SOVERSION "${PROJECT_VERSION_MAJOR}"
        EXPORT_NAME tlsuv
        OUTPUT_NAME tlsuv
        )

target_include_directories(tlsuv_lib
        PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/uv_link_t/include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        )

find_package(ZLIB REQUIRED)

target_link_libraries(tlsuv_lib
        PRIVATE llhttp::llhttp_static
        PUBLIC ${TLSUV_LIBUV_LIB}
        PUBLIC $<TARGET_OBJECTS:uv_link>
        PRIVATE ZLIB::ZLIB
        )
TARGET_COMPILE_DEFINITIONS(tlsuv_lib PRIVATE TLSUV_VERSION=v${PROJECT_VERSION})
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    TARGET_COMPILE_DEFINITIONS(tlsuv_lib PRIVATE _POSIX_C_SOURCE=200112 _GNU_SOURCE)
endif()

if (USE_MBEDTLS)
    find_package(MbedTLS REQUIRED)
    target_compile_definitions(tlsuv_lib PRIVATE USE_MBEDTLS)
    target_include_directories(tlsuv_lib PUBLIC $<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIRS}>)
    target_link_libraries(tlsuv_lib PRIVATE ${MBEDTLS_LIBRARIES})
elseif(USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    target_compile_definitions(tlsuv_lib PRIVATE USE_OPENSSL)
    target_link_libraries(tlsuv_lib PRIVATE OpenSSL::SSL)
endif()

if (WIN32)
    target_compile_definitions(tlsuv_lib PRIVATE WIN32_LEAN_AND_MEAN)
    target_link_libraries(tlsuv_lib PUBLIC crypt32)
endif()

# ---- Install rules ----

if(NOT CMAKE_SKIP_INSTALL_RULES)
  include(cmake/install-rules.cmake)
endif()

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