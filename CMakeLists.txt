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

option(TLSUV_HTTP "enable HTTP/websocket support" ON)

set(TLSUV_TLSLIB "openssl" CACHE STRING "TLS implementation library (openssl|mbedtls)")

if(NOT (TLSUV_TLSLIB STREQUAL "openssl" OR TLSUV_TLSLIB STREQUAL "mbedtls"))
    message(FATAL_ERROR "`${TLSUV_TLSLIB}' TLS library is not supported")
endif()

cmake_dependent_option(USE_OPENSSL "Use OpenSSL" ON "TLSUV_TLSLIB STREQUAL openssl; NOT USE_MBEDTLS" OFF)
cmake_dependent_option(USE_MBEDTLS "Use mbedTLS" ON "TLSUV_TLSLIB STREQUAL mbedtls" OFF)

set(tlsuv_sources
        src/tlsuv.c
        src/um_debug.c
        src/um_debug.h
        src/base64.c
        src/tls_engine.c
        src/p11.c
        src/p11.h
        src/socket.c
        src/util.h
        src/connector.c
        src/alloc.c
        src/keychain.c
)

if (APPLE)
    list(APPEND tlsuv_sources
            src/apple/keychain.c
    )
elseif (WIN32)
    list(APPEND tlsuv_sources
            src/win32/win32_keychain.c
    )
endif ()

if (TLSUV_HTTP)
    list(APPEND tlsuv_sources
            src/http.c
            src/tcp_src.c
            src/websocket.c
            src/http_req.c
            src/tls_link.c
            src/compression.c
            src/compression.h
    )
endif (TLSUV_HTTP)

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
    # newer libuv versions have proper namespacing
    if (TARGET libuv::uv_a)
        set(TLSUV_LIBUV_LIB libuv::uv_a)
    elseif (TARGET uv_a)
        set(TLSUV_LIBUV_LIB uv_a)
    elseif (TARGET libuv::uv)
        set(TLSUV_LIBUV_LIB libuv::uv)
    else()
        set(TLSUV_LIBUV_LIB uv)
    endif()
else()
    find_path(TLSUV_LIBUV_INCLUDE NAMES uv.h)
    find_library(TLSUV_LIBUV_LIB uv_a NAMES uv)
endif()


add_library(tlsuv STATIC
        ${tlsuv_sources}
        )

set_target_properties(tlsuv PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_STANDARD 99)

target_include_directories(tlsuv
        PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        )

target_link_libraries(tlsuv
        PRIVATE ${TLSUV_LIBUV_LIB}
)


if (TLSUV_HTTP)

    add_subdirectory(deps)
    target_link_libraries(tlsuv PUBLIC uv_link)

    find_package(ZLIB REQUIRED)
    target_link_libraries(tlsuv PRIVATE ZLIB::ZLIB)

    find_package(llhttp CONFIG REQUIRED)
    message(NOTICE "llhttp = ${llhttp_VERSION}")
    if (TARGET llhttp::llhttp_static)
        target_link_libraries(tlsuv PUBLIC llhttp::llhttp_static)
    elseif (TARGET llhttp::llhttp_shared)
        target_link_libraries(tlsuv PUBLIC llhttp::llhttp_shared)
    else ()
        target_link_libraries(tlsuv PUBLIC llhttp::llhttp)
    endif ()

endif (TLSUV_HTTP)

if (APPLE)
    target_link_libraries(tlsuv PRIVATE
            "-framework Security"
            "-framework CoreFoundation"
    )
endif (APPLE)

TARGET_COMPILE_DEFINITIONS(tlsuv PRIVATE TLSUV_VERSION=v${PROJECT_VERSION})
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    TARGET_COMPILE_DEFINITIONS(tlsuv PRIVATE _POSIX_C_SOURCE=200112 _GNU_SOURCE)
endif()

if (USE_MBEDTLS)
    find_package(MbedTLS REQUIRED)
    target_compile_definitions(tlsuv PRIVATE USE_MBEDTLS)
    target_include_directories(tlsuv PUBLIC $<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIRS}>)
    target_link_libraries(tlsuv PRIVATE ${MBEDTLS_LIBRARIES})
elseif(USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    target_compile_definitions(tlsuv PRIVATE USE_OPENSSL)
    target_link_libraries(tlsuv PRIVATE OpenSSL::SSL)
endif()

if (WIN32)
    target_compile_definitions(tlsuv
            PRIVATE WIN32_LEAN_AND_MEAN
            PRIVATE WINVER=0x0A00
            PRIVATE _WIN32_WINNT=0x0A00
            PRIVATE _CRT_SECURE_NO_WARNINGS
    )
    target_link_libraries(tlsuv PUBLIC crypt32 ncrypt)
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
