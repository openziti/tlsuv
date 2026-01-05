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
include(FindPkgConfig)
find_package(PkgConfig)

if(tlsuv_DEVELOPER_MODE)
    message(NOTICE "adding developer options")
    set(complist GNU Clang AppleClang)
    if (CMAKE_C_COMPILER_ID IN_LIST complist)
        option(TLSUV_ASAN "turn on sanitizer options")
        option(TLSUV_TEST_COVERAGE "generate test coverage")
    endif ()
    unset(complist)
endif ()
option(TLSUV_HTTP "enable HTTP/websocket support" ON)

if(WIN32)
    set(default_crypto "win32crypto")
else ()
    set(default_crypto "openssl")
endif ()

set(supported_tls_libs openssl mbedtls win32crypto)
set(TLSUV_TLSLIB ${default_crypto} CACHE STRING "TLS implementation library ${supported_tls_libs}")

if(NOT TLSUV_TLSLIB IN_LIST supported_tls_libs)
    message(FATAL_ERROR "`${TLSUV_TLSLIB}' TLS library is not supported")
endif()

if (TLSUV_TEST_COVERAGE)
    add_compile_options(--coverage)
    add_link_options(--coverage)
endif ()

if (TLSUV_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif ()

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
        src/url.c
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
            src/websocket.c
            src/http_req.c
            src/tls_link.c
            src/compression.c
            src/compression.h
    )
endif (TLSUV_HTTP)

add_subdirectory(src/${TLSUV_TLSLIB})

find_package(libuv CONFIG QUIET)
if (libuv_FOUND)
    # newer libuv versions (via VCPKG) have proper namespacing
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
    pkg_check_modules(libuv REQUIRED IMPORTED_TARGET libuv)
    set(TLSUV_LIBUV_LIB PkgConfig::libuv)
endif()

add_library(tlsuv STATIC
        ${tlsuv_sources}
        )

set_target_properties(tlsuv PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_STANDARD 11)

target_include_directories(tlsuv
        PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        )

target_compile_definitions(tlsuv PRIVATE
        TLSUV_VERSION=v${PROJECT_VERSION}
        USE_$<UPPER_CASE:${TLSUV_TLSLIB}>
        TLS_IMPL=${TLSUV_TLSLIB}
)
if(WIN32)
    target_compile_definitions(tlsuv
            PRIVATE _WIN32_WINNT=0x0A00
            PRIVATE WINVER=0x0A00
            PRIVATE WIN32_LEAN_AND_MEAN
            PRIVATE _CRT_SECURE_NO_WARNINGS
            PRIVATE _CRT_NONSTDC_NO_DEPRECATE
            PRIVATE _WINSOCK_DEPRECATED_NO_WARNINGS
    )
    if (MSVC)
        target_compile_options(tlsuv
                PRIVATE /wd4100 # disable "unreferenced formal parameter" warning
        )
    endif (MSVC)

    target_link_libraries(tlsuv PUBLIC crypt32 ncrypt)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(tlsuv PRIVATE _POSIX_C_SOURCE=200112 _GNU_SOURCE)
endif()

target_link_libraries(tlsuv
        PUBLIC ${TLSUV_LIBUV_LIB}
        PRIVATE ${TLSUV_TLSLIB}-impl
)

if (APPLE)
    target_link_libraries(tlsuv PRIVATE
            "-framework Security"
            "-framework CoreFoundation"
    )
endif (APPLE)

if (TLSUV_HTTP)
    target_compile_definitions(tlsuv PUBLIC TLSUV_HTTP)

    add_subdirectory(deps)
    target_link_libraries(tlsuv PUBLIC uv_link)

    find_package(ZLIB 1 REQUIRED)
    target_link_libraries(tlsuv PRIVATE ZLIB::ZLIB)

    find_package(llhttp CONFIG REQUIRED)
    message(NOTICE "llhttp = ${llhttp_CONFIG}")
    if (TARGET llhttp::llhttp_static)
        target_link_libraries(tlsuv PUBLIC llhttp::llhttp_static)
    elseif (TARGET llhttp::llhttp_shared)
        target_link_libraries(tlsuv PUBLIC llhttp::llhttp_shared)
    else ()
        target_link_libraries(tlsuv PUBLIC llhttp::llhttp)
    endif ()

endif (TLSUV_HTTP)

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
