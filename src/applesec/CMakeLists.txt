# Apple Security.framework / SecureTransport backend.
#
# NOTE: src/apple/keychain.c is deliberately NOT listed here. It is the
# platform keychain provider and is compiled directly into the `tlsuv`
# target on APPLE for every TLS backend (see the top level CMakeLists.txt).
# Listing it here -- or using file(GLOB) -- would compile it twice and
# produce a duplicate `platform_keychain` at link time.
add_library(applesec-impl OBJECT
        context.c
        context.h
        engine.c
)

target_include_directories(applesec-impl
        PRIVATE ${PROJECT_SOURCE_DIR}/include
        PRIVATE ${PROJECT_SOURCE_DIR}/src
)

# SecureTransport (SSLContextRef) and SecKeychain are formally deprecated,
# but SecureTransport is the only Apple API that lets the caller drive the
# TLS state machine over its own IO, which is what tlsuv_engine_t requires.
target_compile_options(applesec-impl PRIVATE -Wno-deprecated-declarations)

target_link_libraries(applesec-impl PUBLIC
        "-framework Security"
        "-framework CoreFoundation"
)

# context.c reads CA/key/cert files through uv_fs_*, and src/util.h pulls in uv.h
target_link_libraries(applesec-impl PRIVATE ${TLSUV_LIBUV_LIB})
