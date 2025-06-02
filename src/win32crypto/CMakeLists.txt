# win32 native crypto engine


add_library(win32crypto-impl OBJECT
        wc_context.c
        cert.c
)

target_compile_definitions(win32crypto-impl PRIVATE
        SECURITY_WIN32
)

target_include_directories(win32crypto-impl
        PRIVATE ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(win32crypto-impl
        PRIVATE ncrypt
        PRIVATE crypt32
        PRIVATE security
)
