find_package(OpenSSL REQUIRED)

add_library(openssl-impl OBJECT
        engine.c
        keys.c
        keys.h
)
target_include_directories(openssl-impl
        PRIVATE ${PROJECT_SOURCE_DIR}/include)
if (WIN32)
target_compile_definitions(openssl-impl
        PRIVATE WINVER=0x0A00
        PRIVATE _WIN32_WINNT=0x0A00
        PRIVATE _CRT_SECURE_NO_WARNINGS
        PRIVATE _CRT_NONSTDC_NO_DEPRECATE
        PRIVATE _WINSOCK_DEPRECATED_NO_WARNINGS
        PRIVATE WIN32_LEAN_AND_MEAN
)
if (MSVC)
    target_compile_options(openssl-impl
            PRIVATE /wd4100 # disable "unreferenced formal parameter" warning
    )
endif (MSVC)

endif ()

target_link_libraries(openssl-impl PRIVATE OpenSSL::SSL)


