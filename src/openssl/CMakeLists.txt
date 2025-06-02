find_package(OpenSSL REQUIRED)

add_library(openssl-impl OBJECT
        engine.c
        keys.c
        keys.h
)
target_include_directories(openssl-impl
        PRIVATE ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(openssl-impl PRIVATE OpenSSL::SSL)


