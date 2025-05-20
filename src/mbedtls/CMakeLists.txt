find_package(MbedTLS REQUIRED)

add_library(mbedtls-impl OBJECT
        engine.c
        keys.c
        keys.h
)

target_include_directories(mbedtls-impl
        PRIVATE ${PROJECT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
        PRIVATE $<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIRS}>
)
target_link_libraries(mbedtls-impl PRIVATE ${MBEDTLS_LIBRARIES})
