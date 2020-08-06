
if(USE_MBEDTLS)
include(mbedtls.cmake)
endif()

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
add_subdirectory(libuv)
set_target_properties(uv_a PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libuv/include)
set_target_properties(uv PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libuv/include)

add_library(http-parser STATIC http-parser/http_parser.c)
target_include_directories(http-parser PUBLIC http-parser)

add_library(uv_link STATIC
        uv_link_t/src/uv_link_t.c
        uv_link_t/src/uv_link_source_t.c
        uv_link_t/src/uv_link_observer_t.c
        uv_link_t/src/defaults.c)

target_include_directories(uv_link
        PUBLIC uv_link_t/include
        PRIVATE uv_link_t)

target_link_libraries(uv_link PUBLIC uv_a)