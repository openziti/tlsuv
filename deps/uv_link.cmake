message("current dir = ${CMAKE_CURRENT_SOURCE_DIR}")
set(uvl_src ${CMAKE_CURRENT_SOURCE_DIR}/uv_link_t)
add_library(uv_link OBJECT
        ${uvl_src}/src/uv_link_t.c
        ${uvl_src}/src/uv_link_source_t.c
        ${uvl_src}/src/uv_link_observer_t.c
        ${uvl_src}/src/defaults.c)

target_include_directories(uv_link
        PUBLIC ${uvl_src}/include
        PRIVATE ${uvl_src}
)

if(NOT HAVE_LIBUV)
    target_include_directories(uv_link PRIVATE ${libuv_SOURCE_DIR}/include)
endif()
