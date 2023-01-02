include(FetchContent)
FetchContent_Declare(uv_link
        GIT_REPOSITORY https://github.com/netfoundry/uv_link_t.git
        GIT_TAG v1.0.5+openziti.1
        GIT_SHALLOW 1
)

FetchContent_GetProperties(uv_link)
if (NOT uv_link_POPULATED)
    FetchContent_Populate(uv_link)
endif()

message("uvlink src = ${uv_link_SOURCE_DIR}")
set(uvl_src ${uv_link_SOURCE_DIR})
add_library(uv_link OBJECT
        ${uv_link_SOURCE_DIR}/src/uv_link_t.c
        ${uv_link_SOURCE_DIR}/src/uv_link_source_t.c
        ${uv_link_SOURCE_DIR}/src/uv_link_observer_t.c
        ${uv_link_SOURCE_DIR}/src/defaults.c)

target_include_directories(uv_link
        PUBLIC ${uv_link_SOURCE_DIR}/include
        PRIVATE ${uv_link_SOURCE_DIR}
)
if(NOT HAVE_LIBUV)
    target_include_directories(uv_link PRIVATE ${libuv_SOURCE_DIR}/include)
endif()
