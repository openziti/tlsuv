include(FetchContent)

if (NOT DEFINED LIBUV_VERSION)
    set(LIBUV_VERSION v1.44.2)
endif()

message("using libuv@${LIBUV_VERSION}")

FetchContent_Declare(libuv
        GIT_REPOSITORY https://github.com/libuv/libuv.git
        GIT_TAG ${LIBUV_VERSION}
        GIT_SHALLOW 1
)

FetchContent_MakeAvailable(libuv)
