include(FetchContent)
FetchContent_Declare(libuv
        GIT_REPOSITORY https://github.com/libuv/libuv.git
        GIT_TAG v1.44.1
        GIT_SHALLOW 1
)

FetchContent_MakeAvailable(libuv)
