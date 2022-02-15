if (WIN32)
    include(FetchContent)
    FetchContent_Declare(zlib
            GIT_REPOSITORY https://github.com/madler/zlib.git
            GIT_TAG v1.2.11
            GIT_SHALLOW 1
            )

    FetchContent_MakeAvailable(zlib)

    message("zlibstatic
            PUBLIC ${zlib_SOURCE_DIR}
            PUBLIC ${zlib_BINARY_DIR}")

    target_include_directories(zlib
            PUBLIC ${zlib_SOURCE_DIR}
            ${zlib_BUILD_DIR})
    target_include_directories(zlibstatic
            PUBLIC ${zlib_SOURCE_DIR}
             ${zlib_BINARY_DIR})

endif()