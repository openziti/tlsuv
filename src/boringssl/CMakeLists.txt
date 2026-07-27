add_library(boringssl-impl OBJECT
        engine.c
        keys.c
        keys.h
)
target_include_directories(boringssl-impl
        PRIVATE ${PROJECT_SOURCE_DIR}/include)

if (NOT TARGET OpenSSL::SSL)
    find_package(OpenSSL)
endif ()

if (TARGET OpenSSL::SSL)
    target_link_libraries(boringssl-impl PRIVATE OpenSSL::SSL)
endif ()

# BoringSSL's libssl is implemented in C++ (libcrypto stays C), so anything
# that statically links it in - including this C-only project - needs the
# C++ runtime on the final link line.
if (APPLE)
    target_link_libraries(boringssl-impl PUBLIC "c++")
elseif (UNIX)
    target_link_libraries(boringssl-impl PUBLIC "stdc++")
endif ()
