
set(test_srcs
        http_tests.cpp
        )

ENABLE_LANGUAGE(CXX)

add_executable(all_tests
        all_tests.cpp ${test_srcs})

target_link_libraries(all_tests
        uv_mbed)

include(CTest)
add_test(http_tests all_tests http_tests)
