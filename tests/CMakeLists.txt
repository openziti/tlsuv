
set(test_srcs
        http_tests.cpp
        )

ENABLE_LANGUAGE(CXX)

add_executable(all_tests
        all_tests.cpp ${test_srcs})
set_property(TARGET all_tests PROPERTY CXX_STANDARD 11)
target_link_libraries(all_tests
        uv_mbed)

include(CTest)
add_test(http_tests all_tests http_tests)
