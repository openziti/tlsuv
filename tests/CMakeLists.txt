ENABLE_LANGUAGE(CXX)

set(test_srcs
        http_tests.cpp
        ws_tests.cpp
        engine_tests.cpp
        )


add_executable(all_tests
        all_tests.cpp ${test_srcs})
set_property(TARGET all_tests PROPERTY CXX_STANDARD 11)
target_link_libraries(all_tests
        uv_mbed)

target_include_directories(all_tests PRIVATE ../src)

include(CTest)
add_test(engine_tests all_tests [engine])
add_test(http_tests all_tests [http])
add_test(ws_tests all_tests [websocket])
