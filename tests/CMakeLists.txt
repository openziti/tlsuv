ENABLE_LANGUAGE(CXX)

set(test_srcs
        http_tests.cpp
        ws_tests.cpp
        engine_tests.cpp
        uv_mbed_tests.cpp compression_tests.cpp)


add_executable(all_tests
        all_tests.cpp ${test_srcs})
set_property(TARGET all_tests PROPERTY CXX_STANDARD 11)
target_link_libraries(all_tests
        uv_mbed
        )

target_include_directories(all_tests PRIVATE ../src)

add_custom_target(run-tests
        BYPRODUCTS ${PROJECT_BINARY_DIR}/Testing/results.xml
        DEPENDS all_tests
        COMMAND $<TARGET_FILE:all_tests> -r xml -o ${PROJECT_BINARY_DIR}/Testing/results.xml)
#find_program(MEMORYCHECK_COMMAND valgrindor)
#set( MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full" )

include(CTest)
add_test(engine_tests all_tests [engine])
add_test(http_tests all_tests [http])
add_test(ws_tests all_tests [websocket])
add_test(uv_mbed all_tests [uv-mbed])
