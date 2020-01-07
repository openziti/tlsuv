add_executable(sample sample.c)

target_link_libraries(sample PUBLIC uv_mbed)
target_include_directories(sample PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_executable(engine_test engine_test.c)
target_link_libraries(engine_test PUBLIC uv_mbed)
target_include_directories(engine_test PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_executable(sample-cf sample-cf.c)
target_link_libraries(sample-cf PUBLIC uv_mbed)
target_include_directories(sample-cf PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_executable(um-curl um-curl.c common.c)
target_link_libraries(um-curl PUBLIC uv_mbed)

add_executable(repeat-fetch repeat-fetch.c common.c)
target_link_libraries(repeat-fetch PUBLIC uv_mbed)