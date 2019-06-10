add_executable(sample sample.c)

target_link_libraries(sample PUBLIC uv_mbed)
target_include_directories(sample PUBLIC ${CMAKE_SOURCE_DIR}/include)