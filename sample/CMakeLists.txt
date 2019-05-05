

add_executable(sample sample.c cmd_line_parser.c)

target_link_libraries(sample
        PUBLIC uv_mbed)