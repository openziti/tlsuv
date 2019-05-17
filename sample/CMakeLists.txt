

if(WIN32)
  add_executable(sample sample.c cmd_line_parser.c ../win32/src/getopt.c ../win32/src/getopt_long.c)

  list(APPEND sample_defines WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0600)
  target_compile_definitions(sample PRIVATE ${sample_defines})
  target_include_directories(sample PRIVATE ../win32/include)
else()
add_executable(sample sample.c cmd_line_parser.c)
endif()

target_link_libraries(sample
        PUBLIC uv_mbed)