if (WIN32)
    find_package(unofficial-getopt-win32 REQUIRED)
endif()

add_executable(sample sample.c common.c)
target_link_libraries(sample PUBLIC tlsuv::tlsuv)

add_executable(engine_test engine_test.c common.c)
target_link_libraries(engine_test PUBLIC tlsuv::tlsuv)

add_executable(sample-cf sample-cf.c common.c)
target_link_libraries(sample-cf PUBLIC tlsuv::tlsuv)

add_executable(um-curl um-curl.c common.c)
if (WIN32)
target_link_libraries(um-curl PRIVATE unofficial::getopt-win32::getopt)
endif()
target_link_libraries(um-curl PUBLIC tlsuv::tlsuv)

add_executable(repeat-fetch repeat-fetch.c common.c)
target_link_libraries(repeat-fetch PUBLIC tlsuv::tlsuv)

add_executable(ws-client ws-client.c common.c)
target_link_libraries(ws-client PUBLIC tlsuv::tlsuv)

add_executable(http-ping http-ping.c common.c)
target_link_libraries(http-ping PUBLIC tlsuv::tlsuv)