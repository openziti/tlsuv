add_executable(sample sample.c common.c)
target_link_libraries(sample PUBLIC tlsuv)

add_executable(engine_test engine_test.c)
target_link_libraries(engine_test PUBLIC tlsuv)

add_executable(sample-cf sample-cf.c)
target_link_libraries(sample-cf PUBLIC tlsuv)

add_executable(um-curl um-curl.c common.c)
target_link_libraries(um-curl PUBLIC tlsuv)

add_executable(repeat-fetch repeat-fetch.c common.c)
target_link_libraries(repeat-fetch PUBLIC tlsuv)

add_executable(ws-client ws-client.c)
target_link_libraries(ws-client PUBLIC tlsuv)

add_executable(http-ping http-ping.c)
target_link_libraries(http-ping PUBLIC tlsuv)