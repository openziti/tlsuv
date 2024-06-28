if (WIN32)
    find_package(unofficial-getopt-win32 REQUIRED)
endif()

add_library(common OBJECT common.c)
target_link_libraries(common PUBLIC tlsuv)
target_compile_definitions(common PUBLIC $<$<BOOL:${TLSUV_HTTP}>:TLSUV_HTTP>)

message(NOTICE "TLSUV_HTTP = ${TLSUV_HTTP}")

add_executable(sample sample.c)
target_link_libraries(sample PUBLIC tlsuv common)

add_executable(engine_test engine_test.c)
target_link_libraries(engine_test PUBLIC tlsuv common)

add_executable(sample-cf sample-cf.c)
target_link_libraries(sample-cf PUBLIC tlsuv common)

if (TLSUV_HTTP)
    add_executable(um-curl um-curl.c)
    if (WIN32)
        target_link_libraries(um-curl PRIVATE unofficial::getopt-win32::getopt)
    endif()
    target_link_libraries(um-curl PUBLIC tlsuv common)

    add_executable(repeat-fetch repeat-fetch.c)
    target_link_libraries(repeat-fetch PUBLIC tlsuv common)

    add_executable(ws-client ws-client.c)
    target_link_libraries(ws-client PUBLIC tlsuv common)

    add_executable(http-ping http-ping.c)
    target_link_libraries(http-ping PUBLIC tlsuv common)
endif (TLSUV_HTTP)