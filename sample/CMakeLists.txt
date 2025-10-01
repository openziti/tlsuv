if (MSVC)
    find_package(unofficial-getopt-win32 REQUIRED)
endif()

message(NOTICE "TLSUV_HTTP = ${TLSUV_HTTP}")

add_library(common OBJECT common.c)
target_compile_definitions(common PUBLIC $<$<BOOL:${TLSUV_HTTP}>:TLSUV_HTTP>)
target_link_libraries(common PUBLIC tlsuv)
if (MSVC)
    target_link_libraries(common PRIVATE unofficial::getopt-win32::getopt)
endif()

set(samples
        sample
        engine_test
        sample-cf
)
if (TLSUV_HTTP)
    list(APPEND samples
            um-curl
            repeat-fetch
            ws-client
            http-ping
    )
endif()

foreach (s ${samples})
    add_executable(${s} ${s}.c)
    target_link_libraries(${s} PUBLIC tlsuv common)
endforeach()
