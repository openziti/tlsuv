
if(USE_MBEDTLS)
    include(mbedtls.cmake)
endif()

include(http_parser.cmake)

include(uv_link.cmake)