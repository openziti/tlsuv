
if(USE_MBEDTLS)
    include(mbedtls.cmake)
endif()

if (NOT HAVE_LIBUV)
    include(libuv.cmake)
endif()

include(http_parser.cmake)

include(uv_link.cmake)