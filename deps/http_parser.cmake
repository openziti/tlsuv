include(FetchContent)
FetchContent_Declare(http_parser
        GIT_REPOSITORY https://github.com/netfoundry/http-parser.git
        GIT_TAG master
        GIT_SHALLOW 1
)

FetchContent_GetProperties(http_parser)
if (NOT http_parser_POPULATED)
    FetchContent_Populate(http_parser)
endif()

add_library(http-parser OBJECT
        ${http_parser_SOURCE_DIR}/http_parser.c
        )

target_include_directories(http-parser
        PUBLIC ${http_parser_SOURCE_DIR}
        )
