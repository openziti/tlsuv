ENABLE_LANGUAGE(CXX)

find_package(Catch2 CONFIG REQUIRED)
message("catch2 is ${Catch2_CONFIG}")

find_package(parson CONFIG REQUIRED)

FILE(COPY ${CMAKE_CURRENT_SOURCE_DIR}/testdata DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/ )
CONFIGURE_FILE(softhsm2.conf.in ${CMAKE_CURRENT_BINARY_DIR}/softhsm2.conf)

if (USE_OPENSSL)
    find_library(softhsm_lib softhsm2 PATH_SUFFIXES softhsm)
    if (softhsm_lib)
        set(PKCS11_OPTS -DHSM_LIB=${softhsm_lib} -DHSM_CONFIG=${CMAKE_CURRENT_BINARY_DIR}/softhsm2.conf)
        message("PKCS11 key test is ON")
        message("hsm lib = ${softhsm_lib}")
    else ()
        message("PKCS11 key test is OFF")
    endif ()


    find_program(softhsm_tool softhsm2-util)
    find_program(pk11 pkcs11-tool)
    if (softhsm_lib AND softhsm_tool AND pk11)
        add_custom_target(generate-test-hsm-data
                COMMAND rm -r ${CMAKE_CURRENT_SOURCE_DIR}/testdata/softhsm/*
                COMMAND SOFTHSM2_CONF=${CMAKE_CURRENT_BINARY_DIR}/softhsm2.conf ${softhsm_tool} --init-token --slot 0 --label "test token" --so-pin 1111 --pin 2222
                COMMAND SOFTHSM2_CONF=${CMAKE_CURRENT_BINARY_DIR}/softhsm2.conf ${pk11} --module ${softhsm_lib} -I
                COMMAND SOFTHSM2_CONF=${CMAKE_CURRENT_BINARY_DIR}/softhsm2.conf ${pk11} --module ${softhsm_lib} --keypairgen --key-type rsa:2048 --id 1 --label test-rsa --pin 2222
                COMMAND SOFTHSM2_CONF=${CMAKE_CURRENT_BINARY_DIR}/softhsm2.conf ${pk11} --module ${softhsm_lib} --keypairgen --key-type EC:prime256v1 --id 2 --label test-ec --pin 2222
                COMMAND openssl req -new -x509 -subj '/CN=test-rsa/' -sha256 -engine pkcs11 -keyform engine -key 'pkcs11:id=%01;type=private;pin-value=2222'
                        -out ${CMAKE_CURRENT_BINARY_DIR}/test-rsa.der -config p11.conf -outform DER
                COMMAND openssl req -new -x509 -subj '/CN=test-ec/' -sha256 -engine pkcs11 -keyform engine -key 'pkcs11:id=%02;type=private;pin-value=2222'
                        -out ${CMAKE_CURRENT_BINARY_DIR}/test-ec.der -config p11.conf -outform DER
                COMMAND SOFTHSM2_CONF=${CMAKE_CURRENT_BINARY_DIR}/softhsm2.conf ${pk11} --module ${softhsm_lib} --write-object ${CMAKE_CURRENT_BINARY_DIR}/test-rsa.der --type cert --id 1
                COMMAND SOFTHSM2_CONF=${CMAKE_CURRENT_BINARY_DIR}/softhsm2.conf ${pk11} --module ${softhsm_lib} --write-object ${CMAKE_CURRENT_BINARY_DIR}/test-ec.der --type cert --id 2
                )
    endif()
endif()

set(test_srcs
        http_tests.cpp
        ws_tests.cpp
        engine_tests.cpp
        stream_tests.cpp
        compression_tests.cpp
        key_tests.cpp
        connector_tests.cpp
)


add_executable(all_tests
        all_tests.cpp ${test_srcs})
set_property(TARGET all_tests PROPERTY CXX_STANDARD 20)
target_include_directories(all_tests PRIVATE ../src)
target_compile_options(all_tests PRIVATE ${PKCS11_OPTS})
target_compile_definitions(all_tests PRIVATE TEST_DATA_DIR=${CMAKE_CURRENT_BINARY_DIR}/testdata)

if (WIN32)
    # set NOMINMAX to avoid Catch2 compile errors
    target_compile_definitions(all_tests PRIVATE NOMINMAX)
endif ()

target_compile_definitions(all_tests PRIVATE
        TEST_${TLSUV_TLSLIB}
        TEST_SERVER_CA=${CMAKE_CURRENT_SOURCE_DIR}/certs/ca.pem
        )
if (softhsm_lib)
    target_compile_definitions(all_tests PRIVATE
            HSM_LIB=${softhsm_lib}
            HSM_CONFIG=${CMAKE_CURRENT_BINARY_DIR}/softhsm2.conf
            )
endif (softhsm_lib)

target_link_libraries(all_tests
        tlsuv
        Catch2::Catch2
        parson::parson
        )

target_include_directories(all_tests PRIVATE ../src)

add_custom_target(test-server
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test_server
        COMMAND go run ./test-server.go -ca ../certs/ca.pem -ca-key ../certs/ca.key

)

add_custom_target(run-tests
        BYPRODUCTS ${PROJECT_BINARY_DIR}/Testing/results.xml
        DEPENDS all_tests
        COMMAND $<TARGET_FILE:all_tests> -r xml -o ${PROJECT_BINARY_DIR}/Testing/results.xml)

include(CTest)
add_test(key_tests all_tests [key])
add_test(engine_tests all_tests [engine])
add_test(http_tests all_tests [http])
add_test(ws_tests all_tests [websocket])
add_test(uv_mbed all_tests [stream])
