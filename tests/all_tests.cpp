/*
Copyright 2019-2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define CATCH_CONFIG_RUNNER

#include <uv_mbed/uv_mbed.h>
#include "um_debug.h"
#include "catch.hpp"



static const char *err_labels[] = {
#define ERR_LABEL(e) #e,

        LOG_LEVELS(ERR_LABEL)
};

static void test_log_f(int lvl, const char *file, unsigned int line, const char* msg){
    printf("[%5s] %s:%d %s\n", err_labels[lvl], file, line, msg);
}

um_log_func test_log = test_log_f;

int main( int argc, char* argv[] ) {

    const char* debug = getenv("UM_TEST_DEBUG");
    if (debug) {
        // enable logging during tests
        long level = strtol(debug, nullptr, 10);
        uv_mbed_set_debug((int)level, test_log);

    }
    int result = Catch::Session().run( argc, argv );

    return result;
}