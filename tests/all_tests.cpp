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

#include "catch.hpp"
#include "um_debug.h"
#include <tlsuv/tlsuv.h>


static uv_timeval64_t start;
static const char *err_labels[] = {
#define ERR_LABEL(e) #e,

        LOG_LEVELS(ERR_LABEL)
};

static void test_log_f(int lvl, const char *file, unsigned int line, const char* msg){
    uv_timeval64_t now;
    uv_gettimeofday(&now);
    long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;

    fprintf(stderr, "[%6ld.%03ld]%5s %s:%d %s\n", elapsed/1000, elapsed % 1000,
            err_labels[lvl], file, line, msg);
}

tlsuv_log_func test_log = test_log_f;

#define xstr(s) str(s)
#define str(s) #s

int main( int argc, char* argv[] ) {
#if defined(HSM_CONFIG)
    uv_os_setenv("SOFTHSM2_CONF", xstr(HSM_CONFIG));
#endif
    uv_gettimeofday(&start);
    long level = TLSUV_DEBG;
    const char* debug = getenv("TLSUV_TEST_LOG");
    if (debug) {
        // enable logging during tests
        level = strtol(debug, nullptr, 10);
    }

    tlsuv_set_debug((int) level, test_log);
    int result = Catch::Session().run( argc, argv );

    return result;
}