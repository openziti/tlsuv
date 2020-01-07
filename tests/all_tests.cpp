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
#include "catch.hpp"

int main( int argc, char* argv[] ) {

    // enable full logging during tests
    uv_mbed_set_debug(5, stdout);
    int result = Catch::Session().run( argc, argv );

    return result;
}