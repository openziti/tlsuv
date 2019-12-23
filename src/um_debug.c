/*
Copyright 2019 NetFoundry, Inc.

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


#include "um_debug.h"
#include <stdio.h>
#include <stdarg.h>

int um_log_level = ERR;
static FILE *um_log_out = NULL;

void um_log(const char* fmt,  ...) {
    va_list argp;
    va_start(argp, fmt);
    FILE* out = um_log_out != NULL ? um_log_out : stdout;
    vfprintf(out, fmt, argp);
}

void uv_mbed_set_debug(int level, FILE *out) {
    um_log_level = level;
    um_log_out = out;
}