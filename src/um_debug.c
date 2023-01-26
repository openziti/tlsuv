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


#include <stdio.h>
#include <stdarg.h>

#include "um_debug.h"
#include <tlsuv/tlsuv.h>

int um_log_level = ERR;
static tlsuv_log_func log_func = NULL;

void um_log(int lvl, const char* file, unsigned int line, const char *fmt,  ...) {
    static char logbuf[1024];
    if (log_func) {
        va_list argp;
        va_start(argp, fmt);
        vsnprintf(logbuf, sizeof(logbuf), fmt, argp);
        log_func(lvl, file, line, logbuf);
    }
}

void tlsuv_set_debug(int level, tlsuv_log_func output_f) {
    um_log_level = level;
    log_func = output_f;
}