// Copyright (c) NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#ifndef UV_MBED_UM_DEBUG_H
#define UV_MBED_UM_DEBUG_H

#define TLSUV_NONE 0
#define TLSUV_ERR 1
#define TLSUV_WARN 2
#define TLSUV_INFO 3
#define TLSUV_DEBG 4
#define TLSUV_VERB 5
#define TLSUV_TRACE 6

#define LOG_LEVELS(XX) \
XX(TLSUV_NONE)           \
XX(TLSUV_ERR)            \
XX(TLSUV_WARN)           \
XX(TLSUV_INFO)           \
XX(TLSUV_DEBG)           \
XX(TLSUV_VERB)           \
XX(TLSUV_TRACE)

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __GNUC__
#define tlsuv_printf_args(a, b) __attribute__((__format__ (printf,a,b)))
#else
#define tlsuv_printf_args(a,b)
#endif

extern int um_log_level;
extern void um_log(int lvl, const char* file, unsigned int line, const char* fmt, ...)
    tlsuv_printf_args(4,5);

#ifdef __cplusplus
}
#endif

#define UM_LOG(lvl, fmt, ...) do {\
if ((TLSUV_##lvl) <= um_log_level) um_log(TLSUV_##lvl, __FILE__, __LINE__, fmt, ##__VA_ARGS__ ); \
}while(0)

#endif //UV_MBED_UM_DEBUG_H
