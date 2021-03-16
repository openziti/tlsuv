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


#ifndef UV_MBED_UM_DEBUG_H
#define UV_MBED_UM_DEBUG_H

#define NONE 0
#define ERR 1
#define WARN 2
#define INFO 3
#define DEBG 4
#define VERB 5
#define TRACE 6

#define LOG_LEVELS(XX) \
XX(NONE)           \
XX(ERR)            \
XX(WARN)           \
XX(INFO)           \
XX(DEBG)           \
XX(VERB)           \
XX(TRACE)

#ifdef __cplusplus
extern "C" {
#endif

extern int um_log_level;
extern void um_log(int lvl, const char* file, unsigned int line, const char* fmt, ...);

#ifdef __cplusplus
}
#endif

#define UM_LOG(lvl, fmt, ...) do {\
if ((lvl) <= um_log_level) um_log(lvl, __FILE__, __LINE__, fmt, ##__VA_ARGS__ ); \
}while(0)

#endif //UV_MBED_UM_DEBUG_H
