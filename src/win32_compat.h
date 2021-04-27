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


#ifndef UV_MBED_WIN32_COMPAT_H
#define UV_MBED_WIN32_COMPAT_H

#if _WIN32

#define strcasecmp _stricmp
#define strncasecmp _strnicmp

#if !defined (strndup_DEFINED)
#define strndup_DEFINED
static char* strndup(const char* p, size_t len) {
    char *s = malloc(len + 1);
    strncpy(s, p, len);
    s[len] = '\0';
    return s;
}
#endif // strndup_DEFINED
#endif
#endif //UV_MBED_WIN32_COMPAT_H
