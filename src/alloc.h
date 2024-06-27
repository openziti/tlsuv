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

#ifndef TLSUV_ALLOC_H
#define TLSUV_ALLOC_H

#include <stdlib.h>

extern void *tlsuv__malloc(size_t size);
extern void *tlsuv__calloc(size_t n, size_t size);
extern void *tlsuv__realloc(void *addr, size_t size);
extern void tlsuv__free(void *addr);

extern char* tlsuv__strdup(const char *s);
extern char* tlsuv__strndup(const char *s, size_t len);


#endif //TLSUV_ALLOC_H
