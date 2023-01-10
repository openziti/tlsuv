#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

#include <stdio.h>
#include <stdlib.h>

#include "include/uv_link_t.h"

#define container_of(ptr, type, member) \
  ((type *) ((char *) (ptr) - offsetof(type, member)))

#define CHECK(VALUE, MESSAGE)                                                \
    do {                                                                     \
      if ((VALUE)) break;                                                    \
      fprintf(stderr, "Assertion failure: " #MESSAGE "\n");                  \
      abort();                                                               \
    } while (0)

#define CHECK_EQ(A, B, MESSAGE) CHECK((A) == (B), MESSAGE)
#define CHECK_NE(A, B, MESSAGE) CHECK((A) != (B), MESSAGE)

#endif  /* SRC_COMMON_H_ */
