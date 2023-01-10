#ifndef TEST_SRC_TEST_COMMON_H_
#define TEST_SRC_TEST_COMMON_H_

#include "uv.h"
#include "uv_link_t.h"

#ifdef _WIN32
# include <winsock2.h>
# include <io.h>
#else
# include <sys/socket.h>
# include <unistd.h>
#endif  /* _WIN32 */

#include "test-list.h"
#include "mini/test.h"

#endif  /* TEST_SRC_TEST_COMMON_H_ */
