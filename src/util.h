//
// Created by Eugene Kobyakov on 11/3/23.
//

#ifndef TLSUV_UTIL_H
#define TLSUV_UTIL_H

#include <assert.h>

/**
 * wrap-around buffer
 */
#define WRAPAROUND_BUFFER(name, size) struct name { \
    char *putp;                          \
    char *getp;                          \
    char buf[size];\
}

#define wab_check_bounds(b, p) assert((p) >= (b).buf && (p) <= (b).buf + sizeof((b).buf))

#define WAB_INIT(b) do { (b).getp = (b).putp = (b).buf; } while(0)

/**
 * get space for putting bytes into the buffer
 */
#define WAB_PUT_SPACE(b,p,l) do{ \
if ((b).putp == (b).buf + sizeof((b).buf) && (b).getp != (b).buf) (b).putp = (b).buf; \
p = (b).putp;                                 \
if ((b).putp >= (b).getp) l = (b).buf + sizeof((b).buf) - (b).putp; \
else l = (b).getp - (b).putp - 1; \
} while(0)

/**
 * update buffer's put pointer
 */
#define WAB_UPDATE_PUT(b,l) do { \
wab_check_bounds((b), (b).putp + l);                              \
(b).putp += l;                     \
if ((b).putp - (b).buf == sizeof((b).buf) && (b).getp != (b).buf) (b).putp = (b).buf; \
} while(0)

/**
 * get pointer and available bytes for reading from buffer
 */
#define WAB_GET_SPACE(b,p,l) do { \
p = (b).getp;                       \
if ((b).getp <= (b).putp) l = (b).putp - (b).getp; \
else l = (b).buf + sizeof((b).buf) - (b).getp; \
} while(0)


/**
 * update read pointer
 */
#define WAB_UPDATE_GET(b, l) do { \
wab_check_bounds((b), (b).getp + l);                              \
(b).getp += l;                   \
if ((b).getp == (b).putp) (b).getp = (b).putp = (b).buf; \
if ((b).getp == (b).buf + sizeof((b).buf)) (b).getp = (b).buf; \
} while(0)

#endif //TLSUV_UTIL_H
