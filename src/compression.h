
#ifndef UV_MBED_COMPRESSION_H
#define UV_MBED_COMPRESSION_H

#if !defined(_SSIZE_T_) && !defined(_SSIZE_T_DEFINED)
typedef intptr_t ssize_t;
#ifndef SSIZE_MAX
# define SSIZE_MAX INTPTR_MAX
#endif
#ifndef _SSIZE_T_
# define _SSIZE_T_
#endif
#ifndef _SSIZE_T_DEFINED
# define _SSIZE_T_DEFINED
#endif
#endif

typedef struct um_http_inflater_s http_inflater_t;

#if __cplusplus
extern "C" {
#endif
typedef void (*data_cb)(void *ct, const char* data, ssize_t datalen);

extern const char *um_available_encoding();
extern http_inflater_t* um_get_inflater(const char *encoding, data_cb cb, void *ctx);
extern int um_inflate_state(http_inflater_t *inflater);
extern void um_free_inflater(http_inflater_t *inflater);

extern int um_inflate(http_inflater_t *inflater, const char* input, size_t input_len);


#if __cplusplus
}
#endif
#endif //UV_MBED_COMPRESSION_H
