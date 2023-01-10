#ifndef INCLUDE_UV_LINK_H_
#define INCLUDE_UV_LINK_H_

#include "uv.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

typedef struct uv_link_s uv_link_t;
typedef struct uv_link_methods_s uv_link_methods_t;
typedef struct uv_link_source_s uv_link_source_t;
typedef struct uv_link_observer_s uv_link_observer_t;

typedef void (*uv_link_alloc_cb)(uv_link_t* link,
                                 size_t suggested_size,
                                 uv_buf_t* buf);
typedef void (*uv_link_read_cb)(uv_link_t* link,
                                ssize_t nread,
                                const uv_buf_t* buf);
typedef void (*uv_link_write_cb)(uv_link_t* source, int status, void* arg);
typedef void (*uv_link_shutdown_cb)(uv_link_t* source, int status, void* arg);
typedef void (*uv_link_close_cb)(uv_link_t* source);

struct uv_link_methods_s {
  int (*read_start)(uv_link_t* link);
  int (*read_stop)(uv_link_t* link);

  int (*write)(uv_link_t* link,
               uv_link_t* source,
               const uv_buf_t bufs[],
               unsigned int nbufs,
               uv_stream_t* send_handle,
               uv_link_write_cb cb,
               void* arg);
  int (*try_write)(uv_link_t* link,
                   const uv_buf_t bufs[],
                   unsigned int nbufs);

  int (*shutdown)(uv_link_t* link,
                  uv_link_t* source,
                  uv_link_shutdown_cb cb,
                  void* arg);

  void (*close)(uv_link_t* link, uv_link_t* source, uv_link_close_cb cb);

  const char* (*strerror)(uv_link_t* link, int err);

  /* Overriding callbacks */
  uv_link_alloc_cb alloc_cb_override;
  uv_link_read_cb read_cb_override;
};

#define UV_LINK_FIELDS                                                        \
    uv_link_t* parent;                                                        \
    uv_link_t* child;                                                         \
                                                                              \
    uv_link_alloc_cb alloc_cb;                                                \
    uv_link_read_cb read_cb;                                                  \
                                                                              \
    void* data;                                                               \
                                                                              \
    /* Read-only after assigning initial values */                            \
                                                                              \
    /* Sort of virtual table */                                               \
    uv_link_methods_t const* methods;                                         \
                                                                              \
    /* Private, used for chain/unchain */                                     \
    uv_link_alloc_cb saved_alloc_cb;                                          \
    uv_link_read_cb saved_read_cb;                                            \
                                                                              \
    /* Private, used for error reporting */                                   \
    unsigned int err_prefix;                                                  \
                                                                              \
    /* Private, used for close */                                             \
    int close_depth;                                                          \
    int close_waiting;                                                        \
    uv_link_close_cb saved_close_cb;                                          \
    uv_link_t* pending_close_source;

struct uv_link_s {
  UV_LINK_FIELDS
};

UV_EXTERN int uv_link_init(uv_link_t* link, uv_link_methods_t const* methods);
UV_EXTERN void uv_link_close(uv_link_t* link, uv_link_close_cb cb);

UV_EXTERN int uv_link_chain(uv_link_t* from, uv_link_t* to);
UV_EXTERN int uv_link_unchain(uv_link_t* from, uv_link_t* to);

/* Use this to invoke parent link's methods */
UV_EXTERN void uv_link_propagate_alloc_cb(uv_link_t* link,
                                          size_t suggested_size,
                                          uv_buf_t* buf);
UV_EXTERN void uv_link_propagate_read_cb(uv_link_t* link,
                                         ssize_t nread,
                                         const uv_buf_t* buf);

int uv_link_propagate_write(uv_link_t* link, uv_link_t* source,
                            const uv_buf_t bufs[], unsigned int nbufs,
                            uv_stream_t* send_handle,
                            uv_link_write_cb cb, void* arg);

int uv_link_propagate_shutdown(uv_link_t* link,
                               uv_link_t* source,
                               uv_link_shutdown_cb cb,
                               void* arg);

void uv_link_propagate_close(uv_link_t* link, uv_link_t* source,
                             uv_link_close_cb cb);

/* Use this to invoke methods of `link` */

int uv_link_read_start(uv_link_t* link);
int uv_link_read_stop(uv_link_t* link);

static int uv_link_write(uv_link_t* link, const uv_buf_t bufs[],
                         unsigned int nbufs, uv_stream_t* send_handle,
                         uv_link_write_cb cb, void* arg) {
  return uv_link_propagate_write(link, link, bufs, nbufs, send_handle, cb, arg);
}

int uv_link_try_write(uv_link_t* link,
                      const uv_buf_t bufs[],
                      unsigned int nbufs);

static int uv_link_shutdown(uv_link_t* link, uv_link_shutdown_cb cb,
                            void* arg) {
  return uv_link_propagate_shutdown(link, link, cb, arg);
}

int uv_link_errno(uv_link_t** link, int err);
const char* uv_link_strerror(uv_link_t* link, int err);

/* Link Source */

struct uv_link_source_s {
  /* inherits(uv_link_source_t, uv_link_t) */
  UV_LINK_FIELDS

  uv_stream_t* stream;

  uv_link_close_cb close_cb;
  uv_link_t* close_source;
};

/* NOTE: uses `stream->data` field */
UV_EXTERN int uv_link_source_init(uv_link_source_t* source,
                                  uv_stream_t* stream);

/* Link Observer */

struct uv_link_observer_s {
  /* inherits(uv_link_observer_t, uv_link_t) */
  UV_LINK_FIELDS

  /* This will be called, even if the ones in `link` will be overwritten */
  void (*observer_read_cb)(uv_link_observer_t* observer,
                           ssize_t nread,
                           const uv_buf_t* buf);
};

UV_EXTERN int uv_link_observer_init(uv_link_observer_t* observer);

/* Default callbacks */

int uv_link_default_read_start(uv_link_t* link);
int uv_link_default_read_stop(uv_link_t* link);
int uv_link_default_write(uv_link_t* link,
                          uv_link_t* source,
                          const uv_buf_t bufs[],
                          unsigned int nbufs,
                          uv_stream_t* send_handle,
                          uv_link_write_cb cb,
                          void* arg);
int uv_link_default_try_write(uv_link_t* link,
                              const uv_buf_t bufs[],
                              unsigned int nbufs);
int uv_link_default_shutdown(uv_link_t* link,
                             uv_link_t* source,
                             uv_link_shutdown_cb cb,
                             void* arg);
void uv_link_default_close(uv_link_t* link, uv_link_t* source,
                           uv_link_close_cb cb);
const char* uv_link_default_strerror(uv_link_t* link, int err);

void uv_link_default_alloc_cb_override(uv_link_t* link,
                                       size_t suggested_size,
                                       uv_buf_t* buf);
void uv_link_default_read_cb_override(uv_link_t* link,
                                      ssize_t nread,
                                      const uv_buf_t* buf);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* INCLUDE_UV_LINK_H_ */
