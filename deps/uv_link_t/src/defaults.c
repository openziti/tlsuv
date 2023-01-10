#include "src/common.h"

int uv_link_default_read_start(uv_link_t* link) {
  return uv_link_read_start(link->parent);
}


int uv_link_default_read_stop(uv_link_t* link) {
  return uv_link_read_stop(link->parent);
}


int uv_link_default_write(uv_link_t* link,
                          uv_link_t* source,
                          const uv_buf_t bufs[],
                          unsigned int nbufs,
                          uv_stream_t* send_handle,
                          uv_link_write_cb cb,
                          void* arg) {
  return uv_link_propagate_write(link->parent, source, bufs, nbufs,
                                 send_handle, cb, arg);
}


int uv_link_default_try_write(uv_link_t* link,
                              const uv_buf_t bufs[],
                              unsigned int nbufs) {
  return uv_link_try_write(link->parent, bufs, nbufs);
}


int uv_link_default_shutdown(uv_link_t* link,
                             uv_link_t* source,
                             uv_link_shutdown_cb cb,
                             void* arg) {
  return uv_link_propagate_shutdown(link->parent, source, cb, arg);
}


void uv_link_default_close(uv_link_t* link, uv_link_t* source,
                           uv_link_close_cb cb) {
  cb(source);
}


const char* uv_link_default_strerror(uv_link_t* link, int err) {
  return NULL;
}


void uv_link_default_alloc_cb_override(uv_link_t* link,
                                       size_t suggested_size,
                                       uv_buf_t* buf) {
  return uv_link_propagate_alloc_cb(link, suggested_size, buf);
}


void uv_link_default_read_cb_override(uv_link_t* link,
                                      ssize_t nread,
                                      const uv_buf_t* buf) {
  return uv_link_propagate_read_cb(link, nread, buf);
}
