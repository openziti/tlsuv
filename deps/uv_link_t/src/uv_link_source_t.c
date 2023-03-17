#include <stdlib.h>
#include <string.h>

#include "src/common.h"

typedef struct uv_link_source_write_s uv_link_source_write_t;
typedef struct uv_link_source_shutdown_s uv_link_source_shutdown_t;

struct uv_link_source_write_s {
  uv_write_t req;
  uv_link_t* link;
  void* arg;
  uv_link_write_cb write_cb;
};

struct uv_link_source_shutdown_s {
  uv_shutdown_t req;
  uv_link_t* link;
  void* arg;
  uv_link_shutdown_cb shutdown_cb;
};


static void uv_link_source_wrap_alloc_cb(uv_handle_t* handle,
                                         size_t suggested_size,
                                         uv_buf_t* buf) {
  uv_link_source_t* source;

  source = handle->data;

  uv_link_propagate_alloc_cb((uv_link_t*) source, suggested_size, buf);
}


static void uv_link_source_wrap_read_cb(uv_stream_t* stream,
                                        ssize_t nread,
                                        const uv_buf_t* buf) {
  uv_link_source_t* source;

  source = stream->data;

  uv_link_propagate_read_cb((uv_link_t*) source, nread, buf);
}


static int uv_link_source_read_start(uv_link_t* link) {
  uv_link_source_t* source;

  source = (uv_link_source_t*) link;

  return uv_read_start(source->stream,
                       uv_link_source_wrap_alloc_cb,
                       uv_link_source_wrap_read_cb);
}


static int uv_link_source_read_stop(uv_link_t* link) {
  uv_link_source_t* source;

  source = (uv_link_source_t*) link;

  return uv_read_stop(source->stream);
}


static void uv_link_source_wrap_write_cb(uv_write_t* req, int status) {
  uv_link_source_write_t* lreq;

  lreq = container_of(req, uv_link_source_write_t, req);
  lreq->write_cb(lreq->link, status, lreq->arg);
  free(lreq);
}


static int uv_link_source_write(uv_link_t* link,
                                uv_link_t* source,
                                const uv_buf_t bufs[],
                                unsigned int nbufs,
                                uv_stream_t* send_handle,
                                uv_link_write_cb cb,
                                void* arg) {
  uv_link_source_t* s;
  uv_link_source_write_t* req;
  int rc;

  s = (uv_link_source_t*) link;
  req = malloc(sizeof(*req));
  if (req == NULL)
    return UV_ENOMEM;

  req->link = source;
  req->write_cb = cb;
  req->arg = arg;

  rc = uv_write2(&req->req, s->stream, bufs, nbufs, send_handle,
                 uv_link_source_wrap_write_cb);
  if (rc != 0) {
    free(req);
  }
  return rc;
}


static int uv_link_source_try_write(uv_link_t* link,
                                    const uv_buf_t bufs[],
                                    unsigned int nbufs) {
  uv_link_source_t* source;

  source = (uv_link_source_t*) link;

  return uv_try_write(source->stream, bufs, nbufs);
}


static void uv_link_source_wrap_shutdown_cb(uv_shutdown_t* req, int status) {
  uv_link_source_shutdown_t* lreq;

  lreq = container_of(req, uv_link_source_shutdown_t, req);
  lreq->shutdown_cb(lreq->link, status, lreq->arg);
  free(lreq);
}


static int uv_link_source_shutdown(uv_link_t* link,
                                   uv_link_t* source,
                                   uv_link_shutdown_cb cb,
                                   void* arg) {
  uv_link_source_t* s;
  uv_link_source_shutdown_t* req;
  int rc;

  s = (uv_link_source_t*) link;

  req = malloc(sizeof(*req));
  if (req == NULL)
    return UV_ENOMEM;

  req->link = source;
  req->shutdown_cb = cb;
  req->arg = arg;

  rc = uv_shutdown(&req->req, s->stream, uv_link_source_wrap_shutdown_cb);
  if (rc != 0) {
    free(req);
  }
  return rc;
}


static void uv_link_source_close_cb(uv_handle_t* handle) {
  uv_link_source_t* source;

  source = handle->data;
  handle->data = NULL;

  if (source != NULL) {
      source->stream = NULL;
      if (source->close_cb) {
          source->close_cb(source->close_source);
      }
  }
}


static void uv_link_source_close(uv_link_t* link, uv_link_t* source,
                                 uv_link_close_cb cb) {
  uv_link_source_t* s;

  s = (uv_link_source_t*) link;

  if (s->stream) {
      if (!uv_is_closing((const uv_handle_t *) s->stream)) {
          s->close_cb = cb;
          s->close_source = source;
          uv_close((uv_handle_t *) s->stream, uv_link_source_close_cb);
      }
  } else {
      cb(source);
  }
}


static uv_link_methods_t uv_link_source_methods = {
  .read_start = uv_link_source_read_start,
  .read_stop = uv_link_source_read_stop,
  .write = uv_link_source_write,
  .try_write = uv_link_source_try_write,
  .shutdown = uv_link_source_shutdown,
  .close = uv_link_source_close
};


int uv_link_source_init(uv_link_source_t* source,
                        uv_stream_t* stream) {
  int err;

  err = uv_link_init((uv_link_t*) source, &uv_link_source_methods);
  if (err != 0)
    return err;

  source->stream = stream;
  source->stream->data = source;
  source->close_cb = NULL;
  source->close_source = NULL;

  return 0;
}
