#include <stdlib.h>
#include <string.h>

#include "src/common.h"


static void uv_link_observer_read_cb(uv_link_t* link,
                                     ssize_t nread,
                                     const uv_buf_t* buf) {
  uv_link_observer_t* observer;

  observer = (uv_link_observer_t*) link;

  if (observer->observer_read_cb != NULL)
    observer->observer_read_cb(observer, nread, buf);

  return uv_link_propagate_read_cb(link, nread, buf);
}


static uv_link_methods_t uv_link_observer_methods = {
  .read_start = uv_link_default_read_start,
  .read_stop = uv_link_default_read_stop,
  .write = uv_link_default_write,
  .try_write = uv_link_default_try_write,
  .shutdown = uv_link_default_shutdown,
  .close = uv_link_default_close,

  .alloc_cb_override = uv_link_default_alloc_cb_override,
  .read_cb_override = uv_link_observer_read_cb
};


int uv_link_observer_init(uv_link_observer_t* observer) {
  int err;

  observer->observer_read_cb = NULL;

  err = uv_link_init((uv_link_t*) observer, &uv_link_observer_methods);
  if (err != 0)
    return err;

  return 0;
}
