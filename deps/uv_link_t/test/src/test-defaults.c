#include "test-common.h"

static uv_link_t st_link;

static int reading;
static int close_cb_called;


static int read_start(uv_link_t* link) {
  reading++;
  return 0;
}


static int read_stop(uv_link_t* link) {
  reading--;
  return 0;
}


static uv_link_methods_t methods = {
  .read_start = read_start,
  .read_stop = read_stop,
  .close = uv_link_default_close
};

static void close_cb(uv_link_t* l) {
  close_cb_called++;
}


TEST_IMPL(stop_read_on_error) {
  CHECK_EQ(uv_link_init(&st_link, &methods), 0, "uv_link_init()");
  CHECK_EQ(uv_link_read_start(&st_link), 0, "uv_link_read_start()");
  uv_link_propagate_read_cb(&st_link, UV_EOF, NULL);
  CHECK_EQ(reading, 0, "must not be reading after error");

  uv_link_close(&st_link, close_cb);
  CHECK_EQ(close_cb_called, 1, "close_cb must be called");
}
