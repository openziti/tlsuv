#include "test-common.h"

static uv_link_t a_link;
static uv_link_t b_link;

static int close_cb_called;


static int faulty_try_write(uv_link_t* link,
                            const uv_buf_t bufs[],
                            unsigned int nbufs) {
  return UV_ERRNO_MAX - 1;
}


const char* a_strerror(uv_link_t* l, int err) {
  CHECK_EQ(l, &a_link, "link == a_link");
  return "a";
}


const char* b_strerror(uv_link_t* l, int err) {
  CHECK_EQ(l, &b_link, "link == b_link");
  return "b";
}


static uv_link_methods_t a_methods = {
  .try_write = faulty_try_write,
  .strerror = a_strerror,
  .close = uv_link_default_close
};


static uv_link_methods_t b_methods = {
  .try_write = faulty_try_write,
  .strerror = b_strerror,
  .close = uv_link_default_close,

  .alloc_cb_override = uv_link_default_alloc_cb_override,
  .read_cb_override = uv_link_default_read_cb_override
};


static void close_cb(uv_link_t* l) {
  close_cb_called++;
}


TEST_IMPL(strerror) {
  int err;

  CHECK_EQ(uv_link_init(&a_link, &a_methods), 0, "uv_link_init()");
  CHECK_EQ(uv_link_init(&b_link, &b_methods), 0, "uv_link_init()");
  CHECK_EQ(uv_link_chain(&a_link, &b_link), 0, "uv_link_chain()");

  CHECK_EQ(uv_link_strerror(&b_link, UV_ERRNO_MAX - 1), NULL,
           "unprefixed error should not be found");

  err = uv_link_try_write(&b_link, NULL, 0);
  CHECK_EQ(strcmp(uv_link_strerror(&b_link, err), "b"), 0,
           "error description should match");

  err = uv_link_try_write(&a_link, NULL, 0);
  CHECK_EQ(strcmp(uv_link_strerror(&b_link, err), "a"), 0,
           "error description should match");

  uv_link_close(&b_link, close_cb);
  CHECK_EQ(close_cb_called, 1, "close_cb must be called");
}
