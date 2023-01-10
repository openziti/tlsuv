#include "test-common.h"

static uv_link_observer_t a;
static uv_link_observer_t b;
static uv_link_observer_t c;

static int b_reads;
static int c_reads;
static int close_cb_called;

static void c_close_cb(uv_link_t* l) {
  close_cb_called++;
}


static void b_read_cb(uv_link_observer_t* o, ssize_t nread, const uv_buf_t* d) {
  b_reads |= 1 << nread;
  if (nread == 2) {
    uv_buf_t tmp;

    CHECK_EQ(a.close_depth, 0, "depth check");
    CHECK_EQ(b.close_depth, 2, "depth check");
    CHECK_EQ(c.close_depth, 1, "depth check");
    uv_link_close((uv_link_t*) &c, c_close_cb);

    CHECK_EQ(o->parent, NULL, "parent should be zeroed");
    CHECK_EQ(uv_link_try_write(o->parent, &tmp, 0), UV_EFAULT,
             "write should fail");
  } else {
    CHECK_EQ(a.close_depth, 0, "depth check");
    CHECK_EQ(b.close_depth, 1, "depth check");
    CHECK_EQ(c.close_depth, 0, "depth check");
  }
}


static void c_read_cb(uv_link_observer_t* o, ssize_t nread, const uv_buf_t* d) {
  uv_buf_t tmp;

  CHECK(nread > 0, "c_read_cb nread");

  c_reads |= 1 << nread;
  if (nread == 1) {
    uv_link_propagate_alloc_cb((uv_link_t*) &a, nread + 1, &tmp);
    uv_link_propagate_read_cb((uv_link_t*) &a, nread + 1, &tmp);
  }
}


TEST_IMPL(close_depth) {
  uv_buf_t tmp;

  CHECK_EQ(uv_link_observer_init(&a), 0, "uv_link_observer_init()");
  CHECK_EQ(uv_link_observer_init(&b), 0, "uv_link_observer_init()");
  CHECK_EQ(uv_link_observer_init(&c), 0, "uv_link_observer_init()");

  CHECK_EQ(uv_link_chain((uv_link_t*) &a, (uv_link_t*) &b), 0,
           "uv_link_observer_chain()");
  CHECK_EQ(uv_link_chain((uv_link_t*) &b, (uv_link_t*) &c), 0,
           "uv_link_observer_chain()");

  b.observer_read_cb = b_read_cb;
  c.observer_read_cb = c_read_cb;

  uv_link_propagate_alloc_cb((uv_link_t*) &a, 1, &tmp);
  uv_link_propagate_read_cb((uv_link_t*) &a, 1, &tmp);

  CHECK_EQ(close_cb_called, 1, "close_cb must be called");
  CHECK_EQ(b_reads, 6, "b read_cb must be called");
  CHECK_EQ(c_reads, 2, "c read_cb must be called");
}
