#include "test-common.h"

static uv_link_t source;
static uv_link_observer_t observer;

static int observer_read_cb_called;
static int fake_close_called;
static int close_cb_called;

static void fake_close(uv_link_t* link,
                       uv_link_t* src,
                       uv_link_close_cb cb) {
  CHECK_EQ(link, &source, "fake_close link");
  /* NOTE: `src` may not be a proper source here */

  fake_close_called++;

  /* Not 100% correct, since it is sync, but works here */
  cb(src);
}

static uv_link_methods_t methods = {
  .close = fake_close

  /* rest are no-op, won't be called */
};

static void observer_read_cb(uv_link_observer_t* o,
                             ssize_t nread,
                             const uv_buf_t* buf) {
  CHECK_EQ(o, &observer, "o == &observer");
  CHECK_EQ(nread, 1, "nread == 1");
  CHECK_EQ(buf->base[0], 'x', "correct buf contents");

  observer_read_cb_called++;
}


static void close_cb(uv_link_t* link) {
  CHECK_EQ(link, (uv_link_t*) &observer, "close_cb link");

  close_cb_called++;
}


TEST_IMPL(uv_link_observer_t) {
  uv_buf_t buf;

  CHECK_EQ(uv_link_init(&source, &methods), 0, "uv_link_init(source)");

  CHECK_EQ(uv_link_observer_init(&observer), 0, "uv_link_observer_init()");
  CHECK_EQ(uv_link_chain(&source, (uv_link_t*) &observer), 0,
           "uv_link_chain");

  observer.observer_read_cb = observer_read_cb;

  uv_link_propagate_alloc_cb(&source, 1024, &buf);

  buf.base[0] = 'x';
  uv_link_propagate_read_cb(&source, 1, &buf);
  CHECK_EQ(observer_read_cb_called, 1, "observer.read_cb must be called");

  uv_link_close((uv_link_t*) &observer, close_cb);
  CHECK_EQ(fake_close_called, 1, "fake close count");
  CHECK_EQ(close_cb_called, 1, "close_cb count");
}
