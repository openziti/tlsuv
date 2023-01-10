# Implementation Guide

`uv_link_t` behaves very similar to [`uv_stream_t`][0]. All `uv_link_methods_t`
MUST conform to this semantics.

## Error Codes

All error codes MUST be negative and be less than `UV_ERRNO_MAX`.

* `UV_ENOSYS` SHOULD be returned if the particular method (e.g. `shutdown` or
  `try_write`)
* `UV_EAGAIN` MUST be returned by `uv_link_methods_t.try_write` if the write
  could not be completed at the moment

## uv_link_init()

Links start in non-reading mode, `alloc_cb`/`read_cb` MUST NOT be called until
`uv_link_read_start(link)` will be invoked with zero return code.

## uv_link_read_start()/uv_link_read_stop()

This switch link to and from the reading mode. After the switch to the reading
mode either:

* `alloc_cb` + `read_cb` will be invoked for a particular link (NOTE: `read_cb`
  MUST follow every `alloc_cb`)
* `read_cb(..., err, ...)` will be called to indicate a error. In this case user
  MUST call `uv_read_stop()` on the error'ed link.

NOTE: `buf` argument of `read_cb` may be `NULL` in case of error.

NOTE: If `alloc_cb` sets `buf->len = 0;` - `read_cb(..., UV_ENOBUFS, ...)` MUST
be called by a link implementation.

## uv_link_close()

Links MAY be closed at any time, unless they are already closed or weren't
initialized with `uv_link_init()`. However, the `methods->close()` may not be
called immediately on `uv_link_close()` if close attempt is happening on the
link's call stack:

```c
static void read_cb(uv_link_t* link, ssize_t nread, uv_buf_t* buf) {
  uv_link_close(link, ...);
}

link->read_cb = read_cb;

uv_link_propagate_read_cb(link, UV_EOF, NULL);
/* link->methods->close() call will happen upon returning from
   `uv_link_propagate_read_cb` */
```

uv_link_t public APIs MUST NOT be used on a link after `uv_link_close(link)`.

When several links are chained together, `uv_link_close()` SHOULD be called only
on a last (leaf) link in a chain. Otherwise `uv_link_t` API is allowed to crash.

When closing leaf link in a chain:

1. All links will be unchained
2. Each link starting from the deepest link (from the leaf) will be closed one
   by one
3. `close_cb` will be invoked upon close of all links in a chain

[0]: http://docs.libuv.org/en/v1.x/stream.html
