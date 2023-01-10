# uv_link_t
[![GitHub version](https://badge.fury.io/gh/indutny%2Fuv_link_t.svg)](https://badge.fury.io/gh/indutny%2Fuv_link_t)
[![Build Status](https://secure.travis-ci.org/indutny/uv_link_t.svg)](http://travis-ci.org/indutny/uv_link_t)

**HIGHLY UNSTABLE**

Chainable [libuv][0] streams.

## Why?

It is quite easy to write a TCP server/client in [libuv][0]. Writing HTTP
server/client is a bit harder. Writing HTTP server/client on top of TLS server
could be unwieldy.

`uv_link_t` aims to solve complexity problem that quickly escalates once using
multiple layers of protocols in [libuv][0] by providing a way to implement
protocols separately and chain them together in an easy and high-performant way
using very narrow interfaces.

## How?

_(NOTE: chain is built from links)_

_(NOTE: many of these API methods have return values, check them!)_

First, a `uv_stream_t*` instance needs to be picked. It will act as a source
link in a chain:
```c
uv_stream_t* stream = ...;

uv_link_source_t source;

uv_link_source_init(uv_default_loop(), &source, stream);
```

A chain can be formed with `&source` and any other `uv_link_t` instance:
```c
uv_link_t link;

static uv_link_methods_t methods = {
  .read_start = read_start_impl,
  .read_stop = read_stop_impl,
  .write = write_impl,
  .try_write = try_write_impl,
  .shutdown = shutdown_impl,
  .close = close_impl,

  /* These will be used only when chaining two links together */

  .alloc_cb_override = alloc_cb_impl,
  .read_cb_override = read_cb_impl
};

uv_link_init(&link, &methods);

/* Just like in libuv */
link.alloc_cb = my_alloc_cb;
link.read_cb = my_read_cb;

/* Creating a chain here */
uv_link_chain(&source, &link);

uv_link_read_start(&link);
```

Now comes a funny part, any of these method implementations may hook up into
the parent link in a chain to perform their actions:

```c
static int shutdown_impl(uv_link_t* link,
                         uv_link_t* source,
                         uv_link_shutdown_cb cb,
                         void* arg) {
  fprintf(stderr, "this will be printed\n");
  return uv_link_propagate_shutdown(link->parent, source, cb, arg);
}
```

## Technical details

[API Docs][2]
[Implementation Guide][3]

## LICENSE

This software is licensed under the MIT License.

Copyright Fedor Indutny, 2016.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.

[0]: https://github.com/libuv/libuv
[1]: https://github.com/indutny/uv_link_t/blob/master/include/uv_link_t.h
[2]: https://github.com/indutny/uv_link_t/blob/master/docs/api.md
[3]: https://github.com/indutny/uv_link_t/blob/master/docs/implementation-guide.md
