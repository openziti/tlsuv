# uv_link_t

## General notes

All methods with `int` return value return `0` on success or error code, unless
specified otherwise.

Fields not listed here a considered private and should not be modified/relied
upon in user applications.

## uv_link_t

The base unit of all APIs. Pointer to this structure is what needs to be passed
to the most of the methods.

*NOTE: please don't call methods from [`uv_link_methods_t`][] directly. There
are plenty of API methods that wrap this calls in a simpler and portable
manner.*

### int uv_link_init(...)

* `uv_link_t* link` - user allocated `uv_link_t` instance
* `uv_link_methods_t const* methods` - user defined link methods, see
  [`uv_link_methods_t`][] below

Initialize `link` structure with provided `methods`.

This is a first method to be called on `uv_link_t` instance before it could be
used in any other APIs.

### void uv_link_close(...)

* `uv_link_t* link` - `uv_link_t` instance to close
* `uv_link_close_cb cb` - callback to be invoked upon close

Close `uv_link_t` instance and all other `uv_link_t`s chained into it (see
[`uv_link_chain()`][]), invoke `void (*cb)(uv_link_t*)` once done (may happen
synchronously or on a next libuv tick, depending on particular `uv_link_t`
implementation).

Invokes `close` from link's [`uv_link_methods_t`][].

*NOTE: this method must be called on a leaf link that has no chaining child*

### int uv_link_chain(...)

* `uv_link_t* from`
* `uv_link_t* to`

"Chain" two `uv_link_t` instances together, set `from.child = to` and
`to.parent = from`. After this call, all data emitted by `from` link via
[`uv_link_propagate_alloc_cb()`][] and [`uv_link_propagate_read_cb()`][] will be
passed to `to` link's [`uv_link_methods_t`][]'s
[`uv_link_methods_t.alloc_cb_override`][] and
[`uv_link_methods_t.read_cb_override`][].

Closing `to` with `uv_link_close` will also close `from`, unless they will be
later unchained with [`uv_link_unchain()`][].

*NOTE: Links can have at most one parent and one child.*

### int uv_link_unchain(...)

* `uv_link_t* from`
* `uv_link_t* to`

Unlink chains, restoring `from.read_cb` and `from.alloc_cb` to their previous
values (that they had before `uv_link_unchain()` call).

### int uv_link_read_start(...)

* `uv_link_t* link`

Invoke `read_start` from the link's [`uv_link_methods_t`][].
[`uv_link_t.alloc_cb`][]/[`uv_link_t.read_cb`][] may be called after successful
`uv_link_read_start`.

### int uv_link_read_stop(...)

* `uv_link_t* link`

Invoke `read_stop` from the link's [`uv_link_methods_t`][].
[`uv_link_t.alloc_cb`][]/[`uv_link_t.read_cb`][] won't be called after
`uv_link_read_stop`.

### int uv_link_write(...)

* `uv_link_t* link`
* `const uv_buf_t bufs[]` - buffers to write
* `unsigned int nbufs` - number of buffers to write
* `uv_stream_t* send_handle` - handle to send through IPC (if supported by
  underlying [`uv_link_source_t`][])
* `uv_link_write_cb cb` - callback to be invoked
* `void* arg` - user data to be passed to callback

Invoke `write` from the link's [`uv_link_methods_t`][]. Acts similarly to
`uv_write()`. `cb(uv_link_t* link, int status, void* arg)` is invoked on
completion.

### int uv_link_try_write(...)

* `uv_link_t* link`
* `const uv_buf_t bufs[]` - buffers to write
* `unsigned int nbufs` - number of buffers to write

Invoke `try_write` from the link's [`uv_link_methods_t`][]. Acts similarly to
`uv_try_write()`.

Returns number of bytes written, or negative error code.

### int uv_link_shutdown(...)

* `uv_link_t* link`
* `uv_link_shutdown_cb cb` - callback to be invoked
* `void* arg` - user data to be passed to callback

Invoke `shutdown` from the link's [`uv_link_methods_t`][]. Acts similarly to
`uv_shutdown()`. `cb(uv_link_t* link, int status, void* arg)` is invoked on
completion.

### int uv_link_errno(...)

* `uv_link_t** link`
* `int err` - error code, previously either returned by the one of
  `uv_link...` methods or passed as a negative `nread` to `link->read_cb`

Unprefix internal error code and set the `link` pointer to the link that
have emitted that error.

### const char* uv_link_strerror(...)

* `uv_link_t* link`
* `int err` - error code, previously either returned the one of the
  `uv_link...` methods or passed as a negative `nread` to `link->read_cb`

Invoke `strerror` from the link's [`uv_link_methods_t`][]. Acts similarly to
`uv_strerror()`. Returns a description of error code that has just been given
back to the user.

### void uv_link_propagate_alloc_cb(...)

Should be used only by [`uv_link_methods_t`][] implementation.

* `uv_link_t* link`
* `size_t suggested_size`
* `uv_buf_t* buf`

Arguments have the same meaning as in `uv_alloc_cb`. When calling this function
`link->alloc_cb` will be invoked with either `link` or `link->child` (if latter
is not `NULL`).

This should be used to emit data from `uv_link_t`. Semantics are the same as of
`uv_alloc_cb`.

### void uv_link_propagate_read_cb(...)

Should be used only by [`uv_link_methods_t`][] implementation.

* `uv_link_t* link`
* `ssize_t nread`
* `const uv_buf_t* buf`

Arguments have the same meaning as in `uv_read_cb`. When calling this function
`link->read_cb` will be invoked with either `link` or `link->child` (if latter
is not `NULL`).

Should be used to emit data from `uv_link_t`. Semantics are the same as of
`uv_read_cb`.

### int uv_link_propagate_write(...)

Should be used only by [`uv_link_methods_t`][] implementation.

* `uv_link_t* link`
* `uv_link_t* source` - source link to be passed to `cb` as a first argument
* `const uv_buf_t bufs[]` - buffers to write
* `unsigned int nbufs` - number of buffers to write
* `uv_stream_t* send_handle` - handle to send through IPC (if supported by
  underlying [`uv_link_source_t`][])
* `uv_link_write_cb cb` - callback to be invoked
* `void* arg` - user data to be passed to callback

Invoke `write` from the`link`'s [`uv_link_methods_t`][]. Could be used to
pass through the data in a following way:

```c
uv_link_propagate_write(link->parent, source, ...);
```

*NOTE: `source` and `cb` may be passed through multiple links to avoid storing
extra data in auxilliary structures.*

### int uv_link_propagate_shutdown(...)

Should be used only by [`uv_link_methods_t`][] implementation.

* `uv_link_t* link`
* `uv_link_t* source` - source link to be passed to `cb` as a first argument
* `uv_link_shutdown_cb cb` - callback to be invoked
* `void* arg` - user data to be passed to callback

Invoke `shutdown` from the`link`'s [`uv_link_methods_t`][]. Could be used to
pass through shutdown request in a following way:

```c
uv_link_propagate_shutdown(link->parent, source, ...);
```

*NOTE: `source` and `cb` may be passed through multiple links to avoid storing
extra data in auxilliary structures.*

### void uv_link_propagate_close(...)

Should be used only by [`uv_link_methods_t`][] implementation.

* `uv_link_t* link`
* `uv_link_t* source` - source link to be passed to `cb` as a first argument
* `uv_link_close_cb cb` - callback to be invoked

Invoke `close` from the`link`'s [`uv_link_methods_t`][]. Could be used to
close auxiliary links that are not in a current chain.

`source` MUST be a leaf link of chain that is currently being closed.

### .data

```c
void* data;
```

Property of `void*` type, any value may be stored here. Not used internally.

### .alloc_cb

```c
typedef void (*uv_link_alloc_cb)(uv_link_t* link,
                                 size_t suggested_size,
                                 uv_buf_t* buf);
```

Invoked by [`uv_link_propagate_alloc_cb()`][] to emit data on `link`.
Semantics are the same as in `uv_alloc_cb`.

By default contains a function that `malloc`s `suggested_size`.

Overridden on [`uv_link_chain()`][] call by the value of
[`uv_link_methods_t.alloc_cb_override`][] from the child link's
[`uv_link_methods_t`][].

### .read_cb

```c
typedef void (*uv_link_read_cb)(uv_link_t* link,
                                ssize_t nread,
                                const uv_buf_t* buf);
```

Invoked by [`uv_link_propagate_read_cb()`][] to emit data on `link`.
Semantics are the same as in `uv_read_cb`.

By default just `free`s the `buf->base`, if `buf` is not `NULL`.

Overridden on [`uv_link_chain()`][] call by the value of
[`uv_link_methods_t.read_cb_override`][] from the child link's
[`uv_link_methods_t`][].

### .parent

```c
uv_link_t* parent;
```

Pointer to the parent link in a chain. Default value: `NULL`.

### .child

```c
uv_link_t* child;
```

Pointer to the child link in a chain. Default value: `NULL`.

## uv_link_methods_t

Methods table, can be shared by multiple links. In the most of the cases should
be a pointer to a static structure, since it is immutable and contains only
pointers to the functions.

Must be provided to [`uv_link_init()`][].

These functions could be used as a default implementations of
`uv_link_methods_t` callbacks:

```c
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
```

These maybe used for [`uv_methods_talloc_cb_override`][] and
[`uv_methods_t.read_cb_override`][].

```c
void uv_link_default_alloc_cb_override(uv_link_t* link,
                                       size_t suggested_size,
                                       uv_buf_t* buf);
void uv_link_default_read_cb_override(uv_link_t* link,
                                      ssize_t nread,
                                      const uv_buf_t* buf);
```

### .read_start

```c
int (*read_start)(uv_link_t* link);
```

Invoked by [`uv_link_read_start()`][]. Data may be emitted after this call.

*NOTE: semantics are the same as of `uv_read_start`.*

### .read_stop

```c
int (*read_stop)(uv_link_t* link);
```

Invoked by [`uv_link_read_stop()`][]. Data MUST not be emitted after this call.

*NOTE: semantics are the same as of `uv_read_stop`.*

### .write

```c
int (*write)(uv_link_t* link,
             uv_link_t* source,
             const uv_buf_t bufs[],
             unsigned int nbufs,
             uv_stream_t* send_handle,
             uv_link_write_cb cb,
             void* arg);
```

Invoked by [`uv_link_write()`][] or by [`uv_link_propagate_write()`][].

At the time of completion of operation `cb(source, ...)` MUST be called, `link`
is passed only only for internal operation.

*NOTE: semantics are the same as of `uv_write2`.*

### .try_write

```c
int (*try_write)(uv_link_t* link,
                 const uv_buf_t bufs[],
                 unsigned int nbufs);
```

Invoked by [`uv_link_try_write()`][].

*NOTE: semantics are the same as of `uv_try_write`.*

### .shutdown

```c
int (*shutdown)(uv_link_t* link,
                uv_link_t* source,
                uv_link_shutdown_cb cb,
                void* arg);
```

Invoked by [`uv_link_shutdown()`][] or [`uv_link_propagate_shutdown`][].

At the time of completion of operation `cb(source, ...)` MUST be called, `link`
is passed only only for internal operation.

*NOTE: semantics are the same as of `uv_shutdown`.*

### .close

```c
void (*close)(uv_link_t* link, uv_link_t* source, uv_link_close_cb cb);
```

Invoked by [`uv_link_close()`][] or [`uv_link_propagate_close`][].

At the time of completion of operation `cb(source, ...)` MUST be called, `link`
is passed only only for internal operation.

*NOTE: semantics are the same as of `uv_close`.*

### .strerror

```c
const char* (*strerror)(uv_link_t* link, int err);
```

Invoked by [`uv_link_strerror()`][].

Should return a description string of the `err` that was emitted by the `link`.

*NOTE: semantics are the same as of `uv_strerror`.*

### .alloc_cb_override

A method used to override that value of [`uv_link_t.alloc_cb`][] by
[`uv_link_chain()`][] call.

*NOTE: this method will always receive a `link` associated with a
[`uv_link_methods_t`][] that has this `alloc_cb_override`. This is guaranteed by
the API.*

### .read_cb_override

A method used to override that value of [`uv_link_t.read_cb`][] by
[`uv_link_chain()`][] call.

*NOTE: this method will always receive a `link` associated with a
[`uv_link_methods_t`][] that has this `read_cb_override`. This is guaranteed by
the API.*

## uv_link_source_t

A bridge between `libuv`'s `uv_stream_t` and `uv_link_t`. Emits all incoming
data with [`uv_link_t.alloc_cb`][] and [`uv_link_t.read_cb`][], propagates all
other methods as they are to `libuv`.

Can be cast to `uv_link_t`:
```
uv_link_source_t* source = ...;
uv_link_t* link = (uv_link_t*) source;
```

*NOTE: `stream.data` is used by `uv_link_source_t` internally.*

*NOTE: Most of the applications will use this structure as a root link in their
chains, since it is capable of sending/reading data from the socket/pipe/etc.*

*NOTE: All `uv_link_...` methods can be used with `uv_link_source_t`*

### int uv_link_source_init(...)

* `uv_link_source_t* source` - structure to initialize
* `uv_stream_t* stream` - `uv_stream_t` to use

Initialize `uv_link_source_t` structure to work with `stream`.

*NOTE: `uv_link_source_t` will `uv_close` the `stream` on `uv_link_close`,
however it does not manage the pointer to the stream, so it MUST be released
separately if it was allocated.*

## uv_link_observer_t

A helper structure to observe (*not manage*) the reads of the link. When links
are chained - [`uv_link_t.read_cb`][]/[`uv_link_t.alloc_cb`][] are overwritten
by [`uv_link_chain()`][]. `uv_link_observer_t` provides a consistent way to
observe the reads on a link, even if the link will be chained with another link
later on. Use [`uv_link_observer_t.observer_read_cb`][] property to set up read
callback.

Can be cast to `uv_link_t`:
```
uv_link_observer_t* observer = ...;
uv_link_t* link = (uv_link_t*) observer;
```

*NOTE: All `uv_link_...` methods can be used with `uv_link_source_t`*

### int uv_link_observer_init(...)

* `uv_link_observer_t* observer` - structure to initialize

Initialize the structure.

### .observer_read_cb

```c
void (*observer_read_cb)(uv_link_observer_t* observer,
                         ssize_t nread,
                         const uv_buf_t* buf);
```

Invoked by `uv_link_propagate_read_cb`. MUST not manage the data in `buf`.

[`uv_link_chain()`]: #int-uv_link_chain
[`uv_link_close()`]: #void-uv_link_close
[`uv_link_strerror()`]: #const-char-uv_link_strerror
[`uv_link_init()`]: #int-uv_link_init
[`uv_link_methods_t`]: #uv_link_methods_t
[`uv_link_observer_t.observer_read_cb`]: #observer_read_cb
[`uv_link_propagate_alloc_cb()`]: #void-uv_link_propagate_alloc_cb
[`uv_link_propagate_close`]: #void-uv_link_propagate_close
[`uv_link_propagate_read_cb()`]: #void-uv_link_propagate_read_cb
[`uv_link_propagate_shutdown`]: #int-uv_link_propagate_shutdown
[`uv_link_propagate_write()`]: #int-uv_link_propagate_write
[`uv_link_read_start()`]: #int-uv_link_read_start
[`uv_link_read_stop()`]: #int-uv_link_read_stop
[`uv_link_shutdown()`]: #int-uv_link_shutdown
[`uv_link_source_t`]: #uv_link_source_t
[`uv_link_t.alloc_cb`]: #alloc_cb
[`uv_link_t.read_cb`]: #read_cb
[`uv_link_try_write()`]: #int-uv_link_try_write
[`uv_link_unchain()`]: #int-uv_link_unchain
[`uv_link_write()`]: #int-uv_link_write
[`uv_link_methods_t.alloc_cb_override`]: #alloc_cb_override
[`uv_link_methods_t.read_cb_override`]: #read_cb_override
