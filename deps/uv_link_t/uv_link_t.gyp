{
  "variables": {
    "gypkg_deps": [
      "git://github.com/libuv/libuv.git@^1.9.0 => uv.gyp:libuv",
    ],
  },

  "targets": [{
    "target_name": "uv_link_t",
    "type": "<!(gypkg type)",

    "direct_dependent_settings": {
      "include_dirs": [ "include" ],
    },

    "dependencies": [
      "<!@(gypkg deps <(gypkg_deps))"
    ],

    "include_dirs": [
      ".",
    ],

    "sources": [
      "src/defaults.c",
      "src/uv_link_t.c",
      "src/uv_link_observer_t.c",
      "src/uv_link_source_t.c",
    ],
  }, {
    "target_name": "uv_link_t-test",
    "type": "executable",

    "include_dirs": [
      "test/src"
    ],

    "variables": {
      "gypkg_deps": [
        "git://github.com/libuv/libuv.git@^1.9.0 => uv.gyp:libuv",
        "git://github.com/indutny/mini-test.c.git@^1.0.0 => mini-test.gyp:mini-test",
      ],
    },

    "dependencies": [
      "<!@(gypkg deps <(gypkg_deps))",
      "uv_link_t",
    ],

    "sources": [
      "test/src/main.c",
      "test/src/test-uv-link-source-t.c",
      "test/src/test-uv-link-observer-t.c",
      "test/src/test-defaults.c",
      "test/src/test-close.c",
      "test/src/test-strerror.c",
    ],
  }, {
    "target_name": "uv_link_t-example",
    "type": "executable",

    "include_dirs": [
      "example/src"
    ],

    "dependencies": [
      "<!@(gypkg deps <(gypkg_deps))",
      "uv_link_t",
    ],

    "sources": [
      "example/src/main.c",
      "example/src/middle.c",
    ],
  }],
}
