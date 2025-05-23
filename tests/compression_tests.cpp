

#include <uv.h>
#include <parson.h>
#include <catch2/catch_all.hpp>
#include "compression.h"


TEST_CASE("deflate", "[http]") {

    unsigned char packet_bytes[] = {
  0x78, 0x9c, 0x3d, 0x8f, 0xbb, 0x0e, 0x82, 0x30,
  0x14, 0x86, 0x77, 0x9e, 0xa2, 0xe9, 0x68, 0x6c,
  0xa1, 0xca, 0xd5, 0xc4, 0x81, 0x81, 0xa8, 0x9b,
  0x31, 0x98, 0xb8, 0x42, 0x7b, 0x2c, 0x4d, 0xa4,
  0x25, 0xa5, 0x2e, 0x1a, 0xdf, 0xdd, 0x82, 0x86,
  0xf1, 0xff, 0xfe, 0x4b, 0xce, 0x79, 0x07, 0x08,
  0x61, 0x01, 0xf7, 0x47, 0xe3, 0x40, 0xe0, 0x1d,
  0x72, 0xf6, 0x09, 0x6b, 0x34, 0xc1, 0x0e, 0x1a,
  0x01, 0x76, 0xf4, 0xec, 0xed, 0xa5, 0x07, 0x25,
  0xe7, 0x30, 0x38, 0xaf, 0xf1, 0x2a, 0x5c, 0xe1,
  0x39, 0xb4, 0x50, 0x52, 0x69, 0x6e, 0x84, 0xd2,
  0x72, 0xb2, 0xe5, 0x4b, 0x0d, 0x6b, 0xf4, 0x1f,
  0x5d, 0x82, 0x47, 0x33, 0xce, 0xe5, 0xce, 0xb9,
  0xa1, 0x55, 0x9a, 0x1a, 0x2b, 0x17, 0xef, 0x3a,
  0x82, 0x25, 0xa5, 0x04, 0x3d, 0x27, 0x8e, 0x75,
  0x7d, 0x56, 0x10, 0x32, 0x1a, 0xd1, 0xcd, 0x12,
  0xb9, 0x91, 0xb2, 0x7f, 0x69, 0x52, 0xdb, 0x86,
  0x03, 0x39, 0x4d, 0xa7, 0xe2, 0x8b, 0x31, 0x6e,
  0xcf, 0x48, 0xba, 0x89, 0x58, 0x16, 0xdf, 0x33,
  0x92, 0x25, 0x59, 0x91, 0xb2, 0x96, 0x25, 0x79,
  0xd4, 0x02, 0x08, 0x91, 0xb4, 0xa9, 0x60, 0xc0,
  0x0b, 0xec, 0x17, 0x3e, 0xbf, 0xa7, 0x7a, 0x70,
  0x9d, 0x99, 0xcb, 0x87, 0xaa, 0xfe, 0x6d, 0x63,
  0x63, 0x95, 0x54, 0x7a, 0x62, 0x39, 0x2d, 0x68,
  0x1e, 0x53, 0x16, 0x6f, 0x71, 0xf0, 0x09, 0xbe,
  0x24, 0x59, 0x49, 0xc2
};

    auto encodings = um_available_encoding();

    struct res {
        std::string str;
        bool eof = false;
    } res;
    auto cb = [](void *ctx, const char *b, ssize_t len) {
        auto out = (struct res *)ctx;
        if (len > 0)
            out->str.append(b, len);

        if (len == UV_EOF) {
            out->eof = true;
        }
    };

    auto inflater = um_get_inflater("deflate", cb, &res);

    CHECK(um_inflate(inflater, (const char*)packet_bytes, sizeof(packet_bytes)) == 1);
    CHECK(um_inflate_state(inflater) == 1);
    auto j = json_parse_string(res.str.c_str());
    auto json = json_value_get_object(j);
    auto method = json_object_get_string(json, "method");
    auto url = json_object_dotget_string(json, "url");

    CHECK_THAT(method, Catch::Matchers::Equals("GET"));
    json_value_free(j);

    um_free_inflater(inflater);

    inflater = um_get_inflater("deflate", cb, &res);

    size_t inputLen = sizeof(packet_bytes);
    CHECK(um_inflate(inflater, (const char*)packet_bytes, inputLen / 2 ) == 0);
    CHECK(um_inflate(inflater, (const char*)packet_bytes + (inputLen/2), inputLen - inputLen / 2 ) == 1);
    CHECK(um_inflate_state(inflater) == 1);
    j = json_parse_string(res.str.c_str());
    json = json_value_get_object(j);
    method = json_object_get_string(json, "method");
    CHECK_THAT(method, Catch::Matchers::Equals("GET"));
    um_free_inflater(inflater);
    json_value_free(j);
}


TEST_CASE("gzip", "[http]") {

    unsigned char packet_bytes[] = {
  0x1f, 0x8b, 0x08, 0x00, 0x97, 0x78, 0x01, 0x62,
  0x02, 0xff, 0x3d, 0x8f, 0xbb, 0x0e, 0xc2, 0x20,
  0x14, 0x86, 0xf7, 0x3e, 0x05, 0x61, 0x34, 0x82,
  0xa5, 0x92, 0x5e, 0x4c, 0x1c, 0x3a, 0x18, 0x75,
  0x33, 0xa6, 0x26, 0xae, 0x08, 0x47, 0x4a, 0xa2,
  0xd0, 0x50, 0x5c, 0x34, 0xbe, 0xbb, 0x50, 0x93,
  0x8e, 0xff, 0xf7, 0x5f, 0x72, 0xce, 0x27, 0x43,
  0x08, 0xeb, 0xb7, 0x19, 0x06, 0x50, 0x78, 0x83,
  0x82, 0x7f, 0xc1, 0x12, 0x25, 0xd6, 0x83, 0x50,
  0xe0, 0xc7, 0xc8, 0x3e, 0x51, 0x46, 0xd0, 0x4a,
  0x09, 0x43, 0x88, 0x1a, 0x2f, 0x56, 0x0b, 0x3c,
  0x85, 0x66, 0x4a, 0x76, 0x56, 0x3a, 0x65, 0xac,
  0x4e, 0x76, 0x5a, 0x5b, 0x22, 0x05, 0xf7, 0x87,
  0x08, 0x30, 0x07, 0x0f, 0x6e, 0x9c, 0xca, 0x7d,
  0x08, 0xc3, 0xcd, 0x58, 0xea, 0xbc, 0x9e, 0xbd,
  0xcb, 0x08, 0x9e, 0xb4, 0x1a, 0xec, 0x94, 0x38,
  0x74, 0xdd, 0xc9, 0xc0, 0x8a, 0xd1, 0x9c, 0x16,
  0x73, 0xe4, 0x4a, 0xda, 0xe7, 0xdb, 0x92, 0xce,
  0x0b, 0x09, 0xe4, 0x98, 0x4e, 0xc5, 0x67, 0xe7,
  0xc2, 0x96, 0x91, 0xb2, 0xc8, 0x59, 0x55, 0x37,
  0x15, 0x61, 0xb7, 0xbc, 0x62, 0xb2, 0x64, 0x45,
  0x51, 0x72, 0x21, 0x14, 0xe7, 0xcd, 0x9d, 0x0b,
  0xa6, 0x14, 0x8e, 0x0b, 0xdf, 0xff, 0x53, 0x4f,
  0x08, 0xbd, 0x9b, 0xca, 0xfb, 0x5d, 0xf7, 0xdf,
  0xc6, 0xce, 0x1b, 0x6d, 0x6c, 0x62, 0x35, 0x6d,
  0x68, 0xcd, 0x29, 0xe3, 0x6b, 0x9c, 0x7d, 0xb3,
  0x1f, 0x6d, 0xb1, 0xb0, 0x6a, 0x1a, 0x01, 0x00,
  0x00
};

    auto encodings = um_available_encoding();

    struct res {
        std::string str;
        bool eof = false;
    } res;
    auto cb = [](void *ctx, const char *b, ssize_t len) {
        auto out = (struct res *)ctx;
        if (len > 0)
            out->str.append(b, len);

        if (len == UV_EOF) {
            out->eof = true;
        }
    };

    auto inflater = um_get_inflater("gzip", cb, &res);

    CHECK(um_inflate(inflater, (const char*)packet_bytes, sizeof(packet_bytes)) == 1);
    CHECK(um_inflate_state(inflater) == 1);
    std::string expected("{\n"
                         "  \"gzipped\": true, \n"
                         "  \"headers\": {\n"
                         "    \"Accept\": \"*/*\", \n"
                         "    \"Accept-Encoding\": \"gzip, deflate\", \n"
                         "    \"Host\": \"httpbin.org\", \n"
                         "    \"User-Agent\": \"HTTPie/1.0.2\", \n"
                         "    \"X-Amzn-Trace-Id\": \"Root=1-62017897-1b071c612264aad449f4a1dd\"\n"
                         "  }, \n"
                         "  \"method\": \"GET\", \n"
                         "  \"origin\": \"8.9.84.143\"\n"
                         "}\n");
    CHECK(res.str == expected);
    um_free_inflater(inflater);

    res.str = "";
    inflater = um_get_inflater("gzip", cb, &res);

    size_t inputLen = sizeof(packet_bytes);
    CHECK(um_inflate(inflater, (const char*)packet_bytes, inputLen / 2 ) == 0);
    CHECK(um_inflate_state(inflater) == 0);
    CHECK(um_inflate(inflater, (const char*)packet_bytes + (inputLen/2), inputLen - inputLen / 2 ) == 1);
    CHECK(um_inflate_state(inflater) == 1);
    CHECK_THAT(res.str, Catch::Matchers::Equals(expected));
    um_free_inflater(inflater);
}


TEST_CASE("gzip invalid", "[http]") {

    unsigned char packet_bytes[] = {
  0x1f, 0x8b, 0x08, 0x00, 0x97, 0x78, 0x01, 0x62,
  0x02, 0xff, 0x3d, 0x8f, 0xbb, 0x0e, 0xc2, 0x20,
  0x14, 0x86, 0xf7, 0x3e, 0x05, 0x61, 0x34, 0x82,
  0xa5, 0x92, 0x5e, 0x4c, 0x1c, 0x3a, 0x18, 0x75,
  0x33, 0xa6, 0x26, 0xae, 0x08, 0x47, 0x4a, 0xa2,
  0xd0, 0x50, 0x5c, 0x34, 0xbe, 0xbb, 0x50, 0x93,
  0x8e, 0xff, 0xf7, 0x5f, 0x72, 0xce, 0x27, 0x43,
  0x08, 0xeb, 0xb7, 0x19, 0x06, 0x50, 0x78, 0x83,
  0x82, 0x7f, 0xc1, 0x12, 0x25, 0xd6, 0x83, 0x50,
  0xe0, 0xc7, 0xc8, 0x3e, 0x51, 0x46, 0xd0, 0x4a,
  0x09, 0x43, 0x88, 0x1a, 0x2f, 0x56, 0x0b, 0x3c,
  0x85, 0x66, 0x4a, 0x76, 0x56, 0x3a, 0x65, 0xac,
  0x4e, 0x76, 0x5a, 0x5b, 0x22, 0x05, 0xf7, 0x87,
  0x08, 0x30, 0x07, 0x0f, 0x6e, 0x9c, 0xca, 0x7d,
  0x08, 0xc3, 0xcd, 0x58, 0xea, 0xbc, 0x9e, 0xbd,
  0xcb, 0x08, 0x9e, 0xb4, 0x1a, 0xec, 0x94, 0x38,
  0x74, 0xdd, 0xc9, 0xc0, 0x8a, 0xd1, 0x9c, 0x16,
  0x73, 0xe4, 0x4a, 0xda, 0xe7, 0xdb, 0x92, 0xce,
  0x0b, 0x09, 0xe4, 0x98, 0x4e, 0xc5, 0x67, 0xe7,
  0xc2, 0x96, 0x91, 0xb2, 0xc8, 0x59, 0x55, 0x37,
  0x15, 0x61, 0xb7, 0xbc, 0x62, 0xb2, 0x64, 0x45,
  0x51, 0x72, 0x21, 0x14, 0xe7, 0xcd, 0x9d, 0x0b,
  0xa6, 0x14, 0x8e, 0x0b, 0xdf, 0xff, 0x53, 0x4f,
  0x08, 0xbd, 0x9b, 0xca, 0xfb, 0x5d, 0xf7, 0xdf,
  0xc6, 0xce, 0x1b, 0x6d, 0x6c, 0x62, 0x35, 0x6d,
  0x68, 0xcd, 0x29, 0xe3, 0x6b, 0x9c, 0x7d, 0xb3,
  0x1f, 0x6d, 0xb2, 0xb0, 0x6a, 0x1a, 0x01, 0x00,
  0x00
};

    auto encodings = um_available_encoding();

    struct res {
        std::string str;
        bool eof = false;
    } res;
    auto cb = [](void *ctx, const char *b, ssize_t len) {
        auto out = (struct res *)ctx;
        if (len > 0)
            out->str.append(b, len);

        if (len == UV_EOF) {
            out->eof = true;
        }
    };

    auto inflater = um_get_inflater("gzip", cb, &res);

    CHECK(um_inflate(inflater, (const char*)packet_bytes, sizeof(packet_bytes)) == -1);
    CHECK(um_inflate_state(inflater) == -1);
    um_free_inflater(inflater);
}
