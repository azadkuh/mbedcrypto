#include <catch.hpp>

#include "mbedcrypto/base64.hpp"
#include <iostream>
///////////////////////////////////////////////////////////////////////////////
namespace {
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////
template<class Func> void
try_func(Func&& f) {
    try {
        f();

    } catch ( exception& err ) {
        std::cerr << err.to_string() << "\n";
        FAIL("throws");

    } catch ( std::exception& err ) {
        std::cerr << err.what() << "\n";
        FAIL("throws");
    }
}

const char*
short_text() {
    return "mbedtls cryptography";
}

const char*
short_text_base64() {
    return "bWJlZHRscyBjcnlwdG9ncmFwaHk=";
}

const char*
long_text() {
    return "Lorem ipsum dolor sit amet, consectetur adipiscing elit,"
        " sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
        " Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris"
        " nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in"
        " reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur."
        " Excepteur sint occaecat cupidatat non proident,"
        " sunt in culpa qui officia deserunt mollit anim id est laborum.";
}

const char*
long_text_base64() {
    return "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np"
        "bmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3J"
        "lIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVuaWFtLC"
        "BxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0I"
        "GFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBk"
        "b2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx"
        "1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludC"
        "BvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1a"
        "SBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==";
}
// with many possible null bytes in the middle
const unsigned char Binary[] = {
    0xf3, 0x1b, 0x00, 0xa1, 0x98, 0xbf, 0xd0, 0xe9,
    0xf6, 0x2a, 0xea, 0x28, 0xe0, 0x53, 0xc7, 0x69,
    0xee, 0xdf, 0x81, 0x00, 0x00, 0xb0, 0x67, 0x00,
    0x67, 0xf5, 0xf1, 0xec, 0xff, 0x8e, 0x8d, 0xfe,
    0xe3, 0x5a, 0xc8, 0xb2, 0xd3, 0xdc, 0xe6, 0x9d,
    0xa2, 0x1f, 0x4e, 0xa6, 0x9b, 0xb2, 0xf0, 0xb8,
    0x89, 0xa6, 0x4d, 0xb8, 0xe5, 0x88, 0x22, 0xa4,
    0xc9, 0xec, 0x69, 0xc7, 0x8e, 0x2c, 0x24, 0x04,
    0x29, 0x07, 0xb9, 0x00, 0x32, 0x21, 0x12, 0xab,
    0x18, 0x9a, 0xaf, 0xdb, 0xdb, 0x75, 0x77, 0xd0,
    0x23, 0x37, 0xa3, 0xa9, 0xe6, 0xd0, 0xe3, 0x35,
    0x13, 0x2b, 0x24, 0xf5, 0xe6, 0xe9, 0x74, 0x5f,
    0xb7, 0x08, 0x33, 0x97, 0xb1, 0x75, 0xf9, 0x1c,
    0xea, 0x3a, 0xcb, 0xdf, 0x58, 0x73, 0x35, 0x9a,
    0x6a, 0x12, 0xc1, 0x07, 0x0a, 0x59, 0x40, 0xfa,
    0xb4, 0xb7, 0xc8, 0x6d, 0xab, 0x63, 0x00, 0x8b,
};
///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

TEST_CASE("base64 test cases", "[base64]") {
    using namespace mbedcrypto;

    SECTION("size test") {
        try_func([]() {
            const buffer_t src(short_text());
            const buffer_t predef(short_text_base64());

            size_t size = base64::encode_size(src);
            INFO("endoce size: " << size << " != " << predef.size());
            REQUIRE( (size - 1 == predef.size()) );

            size = base64::decode_size(predef);
            INFO("decode size: " << size << " != " << src.size());
            REQUIRE( size == src.size() );
        });
    }

    SECTION("encode / decode") {
        try_func([]() {
            const buffer_t src(short_text());
            const buffer_t predef(short_text_base64());

            auto encoded = to_base64(src);
            REQUIRE( encoded == predef );

            auto decoded = from_base64(encoded);
            REQUIRE( decoded == src );
        });
    }

    SECTION("invalid base64") {
        const buffer_t invalid_base64("2K=fZhduM2LEg2LLZhdin2YbbjA==");
        REQUIRE_THROWS( base64::decode(invalid_base64) );
    }

    SECTION("reuse") {
        try_func([]() {
            const buffer_t src_short(short_text());
            const buffer_t predef_short(short_text_base64());
            const buffer_t src_long(long_text());
            const buffer_t predef_long(long_text_base64());

            buffer_t encoded, decoded;

            base64::encode(src_short, encoded);
            REQUIRE( encoded == predef_short );
            base64::decode(encoded, decoded);
            REQUIRE( decoded == src_short );
            auto cap_enc1 = encoded.capacity();
            auto cap_dec1 = decoded.capacity();

            base64::encode(src_long, encoded);
            REQUIRE( encoded == predef_long );
            base64::decode(encoded, decoded);
            REQUIRE( decoded == src_long );
            auto cap_enc2 = encoded.capacity();
            auto cap_dec2 = decoded.capacity();
            REQUIRE( (cap_enc1 < cap_enc2  &&  cap_dec1 < cap_dec2) );

            base64::encode(src_short, encoded);
            REQUIRE( encoded == predef_short );
            base64::decode(encoded, decoded);
            REQUIRE( decoded == src_short );
            auto cap_enc3 = encoded.capacity();
            auto cap_dec3 = decoded.capacity();
            REQUIRE( (cap_enc2 == cap_enc3  &&  cap_dec2 == cap_dec3) );
        });
    }

    SECTION("binary tests") {
        constexpr size_t bin_length = sizeof(Binary);
        const buffer_t src(reinterpret_cast<const char*>(Binary), bin_length);
        REQUIRE( src.size() == bin_length);

        auto encoded = to_base64(src);
        REQUIRE( encoded.size() > bin_length );

        auto decoded = from_base64(encoded);
        REQUIRE( decoded.size() == src.size() );
        REQUIRE( decoded == src );
    }
}
