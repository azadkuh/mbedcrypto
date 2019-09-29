#include <catch2/catch.hpp>

#include "generator.hpp"
#include "mbedcrypto/tcodec.hpp"

#include <iostream>
///////////////////////////////////////////////////////////////////////////////
namespace {
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////
template <class Func>
void
try_func(Func&& f) {
    try {
        f();

    } catch (exception& err) {
        std::cerr << err.what() << "\n";
        FAIL("throws");

    } catch (std::exception& err) {
        std::cerr << err.what() << "\n";
        FAIL("throws");
    }
}

// of test::short_binary()
const char Hex[] = "68404c76377188143ae9673f9413dadd"
                   "03809d3100ffd778baac90f0a30ec0ca"
                   "714fe42348f23e5d8563fb626708f577"
                   "0025f62c74107759dfb218";

const char*
short_text_base64() { // test::short_text()
    return "bWJlZHRscyBjcnlwdG9ncmFwaHk=";
}

const char*
long_text_base64() { // of test::long_text()
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

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

TEST_CASE("hex tests", "[hex]") {
    using namespace mbedcrypto;

    SECTION("to hex") {
        const buffer_t binary = test::short_binary();
        const buffer_t hex(Hex);

        REQUIRE(to_hex(binary) == hex);
    }

    SECTION("from hex") {
        const buffer_t binary = test::short_binary();
        const buffer_t hex(Hex);

        REQUIRE(from_hex(hex) == binary);
        // overload without exception
        bool ok    = false;
        auto unhex = from_hex(hex, ok);
        REQUIRE(ok);
        REQUIRE(unhex == binary);

        const buffer_t inv_char("03fe65ds35"); // s is invalid
        REQUIRE_THROWS(from_hex(inv_char));
        // overload without exception
        unhex = from_hex(inv_char, ok);
        REQUIRE_FALSE(ok);
        REQUIRE(unhex.empty());

        const buffer_t inv_size("0a347535fa1"); // size is invalid
        REQUIRE_THROWS(from_hex(inv_size));
        // overload without exception
        unhex = from_hex(inv_size, ok);
        REQUIRE_FALSE(ok);
        REQUIRE(unhex.empty());
    }
}

TEST_CASE("base64 test cases", "[base64]") {
    using namespace mbedcrypto;

    SECTION("size test") {
        try_func([]() {
            const buffer_t src(test::short_text());
            const buffer_t predef(short_text_base64());

            size_t size = base64::encode_size(src);
            INFO("endoce size: " << size << " != " << predef.size());
            REQUIRE((size - 1 == predef.size()));

            size = base64::decode_size(predef);
            INFO("decode size: " << size << " != " << src.size());
            REQUIRE(size == src.size());
        });
    }

    SECTION("encode / decode") {
        try_func([]() {
            const buffer_t src(test::short_text());
            const buffer_t predef(short_text_base64());

            const auto encoded = to_base64(src);
            REQUIRE(encoded == predef);

            auto decoded = from_base64(encoded);
            REQUIRE(decoded == src);
            // overload without exception
            bool ok = false;
            decoded = from_base64(encoded, ok);
            REQUIRE(ok);
            REQUIRE(decoded == src);
        });
    }

    SECTION("invalid base64") {
        const buffer_t invalid_base64("2K=fZhduM2LEg2LLZhdin2YbbjA==");
        REQUIRE_THROWS(base64::decode(invalid_base64));
        // overload without exception
        bool ok    = false;
        auto plain = from_base64(invalid_base64, ok);
        REQUIRE_FALSE(ok);
        REQUIRE(plain.empty());
    }

    SECTION("reuse") {
        try_func([]() {
            const buffer_t src_short(test::short_text());
            const buffer_t predef_short(short_text_base64());
            const buffer_t src_long(test::long_text());
            const buffer_t predef_long(long_text_base64());

            buffer_t encoded, decoded;

            base64::encode(src_short, encoded);
            REQUIRE(encoded == predef_short);
            base64::decode(encoded, decoded);
            REQUIRE(decoded == src_short);
            auto cap_enc1 = encoded.capacity();
            auto cap_dec1 = decoded.capacity();

            base64::encode(src_long, encoded);
            REQUIRE(encoded == predef_long);
            base64::decode(encoded, decoded);
            REQUIRE(decoded == src_long);
            auto cap_enc2 = encoded.capacity();
            auto cap_dec2 = decoded.capacity();
            REQUIRE((cap_enc1 < cap_enc2 && cap_dec1 < cap_dec2));

            base64::encode(src_short, encoded);
            REQUIRE(encoded == predef_short);
            base64::decode(encoded, decoded);
            REQUIRE(decoded == src_short);
            auto cap_enc3 = encoded.capacity();
            auto cap_dec3 = decoded.capacity();
            REQUIRE((cap_enc2 == cap_enc3 && cap_dec2 == cap_dec3));
        });
    }

    SECTION("binary tests") {
        const buffer_t src        = test::long_binary();
        size_t         bin_length = src.size();

        const auto encoded = to_base64(src);
        REQUIRE(encoded.size() > bin_length);

        auto decoded = from_base64(encoded);
        REQUIRE(decoded.size() == src.size());
        REQUIRE(decoded == src);
        // overload without exception
        bool ok = false;
        decoded = from_base64(encoded, ok);
        REQUIRE(ok);
        REQUIRE(decoded.size() == src.size());
        REQUIRE(decoded == src);
    }
}
