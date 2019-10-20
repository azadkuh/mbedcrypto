#include <catch2/catch.hpp>

#include "./helper.hpp"
#include "mbedcrypto/text_codec.hpp"

#include <array>
#include <iostream>
//-----------------------------------------------------------------------------
namespace {
using namespace mbedcrypto;
//-----------------------------------------------------------------------------

// of test::short_binary()
constexpr char HexShortBin[] =
    "68404c76377188143ae9673f9413dadd"
    "03809d3100ffd778baac90f0a30ec0ca"
    "714fe42348f23e5d8563fb626708f577"
    "0025f62c74107759dfb218";

// of test::short_text()
constexpr char Base64ShortText[] =
    "bWJlZHRscyBjcnlwdG9ncmFwaHk=";

// of test::long_text()
constexpr char Base64LongText[] =
    "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np"
    "bmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3J"
    "lIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVuaWFtLC"
    "BxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0I"
    "GFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBk"
    "b2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx"
    "1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludC"
    "BvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1a"
    "SBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==";

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

TEST_CASE("hex tests", "[hex]") {
    SECTION("empty inputs") {
        size_t osize = 0;
        auto ec = to_hex(bin_view_t{}, nullptr, osize);
        REQUIRE(ec == make_error_code(error_t::empty_input));
        ec = from_hex(bin_view_t{}, nullptr, osize);
        REQUIRE(ec == make_error_code(error_t::empty_input));
    }

    SECTION("find output size") {
        size_t osize = 0;
        SECTION("to_hex") {
            auto ec = to_hex(test::short_binary(), nullptr, osize);
            REQUIRE_FALSE(ec);
            REQUIRE(osize == test::short_binary().size * 2 + 1); // null-terminator
        }
        SECTION("from_hex") {
            auto ec = from_hex(HexShortBin, nullptr, osize);
            REQUIRE_FALSE(ec);
            REQUIRE(osize * 2 == std::strlen(HexShortBin));
        }
    }

    SECTION("small output buffer") {
        std::array<char, 16> output;
        size_t osize = output.size();
        SECTION("to_hex") {
            auto ec = to_hex(test::short_binary(), &output[0], osize);
            REQUIRE(ec    == make_error_code(error_t::small_output));
            REQUIRE(osize == sizeof(HexShortBin)); // null-terminator
        }
        SECTION("from_hex") {
            auto ec = from_hex(HexShortBin, reinterpret_cast<uint8_t*>(&output[0]), osize);
            REQUIRE(ec    == make_error_code(error_t::small_output));
            REQUIRE(osize == test::short_binary().size);
        }
    }

    SECTION("invalid hex size") {
        std::array<uint8_t, 16> output;
        output.fill(0);
        size_t osize = output.size();
        SECTION("bad size") {
            auto ec = from_hex("badc0de", &output[0], osize); // invalid size: not even size
            REQUIRE(ec == make_error_code(error_t::bad_input));
        }
        SECTION("bad char") {
            auto ec = from_hex("abadcode", &output[0], osize); // invalid char: o
            REQUIRE(ec        == make_error_code(error_t::bad_input));
            REQUIRE(osize     == 2); // 2 proper decoding
            REQUIRE(output[0] == 0xab);
            REQUIRE(output[1] == 0xad);
            REQUIRE(output[2] == 0xc0); // where the error happens
            REQUIRE(output[3] == 0x00);
        }
    }

    SECTION("proper conversion") {
        std::string output;
        SECTION("to_hex") {
            auto ec = to_hex(output, test::short_binary());
            REQUIRE_FALSE(ec); // no error
            REQUIRE(output == HexShortBin);
        }
        SECTION("from_hex") {
            auto ec = from_hex(output, HexShortBin);
            REQUIRE_FALSE(ec);
            REQUIRE(output.size() == test::short_binary().size);
            REQUIRE(output == test::short_binary());
        }
    }
}

TEST_CASE("base64 tests", "[base64]") {
    SECTION("empty inputs") {
        const bin_view_t empty{};
        auto e = to_base64(empty);
        REQUIRE_FALSE(e.second);
        REQUIRE(e.first.empty());
        auto d = from_base64(empty);
        REQUIRE_FALSE(e.second);
        REQUIRE(e.first.empty());
    }

    SECTION("find output size") {
        size_t osize = 0;
        SECTION("to_base64") {
            auto ec = to_base64(test::short_text(), nullptr, osize);
            REQUIRE_FALSE(ec);
            REQUIRE(osize == sizeof(Base64ShortText)); // both include null-terminator
        }
        SECTION("from_base64") {
            auto ec = from_base64(Base64ShortText, nullptr, osize);
            REQUIRE_FALSE(ec);
            REQUIRE(osize == std::strlen(test::short_text()));
        }
    }

    SECTION("small output buffer") {
        SECTION("to_base64") {
            std::array<char, 8> small;
            size_t osize = small.size();
            auto ec = to_base64(test::short_text(), &small[0], osize);
            REQUIRE(ec    == make_error_code(error_t::small_output));
            REQUIRE(osize == sizeof(Base64ShortText)); // both include null-terminator
        }
        SECTION("from_base64") {
            std::array<uint8_t, 4> small;
            size_t osize = small.size();
            auto ec = from_base64(Base64ShortText, &small[0], osize);
            REQUIRE(ec    == make_error_code(error_t::small_output));
            REQUIRE(osize == std::strlen(test::short_text()));
        }
    }

    SECTION("invalid base64 input") {
        constexpr char SillyInput[] = "(.)<==>(.)";
        SECTION("raw api") {
            std::array<uint8_t, 64> arr;
            size_t osize = arr.size();
            auto ec = from_base64(SillyInput, &arr[0], osize);
            REQUIRE(ec    == make_error_code(error_t::bad_input));
            REQUIRE(osize == 0);
        }
        SECTION("container") {
            std::vector<uint8_t> vec;
            auto ec = from_base64(vec, SillyInput);
            REQUIRE(ec == make_error_code(error_t::bad_input));
            REQUIRE(vec.empty());
        }
        SECTION("pair results") {
            auto p = from_base64(SillyInput);
            REQUIRE(p.second == make_error_code(error_t::bad_input));
            REQUIRE(p.first.empty());
        }
    }

    SECTION("encoding/decoding") {
        SECTION("to_base64") {
            std::vector<char> vec;
            auto ec = to_base64(vec, test::long_text());
            REQUIRE_FALSE(ec);
            const auto osize = std::strlen(Base64LongText);
            REQUIRE(vec.size() == osize);
            //REQUIRE(std::equal(vec.cbegin(), vec.cend(), Base64LongText, Base64LongText + osize));

            auto p = to_base64(test::long_text());
            REQUIRE_FALSE(p.second);
            REQUIRE(p.first == Base64LongText);
        }
        SECTION("from_base64") {
            auto p = from_base64(Base64LongText);
            REQUIRE_FALSE(p.second);
            REQUIRE(p.first == test::long_text());
        }
    }
}

