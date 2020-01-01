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
        bin_edit_t output;
        auto ec = to_hex(output, bin_view_t{});
        REQUIRE(ec == make_error_code(error_t::empty_input));
        ec = from_hex(output, bin_view_t{});
        REQUIRE(ec == make_error_code(error_t::empty_input));
    }

    SECTION("find output size") {
        bin_edit_t output;
        SECTION("to_hex") {
            auto ec = to_hex(output, test::short_binary());
            REQUIRE_FALSE(ec); // to find the required size
            REQUIRE(output.size == test::short_binary().size * 2 + 1); // null-terminator
        }
        SECTION("from_hex") {
            auto ec = from_hex(output, HexShortBin);
            REQUIRE_FALSE(ec);
            REQUIRE(output.size * 2 == std::strlen(HexShortBin));
        }
    }

    SECTION("small output buffer") {
        std::array<char, 16> output;
        bin_edit_t wrapper{output};
        SECTION("to_hex") {
            auto ec = to_hex(wrapper, test::short_binary());
            REQUIRE(ec           == make_error_code(error_t::small_output));
            REQUIRE(wrapper.size == sizeof(HexShortBin)); // null-terminator
        }
        SECTION("from_hex") {
            auto ec = from_hex(wrapper, HexShortBin);
            REQUIRE(ec           == make_error_code(error_t::small_output));
            REQUIRE(wrapper.size == test::short_binary().size);
        }
    }

    SECTION("invalid hex size") {
        std::array<uint8_t, 16> output;
        output.fill(0);
        bin_edit_t wrapper{output};
        SECTION("bad size") {
            auto ec = from_hex(wrapper, "badc0de"); // invalid size: not even size
            REQUIRE(ec == make_error_code(error_t::bad_input));
        }
        SECTION("bad char") {
            auto ec = from_hex(wrapper, "abadcode"); // invalid char: o
            REQUIRE(ec           == make_error_code(error_t::bad_input));
            REQUIRE(wrapper.size == 2); // 2 proper decoding
            REQUIRE(output[0]    == 0xab);
            REQUIRE(output[1]    == 0xad);
            REQUIRE(output[2]    == 0xc0); // where the error happens
            REQUIRE(output[3]    == 0x00);
        }
    }

    SECTION("proper conversion") {
        std::string output;
        SECTION("to_hex") {
            auto ec = to_hex(auto_size_t{output}, test::short_binary());
            REQUIRE_FALSE(ec); // no error
            REQUIRE(output == HexShortBin);
        }
        SECTION("from_hex") {
            auto ec = from_hex(auto_size_t{output}, HexShortBin);
            REQUIRE_FALSE(ec);
            REQUIRE(output.size() == test::short_binary().size);
            REQUIRE(output == test::short_binary());
        }
    }
}

TEST_CASE("base64 tests", "[base64]") {
    SECTION("empty inputs") {
        const bin_view_t empty{};
        auto e = to_base64<std::string>(empty);
        REQUIRE_FALSE(e.second);
        REQUIRE(e.first.empty());
        auto d = from_base64<std::vector<uint8_t>>(empty);
        REQUIRE_FALSE(e.second);
        REQUIRE(e.first.empty());
    }

    SECTION("find output size") {
        bin_edit_t output;
        SECTION("to_base64") {
            auto ec = to_base64(output, test::short_text());
            REQUIRE_FALSE(ec);
            REQUIRE(output.size == sizeof(Base64ShortText)); // both include null-terminator
        }
        SECTION("from_base64") {
            auto ec = from_base64(output, Base64ShortText);
            REQUIRE_FALSE(ec);
            REQUIRE(output.size == std::strlen(test::short_text()));
        }
    }

    SECTION("small output buffer") {
        SECTION("to_base64") {
            std::array<char, 8> small;
            bin_edit_t wrapper{small};
            auto ec = to_base64(wrapper, test::short_text());
            REQUIRE(ec           == make_error_code(error_t::small_output));
            REQUIRE(wrapper.size == sizeof(Base64ShortText)); // both include null-terminator
        }
        SECTION("from_base64") {
            std::array<uint8_t, 4> small;
            bin_edit_t wrapper{small};
            auto ec = from_base64(wrapper, Base64ShortText);
            REQUIRE(ec           == make_error_code(error_t::small_output));
            REQUIRE(wrapper.size == std::strlen(test::short_text()));
        }
    }

    SECTION("invalid base64 input") {
        constexpr char SillyInput[] = "(.)<==>(.)";
        SECTION("raw api") {
            std::array<uint8_t, 64> arr;
            bin_edit_t wrapper{arr};
            auto ec = from_base64(wrapper, SillyInput);
            REQUIRE(ec           == make_error_code(error_t::bad_input));
            REQUIRE(wrapper.size == 0);
        }
        SECTION("container") {
            std::vector<uint8_t> vec;
            auto ec = from_base64(auto_size_t{vec}, SillyInput);
            REQUIRE(ec == make_error_code(error_t::bad_input));
            REQUIRE(vec.empty());
        }
        SECTION("pair results") {
            auto p = from_base64<std::string>(SillyInput);
            REQUIRE(p.second == make_error_code(error_t::bad_input));
            REQUIRE(p.first.empty());
        }
    }

    SECTION("encoding/decoding") {
        SECTION("to_base64") {
            std::vector<char> vec;
            auto ec = to_base64(auto_size_t{vec}, test::long_text());
            REQUIRE_FALSE(ec);
            const auto osize = std::strlen(Base64LongText);
            REQUIRE(vec.size() == osize);
            REQUIRE(std::equal(vec.cbegin(), vec.cend(), Base64LongText, Base64LongText + osize));

            auto p = to_base64<std::string>(test::long_text());
            REQUIRE_FALSE(p.second);
            REQUIRE(p.first == Base64LongText);
        }
        SECTION("from_base64") {
            auto p = from_base64<std::string>(Base64LongText);
            REQUIRE_FALSE(p.second);
            REQUIRE(p.first == test::long_text());
        }
    }
}

