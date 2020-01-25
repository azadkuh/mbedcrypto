#include <catch2/catch.hpp>

#include "mbedcrypto/binutils.hpp"

#include <vector>
#include <list>
#include <array>
//-----------------------------------------------------------------------------
namespace {
using namespace mbedcrypto;
//-----------------------------------------------------------------------------

// bin_edit_t checks {{{
// is copy constructible and movable
static_assert(std::is_nothrow_copy_constructible<bin_edit_t>::value, "");
static_assert(std::is_nothrow_move_constructible<bin_edit_t>::value, "");
static_assert(std::is_nothrow_copy_assignable<bin_edit_t>::value,    "");
static_assert(std::is_nothrow_move_assignable<bin_edit_t>::value,    "");
// valid pointer and size type
static_assert(std::is_nothrow_constructible<bin_edit_t, char*,    int>::value,         "");
static_assert(std::is_nothrow_constructible<bin_edit_t, uint8_t*, size_t>::value,      "");
static_assert(std::is_nothrow_constructible<bin_edit_t, unsigned char*, short>::value, "");
// valid containers
static_assert(std::is_nothrow_constructible<bin_edit_t, std::string&>::value,          "");
static_assert(std::is_nothrow_constructible<bin_edit_t, std::vector<uint8_t>&>::value, "");
static_assert(std::is_nothrow_constructible<bin_edit_t, std::array<char, 8>&>::value,  "");
// incompatible pointer or size type
static_assert(!std::is_nothrow_constructible<bin_edit_t, const char*, int>::value, "const");
static_assert(!std::is_nothrow_constructible<bin_edit_t, short*, size_t>::value,   "short is not single byte");
static_assert(!std::is_nothrow_constructible<bin_edit_t, void*,  size_t>::value,   "void is not valid byte type");
static_assert(!std::is_nothrow_constructible<bin_edit_t, char*,  float>::value,    "float is not integral");
// incompatible containers
static_assert(!std::is_nothrow_constructible<bin_edit_t, std::string>::value,         "only accepts a ref to container");
static_assert(!std::is_nothrow_constructible<bin_edit_t, std::string&&>::value,       "only accepts a ref to container");
static_assert(!std::is_nothrow_constructible<bin_edit_t, const std::string&>::value,  "not mutable container");
static_assert(!std::is_nothrow_constructible<bin_edit_t, std::wstring&>::value,       "wstring hasn't byte elements");
static_assert(!std::is_nothrow_constructible<bin_edit_t, std::vector<short>&>::value, "short");
static_assert(!std::is_nothrow_constructible<bin_edit_t, std::list<uint8_t>&>::value, "list is not supported");
// }}} bin_edit_t checks

//-----------------------------------------------------------------------------
// bin_view_t checks {{{
// is copy constructible and movable
static_assert(std::is_nothrow_copy_constructible<bin_view_t>::value, "");
static_assert(std::is_nothrow_move_constructible<bin_view_t>::value, "");
static_assert(std::is_nothrow_copy_assignable<bin_view_t>::value,    "");
static_assert(std::is_nothrow_move_assignable<bin_view_t>::value,    "");
// valid pointer and size type
static_assert(std::is_nothrow_constructible<bin_view_t, const char*,    int>::value,    "");
static_assert(std::is_nothrow_constructible<bin_view_t, const uint8_t*, size_t>::value, "");
static_assert(std::is_nothrow_constructible<bin_view_t, unsigned char*, short>::value,  "");
static_assert(std::is_constructible<bin_view_t, const char*>::value,                    "");
// valid containers
static_assert(std::is_nothrow_constructible<bin_view_t, bin_edit_t>::value,           "");
static_assert(std::is_nothrow_constructible<bin_view_t, std::string>::value,          "");
static_assert(std::is_nothrow_constructible<bin_view_t, std::string&>::value,         "");
static_assert(std::is_nothrow_constructible<bin_view_t, std::string&&>::value,        "");
static_assert(std::is_nothrow_constructible<bin_view_t, const std::string&>::value,   "");
static_assert(std::is_nothrow_constructible<bin_view_t, std::vector<uint8_t>>::value, "");
static_assert(std::is_nothrow_constructible<bin_view_t, std::array<char, 8>>::value,  "");
// incompatible pointer or size type
static_assert(!std::is_nothrow_constructible<bin_view_t, const short*, size_t>::value, "");
static_assert(!std::is_nothrow_constructible<bin_view_t, const void*,  size_t>::value, "");
static_assert(!std::is_nothrow_constructible<bin_view_t, const char*,  float>::value,  "");
// incompatible containers
static_assert(!std::is_nothrow_constructible<bin_view_t, std::wstring>::value,         "");
static_assert(!std::is_nothrow_constructible<bin_view_t, std::vector<short>>::value,   "");
static_assert(!std::is_nothrow_constructible<bin_view_t, std::list<uint8_t>>::value,   "");
/// }}} bin_view_checks

//-----------------------------------------------------------------------------
// auto_size_t checks {{{
// is not copy constructible nor movable
static_assert(!std::is_copy_constructible<auto_size_t>::value, "");
static_assert(!std::is_move_constructible<auto_size_t>::value, "");
static_assert(!std::is_copy_assignable<auto_size_t>::value,    "");
static_assert(!std::is_move_assignable<auto_size_t>::value,    "");
// valid containers
static_assert(std::is_constructible<auto_size_t, std::string&>::value,          "");
static_assert(std::is_constructible<auto_size_t, std::vector<uint8_t>&>::value, "");
static_assert(std::is_constructible<auto_size_t, std::vector<char>&>::value,    "");
// bad containers
static_assert(!std::is_nothrow_constructible<auto_size_t, std::string&>::value,   "ctor may throw");
static_assert(!std::is_constructible<auto_size_t, std::string>::value,            "only accepts reference");
static_assert(!std::is_constructible<auto_size_t, std::string&&>::value,          "only accepts reference");
static_assert(!std::is_constructible<auto_size_t, const std::string&>::value,     "reference must be mutable");
static_assert(!std::is_constructible<auto_size_t, std::array<char, 8>&>::value,   "not resizable");
static_assert(!std::is_constructible<auto_size_t, std::wstring&>::value,          "not a single-byte container");
static_assert(!std::is_constructible<auto_size_t, std::vector<int>&>::value,      "not a single-byte container");
static_assert(!std::is_constructible<auto_size_t, std::list<uint8_t>&>::value,    "has not operator[]()");
// default constructors
static_assert(!std::is_constructible<auto_size_t>::value,                "not default constructible");
static_assert(!std::is_constructible<auto_size_t, char*, size_t>::value, "only accepts a container");
// }}} auto_size_t checks

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

TEST_CASE("binary view", "[binutils]") {
    SECTION("empty") {
        bin_view_t empty{};
        REQUIRE(is_empty(empty));
        REQUIRE(empty.data == nullptr);
        REQUIRE(empty.size == 0);

        const char* temp = nullptr;
        REQUIRE(is_empty(bin_view_t{temp, 12}));
        char buff[8] = {0};
        REQUIRE(is_empty(bin_view_t{buff, 0}));
        REQUIRE_FALSE(is_empty(bin_view_t{buff, 4}));
    }
    SECTION("iterators") {
        bin_view_t src{"0123456789"};
        char i = 0;
        for (const auto& u : src) {
            REQUIRE(u == i + '0');
            ++i;
        }
        REQUIRE(i == 10);
    }
    SECTION("comparison") {
        std::array<char, 32> arr;
        for (size_t i = 0; i < arr.size(); ++i)
           arr[i] = i % 10; // also includes some null bytes

        bin_view_t  bin{arr};
        REQUIRE(bin.size == arr.size());

        std::string str{arr.data(), arr.size()};
        REQUIRE(str.size() == arr.size());

        REQUIRE(str == bin);
        REQUIRE(bin == str);
    }
}

TEST_CASE("binary edit", "[binutils]") {
    SECTION("string") {
        constexpr char Name[] = "mbedcrypto";
        std::string s;
        auto_size_t ob{s};
        ob.resize(std::strlen(Name));
        std::memcpy(ob.data, Name, ob.size);
        REQUIRE(s == Name);
        REQUIRE(bin_view_t{ob} == Name);
    }
    SECTION("binary") {
        std::vector<uint8_t> v;
        auto_size_t ob{v};
        ob.resize(8);
        for (size_t i = 0; i < 8; ++i)
            ob.data[i] = static_cast<uint8_t>(i);
        REQUIRE(v == std::vector<uint8_t>{0, 1, 2, 3, 4, 5, 6, 7});
        REQUIRE(bin_view_t{ob} == std::vector<uint8_t>{0, 1, 2, 3, 4, 5, 6, 7});
    }
}
