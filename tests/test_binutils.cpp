#include <catch2/catch.hpp>

#include "mbedcrypto/binutils.hpp"

#include <vector>
#include <list>
#include <array>
//-----------------------------------------------------------------------------
namespace {
using namespace mbedcrypto;
//-----------------------------------------------------------------------------
// valid pointer and size type
static_assert(std::is_nothrow_constructible<bin_view_t, const char*,    int>::value,    "");
static_assert(std::is_nothrow_constructible<bin_view_t, const uint8_t*, size_t>::value, "");
static_assert(std::is_nothrow_constructible<bin_view_t, unsigned char*, short>::value,  "");

static_assert(std::is_constructible<bin_view_t, const char*>::value,  "");

// incompatible pointer or size type
static_assert(!std::is_nothrow_constructible<bin_view_t, const short*, size_t>::value, "");
static_assert(!std::is_nothrow_constructible<bin_view_t, const void*,  size_t>::value, "");
static_assert(!std::is_nothrow_constructible<bin_view_t, const char*,  float>::value,  "");

// valid containers
static_assert(std::is_nothrow_constructible<bin_view_t,  std::string>::value,          "");
static_assert(std::is_nothrow_constructible<bin_view_t,  std::vector<uint8_t>>::value, "");
static_assert(std::is_nothrow_constructible<bin_view_t,  std::array<char, 8>>::value,  "");

// incompatible containers
static_assert(!std::is_nothrow_constructible<bin_view_t, std::wstring>::value,         "");
static_assert(!std::is_nothrow_constructible<bin_view_t, std::vector<short>>::value,   "");
static_assert(!std::is_nothrow_constructible<bin_view_t, std::list<uint8_t>>::value,   "");

// is copy constructible and movable
static_assert(std::is_nothrow_copy_constructible<bin_view_t>::value, "");
static_assert(std::is_nothrow_move_constructible<bin_view_t>::value, "");

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

TEST_CASE("binary utils", "[binutils]") {
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
}
