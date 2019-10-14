#include "mbedcrypto/binutils.hpp"

#include <vector>
#include <array>

//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
//-----------------------------------------------------------------------------

struct bad_resize {
    int resize();
    void resize(const std::string&);
};

struct good_resize {
    void resize(size_t);
};

static_assert(has_resize_mfn<std::string>::value,         "");
static_assert(has_resize_mfn<std::vector<int>>::value,    "");
static_assert(has_resize_mfn<good_resize>::value,         "");
static_assert(!has_resize_mfn<std::array<int, 8>>::value, "");
static_assert(!has_resize_mfn<bad_resize>::value,         "");

//-----------------------------------------------------------------------------

struct bad_buffer_1 {
    char operator[](size_t) noexcept;   // return type is not a reference
};
struct bad_buffer_2 {
    short& operator[](size_t) noexcept; // sizeof(short) != 1
};
struct bad_buffer_3 {
    const char& operator[](size_t) noexcept; // return type is not writable
};
struct good_buffer {
    uint8_t& operator[](size_t) noexcept;
};

static_assert(!has_writable_buffer<bad_buffer_1>::value, "");
static_assert(!has_writable_buffer<bad_buffer_2>::value, "");
static_assert(!has_writable_buffer<bad_buffer_3>::value, "");

static_assert(!has_writable_buffer<std::wstring>::value,        "");
static_assert(!has_writable_buffer<std::vector<short>>::value,  "");
static_assert(!has_writable_buffer<const std::string>::value,   "");

static_assert(has_writable_buffer<good_buffer>::value,          "");
static_assert(has_writable_buffer<std::string>::value,          "");
static_assert(has_writable_buffer<std::vector<uint8_t>>::value, "");
static_assert(has_writable_buffer<std::array<char, 8>>::value,  "");

//-----------------------------------------------------------------------------

static_assert(is_output_container<std::string>::value,          "");
static_assert(is_output_container<std::vector<uint8_t>>::value, "");

static_assert(!is_output_container<std::wstring>::value,        "");
static_assert(!is_output_container<std::vector<short>>::value,  "");
static_assert(!is_output_container<const std::string>::value,   "");
static_assert(!is_output_container<std::array<char, 8>>::value, "");

//-----------------------------------------------------------------------------
} // namespace anon
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
