#include "mbedcrypto/text_codec.hpp"
#include "mbedcrypto/errors.hpp"

#include <mbedtls/base64.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
//-----------------------------------------------------------------------------

constexpr inline uint8_t
hex_lower(uint8_t u) noexcept {
    return static_cast<uint8_t>("0123456789abcdef"[u & 0x0f]);
}

inline std::error_code
base64_error(int ret) noexcept {
    if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
        return make_error_code(error_t::small_output);
    else if (ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER)
        return make_error_code(error_t::bad_input);
    return mbedtls::make_error_code(ret);
}

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

std::error_code
to_hex(bin_edit_t& output, bin_view_t input) noexcept {
    if (is_empty(input))
        return make_error_code(error_t::empty_input);

    const auto capacity = output.size;
    output.size         = (input.size << 1) + 1; // inlcude null-terminator

    if (output.data == nullptr || capacity == 0) {
    } else if (capacity < output.size) {
        return make_error_code(error_t::small_output);
    } else {
        for (size_t i = 0; i < input.size; ++i) {
            output.data[i << 1]       = hex_lower(input.data[i] >> 4);
            output.data[(i << 1) + 1] = hex_lower(input.data[i] & 0x0f);
        }
        output.data[--output.size] = 0; // null-terminate
    }

    return std::error_code{};
}

std::error_code
to_hex(auto_size_t&& output, bin_view_t input) {
    bin_edit_t expected;
    auto       ec = to_hex(expected, input);
    if (ec)
        return ec;
    output.resize(expected.size);
    ec = to_hex(static_cast<bin_edit_t&>(output), input);
    if (output.size && !ec) // remove null-terminator
        output.resize(output.size);
    return ec;
}

std::error_code
from_hex(bin_edit_t& output, bin_view_t input) noexcept {
    if (is_empty(input))
        return make_error_code(error_t::empty_input);
    else if ((input.size & 0x1) == 1) // len must be even
        return make_error_code(error_t::bad_input);

    const auto capacity = output.size;
    output.size         = input.size >> 1;

    if (output.data == nullptr || capacity == 0) {
    } else if (capacity < output.size) {
        return make_error_code(error_t::small_output);
    } else {
        const auto* src = reinterpret_cast<const char*>(input.data);
        for (size_t i = 0; i < input.size; ++i, ++src) {
            char ch = *src;
            if (ch >= '0' && ch <= '9')
                ch -= '0';
            else if (ch >= 'A' && ch <= 'F')
                ch -= '7'; // 'A' - 10
            else if (ch >= 'a' && ch <= 'f')
                ch -= 'W'; // 'a' - 10
            else {
                output.size = i >> 1; // bytes have been decoded so far
                return make_error_code(error_t::bad_input);
            }
            auto& des = output.data[i >> 1];
            des       = (i & 1) ? (des + ch) : (ch << 4);
        }
    }

    return std::error_code{};
}

std::error_code
from_hex(auto_size_t&& output, bin_view_t input) {
    bin_edit_t expected;
    auto ec = from_hex(expected, input);
    if (ec)
        return ec;
    output.resize(expected.size);
    return from_hex(static_cast<bin_edit_t&>(output), input);
}

//-----------------------------------------------------------------------------

std::error_code
to_base64(bin_edit_t& output, bin_view_t input) noexcept {
    int ret = 0;
    if (output.data == nullptr || output.size == 0) {
        ret = mbedtls_base64_encode(
            nullptr, 0, &output.size, input.data, input.size);
        if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
            ret = 0; // it's ok as we intentionally passed a nullptr output
    } else {
        size_t olen = 0;
        ret         = mbedtls_base64_encode(
            output.data, output.size, &olen, input.data, input.size);
        output.size = olen;
    }
    return (ret != 0) ? base64_error(ret) : std::error_code{};
}

std::error_code
to_base64(auto_size_t&& output, bin_view_t input) {
    bin_edit_t expected;
    auto ec = to_base64(expected, input);
    if (ec)
        return ec;
    output.resize(expected.size);
    ec = to_base64(static_cast<bin_edit_t&>(output), input);
    if (output.size && !ec) // remove null-terminator
        output.resize(output.size);
    return ec;
}

std::error_code
from_base64(bin_edit_t& output, bin_view_t input) noexcept {
    int ret = 0;
    if (output.data == nullptr || output.size == 0) {
        ret = mbedtls_base64_decode(
            nullptr, 0, &output.size, input.data, input.size);
        if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
            ret = 0; // it's ok as we intentionally passed a nullptr output
    } else {
        size_t olen = 0;
        ret         = mbedtls_base64_decode(
            output.data, output.size, &olen, input.data, input.size);
        output.size = olen;
    }
    return (ret != 0) ? base64_error(ret) : std::error_code{};
}

std::error_code
from_base64(auto_size_t&& output, bin_view_t input) {
    bin_edit_t expected;
    auto ec = from_base64(expected, input);
    if (ec)
        return ec;
    output.resize(expected.size);
    return from_base64(static_cast<bin_edit_t&>(output), input);
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
