#include "mbedcrypto/text_codec.hpp"
#include "mbedcrypto/errors.hpp"

#include <mbedtls/base64.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
//-----------------------------------------------------------------------------

constexpr inline char
hex_lower(uint8_t u) noexcept {
    return "0123456789abcdef"[u & 0x0f];
}

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

std::error_code
to_hex(bin_view_t input, char* output, size_t& osize) noexcept {
    if (is_empty(input))
        return make_error_code(error_t::empty_input);

    const auto capacity = osize;
    osize               = (input.size << 1) + 1; // inlcude null-terminator

    if (output == nullptr || capacity == 0) {
    } else if (capacity < osize) {
        return make_error_code(error_t::small_output);
    } else {
        for (size_t i = 0; i < input.size; ++i) {
            output[i << 1]       = hex_lower(input.data[i] >> 4);
            output[(i << 1) + 1] = hex_lower(input.data[i] & 0x0f);
        }
        output[--osize] = 0; // null-terminate
    }

    return std::error_code{};
}

std::error_code
from_hex(bin_view_t input, uint8_t* output, size_t& osize) noexcept {
    if (is_empty(input))
        return make_error_code(error_t::empty_input);
    else if ((input.size & 0x1) == 1) // len must be even
        return make_error_code(error_t::bad_input);

    const auto capacity = osize;
    osize               = input.size >> 1;

    if (output == nullptr || capacity == 0) {
    } else if (capacity < osize) {
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
                osize = i >> 1; // bytes have been decoded so far
                return make_error_code(error_t::bad_input);
            }
            auto& des = output[i >> 1];
            des       = (i & 1) ? (des + ch) : (ch << 4);
        }
    }

    return std::error_code{};
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
