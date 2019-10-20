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

std::error_code
to_base64(bin_view_t input, char* output, size_t& osize) noexcept {
    int ret = 0;
    if (output == nullptr || osize == 0) {
        ret = mbedtls_base64_encode(nullptr, 0, &osize, input.data, input.size);
        if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
            ret = 0; // it's ok as we intentionally passed a nullptr output
    } else {
        size_t olen = 0;
        ret         = mbedtls_base64_encode(
            reinterpret_cast<uint8_t*>(output),
            osize,
            &olen,
            input.data,
            input.size);
        osize = olen;
    }
    return (ret != 0) ? base64_error(ret) : std::error_code{};
}

std::error_code
from_base64(bin_view_t input, uint8_t* output, size_t& osize) noexcept {
    int ret = 0;
    if (output == nullptr || osize == 0) {
        ret = mbedtls_base64_decode(nullptr, 0, &osize, input.data, input.size);
        if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
            ret = 0; // it's ok as we intentionally passed a nullptr output
    } else {
        size_t olen = 0;
        ret =
            mbedtls_base64_decode(output, osize, &olen, input.data, input.size);
        osize = olen;
    }
    return (ret != 0) ? base64_error(ret) : std::error_code{};
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
