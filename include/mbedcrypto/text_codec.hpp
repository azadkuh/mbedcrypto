/** @file text_codec.hpp
 * encoder / decoder for text <-> binary
 *
 * @copyright (C) 2016
 * @date 2016.03.07
 * @author amir zamani <azadkuh@live.com>
 */

#ifndef MBEDCRYPTO_TEXT_CODEC_HPP
#define MBEDCRYPTO_TEXT_CODEC_HPP

#include "mbedcrypto/errors.hpp"
#include "mbedcrypto/binutils.hpp"
//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

/** makes a hex string from any non-empty input.
 * if output == nullptr, then fills the required output size into output_size.
 * if output_size is smaller than required size, returns error and fills the
 * proper output_size.
 *
 * also appends a null-terminator to output, but output_size is the strlen() of
 * the output (excludes null-terminator)
 */
std::error_code
to_hex(bin_view_t input, char* output, size_t& output_size) noexcept;

/** decodes from a hex string (accepts lower/upper case).
 * if output == nullptr, then fills the required output size into output_size.
 * if output_size is smaller than required size, returns error and fills the
 * proper output_size.
 *
 * the input hex string should be even in size, and
 */
std::error_code
from_hex(bin_view_t input, uint8_t* output, size_t& output_size) noexcept;

//-----------------------------------------------------------------------------

/** makes a base64 string from any input.
 * if output == nullptr, then fills the required output size into output_size.
 * if output_size is smaller than required size, returns error and fills the
 * proper output_size.
 * empty input will result an empty output.
 *
 * also appends a null-terminator to output, but output_size is the strlen() of
 * the output (excludes null-terminator)
 */
std::error_code
to_base64(bin_view_t input, char* output, size_t& output_size) noexcept;

/** decodes from a base64 string.
 * if output == nullptr, then fills the required output size into output_size.
 * if output_size is smaller than required size, returns error and fills the
 * proper output_size.
 * empty input will result an empty output.
 */
std::error_code
from_base64(bin_view_t input, uint8_t* output, size_t& output_size) noexcept;

//-----------------------------------------------------------------------------
// hex helper overloads

template <typename Container>
inline std::error_code
to_hex(Container& output, bin_view_t input) {
    size_t size = 0;
    auto   ec   = to_hex(input, nullptr, size);
    if (ec)
        return ec;
    output.resize(size); // includes null-terminator
    ec = to_hex(input, reinterpret_cast<char*>(&output[0]), size);
    if (size && !ec) // remove null-terminator
        output.resize(size);
    return ec;
}

template <typename Container>
inline std::error_code
from_hex(Container& output, bin_view_t input) {
    size_t size = 0;
    auto   ec   = from_hex(input, nullptr, size);
    if (ec)
        return ec;
    output.resize(size);
    return from_hex(input, reinterpret_cast<uint8_t*>(&output[0]), size);
}

template <typename Container>
inline std::pair<Container, std::error_code>
to_hex(bin_view_t input) {
    Container output;
    auto      ec = to_hex(output, input);
    return {output, ec};
}

template <typename Container>
inline std::pair<Container, std::error_code>
from_hex(bin_view_t input) {
    Container output;
    auto      ec = from_hex(output, input);
    return {output, ec};
}

//-----------------------------------------------------------------------------
// base64 helper overloads

template <typename Container>
inline std::error_code
to_base64(Container& output, bin_view_t input) {
    size_t size = 0;
    auto   ec   = to_base64(input, nullptr, size);
    if (ec)
        return ec;
    output.resize(size); // includes null-terminator
    ec = to_base64(input, reinterpret_cast<char*>(&output[0]), size);
    if (size && !ec) // remove null-terminator
        output.resize(size);
    return ec;
}

template <typename Container>
inline std::error_code
from_base64(Container& output, bin_view_t input) {
    size_t size = 0;
    auto   ec   = from_base64(input, nullptr, size);
    if (ec)
        return ec;
    output.resize(size);
    return from_base64(input, reinterpret_cast<uint8_t*>(&output[0]), size);
}

template <typename Container>
inline std::pair<Container, std::error_code>
to_base64(bin_view_t input) {
    Container output;
    auto      ec = to_base64(output, input);
    return {output, ec};
}

template <typename Container>
inline std::pair<Container, std::error_code>
from_base64(bin_view_t input) {
    Container output;
    auto      ec = from_base64(output, input);
    return {output, ec};
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_TEXT_CODEC_HPP
