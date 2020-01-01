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
 * if output.data == nullptr, then fills the required output size into
 * output.size.
 * if output.size is smaller than required size, returns error and fills the
 * proper output_size.
 *
 * also appends a null-terminator to output, but output.size is the strlen() of
 * the output (excludes null-terminator)
 */
std::error_code to_hex(bin_edit_t& output, bin_view_t input) noexcept;
/// overload with contaienr apdapter
std::error_code to_hex(auto_size_t&& output, bin_view_t input);

/** decodes from a hex string (accepts lower/upper case).
 * if output.data == nullptr, then fills the required output size into
 * output.size.
 * if output.size is smaller than required size, returns error and fills the
 * proper output.size.
 *
 * the input hex string should be even in size and excludes 0x
 */
std::error_code from_hex(bin_edit_t& output, bin_view_t input) noexcept;
/// overload with contaienr apdapter
std::error_code from_hex(auto_size_t&& output, bin_view_t input);
//-----------------------------------------------------------------------------

/** makes a base64 string from any input.
 * if output.data == nullptr, then fills the required output size into
 * output.size.
 * if output.size is smaller than required size, returns error and fills the
 * proper output.size.
 * empty input will result an empty output.
 *
 * also appends a null-terminator to output, but output.size is the strlen() of
 * the output (excludes null-terminator)
 */
std::error_code to_base64(bin_edit_t& output, bin_view_t input) noexcept;
/// overload with contaienr apdapter
std::error_code to_base64(auto_size_t&& output, bin_view_t input);

/** decodes from a base64 string.
 * if output.data == nullptr, then fills the required output size into
 * output.size.
 * if output.size is smaller than required size, returns error and fills the
 * proper output.size.
 * empty input will result an empty output
 */
std::error_code from_base64(bin_edit_t& output, bin_view_t input) noexcept;
/// overload with contaienr apdapter
std::error_code from_base64(auto_size_t&& output, bin_view_t input);

//-----------------------------------------------------------------------------
// hex helper overloads

template <typename Container>
inline std::pair<Container, std::error_code>
to_hex(bin_view_t input) {
    Container output;
    auto      ec = to_hex(auto_size_t{output}, input);
    return {output, ec};
}

template <typename Container>
inline std::pair<Container, std::error_code>
from_hex(bin_view_t input) {
    Container output;
    auto      ec = from_hex(auto_size_t{output}, input);
    return {output, ec};
}

//-----------------------------------------------------------------------------
// base64 helper overloads

template <typename Container>
inline std::pair<Container, std::error_code>
to_base64(bin_view_t input) {
    Container output;
    auto      ec = to_base64(auto_size_t{output}, input);
    return {output, ec};
}

template <typename Container>
inline std::pair<Container, std::error_code>
from_base64(bin_view_t input) {
    Container output;
    auto      ec = from_base64(auto_size_t{output}, input);
    return {output, ec};
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_TEXT_CODEC_HPP
