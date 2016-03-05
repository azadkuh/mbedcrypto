/** @file base64.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.05
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_BASE64_HPP
#define MBEDCRYPTO_BASE64_HPP

#include "mbedcrypto/types.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace base64 {
///////////////////////////////////////////////////////////////////////////////

/// encodes a buffer into base64 format
buffer_t encode(const buffer_t& src);

/// decodes a base64-formatted buffer
buffer_t decode(const buffer_t& src);

/// tries to reuse the dest memory, or resizes if there is not enough room
void     encode(const buffer_t& src, buffer_t& dest);
/// tries to reuse the dest memory, or resizes if there is not enough room
void     decode(const buffer_t& src, buffer_t& dest);

/// returns the required result size of encoding to base64, including null-terminating byte
size_t   encode_size(const buffer_t&);

/// returns the required result size of decoding from base64
size_t   decode_size(const buffer_t&);

// raw overloads

size_t   encode_size(const unsigned char* src, size_t src_length) noexcept;
size_t   decode_size(const unsigned char* src, size_t src_length) noexcept;

int      encode(const unsigned char* src, size_t src_length,
                unsigned char* dest, size_t& dest_length) noexcept;
int      decode(const unsigned char* src, size_t src_length,
                unsigned char* dest, size_t& dest_length) noexcept;

///////////////////////////////////////////////////////////////////////////////
} // namespace base64
///////////////////////////////////////////////////////////////////////////////

inline buffer_t
to_base64(const buffer_t& src) {
    return base64::encode(src);
}

inline buffer_t
from_base64(const buffer_t& src) {
    return base64::decode(src);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_BASE64_HPP
