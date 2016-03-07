/** @file tcodec.hpp
 * encoder / decoder for text <-> binary
 *
 * @copyright (C) 2016
 * @date 2016.03.07
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_TEXT_CODEC_HPP
#define MBEDCRYPTO_TEXT_CODEC_HPP

#include "mbedcrypto/exception.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/// hex represetation
struct hex {

    /// encodes a buffer to hex string
    static buffer_t encode(const unsigned char* src, size_t length);

    /// decodes froma a hex string
    static buffer_t decode(const char* src, size_t length = 0);

    /// overload
    static buffer_t encode(const buffer_t& src) {
        return encode(
                reinterpret_cast<const unsigned char*>(src.data()),
                src.size()
                );
    }

    /// overload
    static buffer_t decode(const buffer_t& src) {
        return decode(
                reinterpret_cast<const char*>(src.data()),
                src.size()
                );
    }

}; // struct hex

///////////////////////////////////////////////////////////////////////////////

/// base64 representation
struct base64 {
    /// encodes a buffer into base64 format
    static buffer_t encode(const buffer_t& src);

    /// decodes a base64-formatted buffer
    static buffer_t decode(const buffer_t& src);

    /// tries to reuse the dest memory, or resizes if there is not enough room
    static void     encode(const buffer_t& src, buffer_t& dest);
    /// tries to reuse the dest memory, or resizes if there is not enough room
    static void     decode(const buffer_t& src, buffer_t& dest);

    /// returns the required result size of encoding to base64, including null-terminating byte
    static size_t   encode_size(const buffer_t&);

    /// returns the required result size of decoding from base64
    static size_t   decode_size(const buffer_t&);

    // raw overloads

    static size_t   encode_size(const unsigned char* src, size_t src_length) noexcept;
    static size_t   decode_size(const unsigned char* src, size_t src_length) noexcept;

    static int      encode(const unsigned char* src, size_t src_length,
                           unsigned char* dest, size_t& dest_length) noexcept;
    static int      decode(const unsigned char* src, size_t src_length,
                           unsigned char* dest, size_t& dest_length) noexcept;

}; // struct base64

///////////////////////////////////////////////////////////////////////////////

inline buffer_t
to_hex(const buffer_t& src) {
    return hex::encode(src);
}

inline buffer_t
from_hex(const buffer_t& src) {
    return hex::decode(src);
}

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
#endif // MBEDCRYPTO_TEXT_CODEC_HPP
