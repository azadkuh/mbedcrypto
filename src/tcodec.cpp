#include "mbedcrypto/tcodec.hpp"

#include <mbedtls/base64.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
//-----------------------------------------------------------------------------

constexpr char
hex_lower(unsigned char b) noexcept {
    return "0123456789abcdef"[b & 0x0f];
}

enum class hex_err {
    ok,
    invalid_size,
    invalid_chars,
};

std::pair<buffer_t, hex_err>
hex_decode_impl(const char* src, size_t length) {
    if (length == 0)
        length = std::strlen(src);
    if (length == 0) // empty buffer
        return std::make_pair(buffer_t{}, hex_err::ok);
    if ((length & 1) != 0) // size must be even
        return std::make_pair(buffer_t{}, hex_err::invalid_size);

    buffer_t buffer(length >> 1, '\0');
    auto*    bindata = to_ptr(buffer);

    size_t j = 0, k = 0;
    for (size_t i = 0; i < length; ++i, ++src) {
        char s = *src;

        if (s >= '0' && s <= '9')
            j = s - '0';
        else if (s >= 'A' && s <= 'F')
            j = s - '7';
        else if (s >= 'a' && s <= 'f')
            j = s - 'W';
        else
            return std::make_pair(buffer_t{}, hex_err::invalid_chars);

        k               = ((i & 1) != 0) ? j : j << 4;
        bindata[i >> 1] = (unsigned char)(bindata[i >> 1] | k);
    }

    return std::make_pair(std::move(buffer), hex_err::ok);
}

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

buffer_t
hex::encode(buffer_view_t bsrc) {
    auto     length = bsrc.length();
    auto     src    = bsrc.data();
    buffer_t buffer(length << 1, '\0');
    auto*    hexdata = to_ptr(buffer);

    for (size_t i = 0; i < length; ++i) {
        hexdata[i << 1]       = hex_lower(src[i] >> 4);
        hexdata[(i << 1) + 1] = hex_lower(src[i] & 0x0f);
    }

    return buffer;
}

buffer_t
hex::decode(const char* src, size_t length) {
    auto p = hex_decode_impl(src, length);
    if (p.second == hex_err::invalid_size)
        throw exceptions::usage_error{"invalid size for hex string"};
    else if (p.second == hex_err::invalid_chars)
        throw exceptions::usage_error{"invalid character in hex string"};
    return p.first;
}

buffer_t
from_hex(const buffer_t& src, bool& ok) {
    auto p = hex_decode_impl(src.data(), src.size());
    ok     = p.second == hex_err::ok ? true : false;
    return p.first;
}

//-----------------------------------------------------------------------------

size_t
base64::encode_size(buffer_view_t src) noexcept {
    size_t olen = 0;
    mbedtls_base64_encode(
        nullptr,
        0, // dest
        &olen,
        src.data(),
        src.size());

    return olen;
}

size_t
base64::decode_size(buffer_view_t src) noexcept {
    size_t olen = 0;
    mbedtls_base64_decode(
        nullptr,
        0, // dest
        &olen,
        src.data(),
        src.size());

    return olen;
}

int
base64::encode(
    const uint8_t* src,
    size_t         srclen,
    uint8_t*       dest,
    size_t&        destlen) noexcept {
    size_t olen = 0;
    int    ret  = mbedtls_base64_encode(dest, destlen, &olen, src, srclen);
    destlen     = olen;
    return ret;
}

int
base64::decode(
    const uint8_t* src,
    size_t         srclen,
    uint8_t*       dest,
    size_t&        destlen) noexcept {
    size_t olen = 0;
    int    ret  = mbedtls_base64_decode(dest, destlen, &olen, src, srclen);
    destlen     = olen;
    return ret;
}

void
base64::encode(buffer_view_t src, buffer_t& dest) {
    size_t requiredSize = encode_size(src);
    if (dest.capacity() <= requiredSize)
        dest.reserve(requiredSize + 1);

    dest.resize(requiredSize);
    size_t dsize = requiredSize;
    int    ret   = encode(src.data(), src.size(), to_ptr(dest), dsize);

    if (ret != 0)
        throw exception{ret, "failed to base64 encode"};

    // adjust possible null byte at the end
    dest.resize(dsize);
}

void
base64::decode(buffer_view_t src, buffer_t& dest) {
    size_t requiredSize = decode_size(src);
    if (dest.capacity() <= requiredSize)
        dest.reserve(requiredSize + 1);

    dest.resize(requiredSize);
    size_t dsize = requiredSize;
    int    ret   = decode(src.data(), src.size(), to_ptr(dest), dsize);

    if (ret != 0)
        throw exception{ret, "failed to base64 decode"};
}

buffer_t
base64::encode(buffer_view_t src) {
    buffer_t dest;
    encode(src, dest);
    return dest;
}

buffer_t
base64::decode(buffer_view_t src) {
    buffer_t dest;
    decode(src, dest);
    return dest;
}

buffer_t
from_base64(const buffer_t& src, bool& ok) {
    ok           = false;
    size_t dsize = base64::decode_size(src);
    if (dsize == 0)
        return buffer_t{};
    buffer_t des(dsize, char(0));
    auto     ret =
        base64::decode(to_const_ptr(src), src.size(), to_ptr(des), dsize);
    if (ret != 0)
        return buffer_t{};
    ok = true;
    return des;
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
