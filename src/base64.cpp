#include "mbedcrypto/base64.hpp"

#include "mbedtls/base64.h"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace base64 {
namespace {
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
size_t
encode_size(const unsigned char* src, size_t srclen) noexcept {
    size_t olen = 0;
    mbedtls_base64_encode(
            nullptr, 0, // dest
            &olen,
            src, srclen
            );

    return olen;
}

size_t
decode_size(const unsigned char* src, size_t srclen) noexcept {
    size_t olen = 0;
    mbedtls_base64_decode(
            nullptr, 0, // dest
            &olen,
            src, srclen
            );

    return olen;
}

size_t
encode_size(const buffer_t& src) {
    return encode_size(reinterpret_cast<const unsigned char*>(src.data()),
            src.size()
            );
}

size_t
decode_size(const buffer_t& src) {
    return decode_size(reinterpret_cast<const unsigned char*>(src.data()),
            src.size()
            );
}

int
encode(const unsigned char* src, size_t srclen,
        unsigned char* dest, size_t& destlen) noexcept {
    size_t olen = 0;
    int ret = mbedtls_base64_encode(
            dest, destlen,
            &olen,
            src, srclen
            );
    destlen = olen;

    return ret;
}

int
decode(const unsigned char* src, size_t srclen,
        unsigned char* dest, size_t& destlen) noexcept {
    size_t olen = 0;
    int ret = mbedtls_base64_decode(
            dest, destlen,
            &olen,
            src, srclen
            );
    destlen = olen;

    return ret;
}

void
encode(const buffer_t& src, buffer_t& dest) {
    size_t requiredSize = encode_size(src);
    if ( dest.capacity() <= requiredSize )
        dest.reserve(requiredSize + 1);

    dest.resize(requiredSize);
    size_t dsize = requiredSize;
    int ret = encode(
            reinterpret_cast<const unsigned char*>(src.data()),
            src.size(),
            reinterpret_cast<unsigned char*>(&dest.front()),
            dsize
            );

    if ( ret != 0 )
        throw exception(ret, "failed to base64 encode");

    // adjust possible null byte at the end
    dest.resize(dsize);
}

void
decode(const buffer_t& src, buffer_t& dest) {
    size_t requiredSize = decode_size(src);
    if ( dest.capacity() <= requiredSize )
        dest.reserve(requiredSize + 1);

    dest.resize(requiredSize);
    size_t dsize = requiredSize;
    int ret = decode(
            reinterpret_cast<const unsigned char*>(src.data()),
            src.size(),
            reinterpret_cast<unsigned char*>(&dest.front()),
            dsize
            );

    if ( ret != 0 )
        throw exception(ret, "failed to base64 decode");
}

buffer_t
encode(const buffer_t& src) {
    buffer_t dest;
    encode(src, dest);
    return dest;
}

buffer_t
decode(const buffer_t& src) {
    buffer_t dest;
    decode(src, dest);
    return dest;
}




///////////////////////////////////////////////////////////////////////////////
} // namespace base64
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
