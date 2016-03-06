#include "mbedcrypto/types.hpp"
#include "conversions.hpp"
#include "src/mbedtls_config.h"

#include "mbedtls/error.h"
#include <sstream>
#include <algorithm>
#include <cctype>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
constexpr char
hex_lower(unsigned char b) noexcept {
    return "0123456789abcdef"[b & 0x0f];
}

std::string
to_upper(const char* p) {
    std::string s(p);
    std::transform(s.cbegin(), s.cend(), s.begin(),
            [](char c) {return std::toupper(c);}
            );
    return s;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
std::string
exception::error_string()const {
    if ( code_ == 0 )
        return std::string{};

    std::string message(160, '\0');
    mbedtls_strerror(code_, &message.front(), message.size());
    message.resize(std::strlen(message.data()));

    return message;
}

std::string
exception::to_string()const {
    const char* w = what();
    if ( code_ == 0 )
        return w;

    std::stringstream ss;
    if ( std::strlen(w) > 0 )
        ss << w << " ";

    ss << "(" << code_ << "): " << error_string();
    return ss.str();
}

///////////////////////////////////////////////////////////////////////////////
bool
supports(hash_t e) {
    return mbedtls_md_info_from_type(to_native(e)) != nullptr;
}

bool
supports(cipher_t e) {
    return mbedtls_cipher_info_from_type(to_native(e)) != nullptr;
}

bool
supports(padding_t e) {
#if defined(MBEDTLS_CIPHER_PADDING_PKCS7)
    if ( e == padding_t::pkcs7 )
        return true;
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS)
    if ( e == padding_t::one_and_zeros)
        return true;
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN)
    if ( e == padding_t::zeros_and_len )
        return true;
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS)
    if ( e == padding_t::zeros )
        return true;
#endif
    if ( e == padding_t::none )
        return true;

    return false;
}

bool
supports(pk_t e) {
    return mbedtls_pk_info_from_type(to_native(e)) != nullptr;
}

bool
supports_hash(const char* name) {
    return mbedtls_md_info_from_string(to_upper(name).c_str()) != nullptr;
}

bool
supports_cipher(const char* name) {
    return mbedtls_cipher_info_from_string(to_upper(name).c_str()) != nullptr;
}

const char*
to_string(hash_t e) {
    return mbedtls_md_get_name(
            mbedtls_md_info_from_type(to_native(e))
            );
}

const char*
to_string(cipher_t e) {
    const auto* p = mbedtls_cipher_info_from_type(to_native(e));
    if ( p == nullptr )
        return nullptr;
    return p->name;
}

const char*
to_string(padding_t p) {
    switch ( p ) {
        case padding_t::none:          return "NONE";
        case padding_t::pkcs7:         return "PKCS7";
        case padding_t::one_and_zeros: return "ONE_AND_ZEROS";
        case padding_t::zeros_and_len: return "ZEROS_AND_LEN";
        case padding_t::zeros:         return "ZEROS";

        default: return nullptr;
    }
}

hash_t
hash_from_string(const char* name) {
    auto t = mbedtls_md_get_type(
            mbedtls_md_info_from_string(to_upper(name).c_str())
            );
    return from_native(t);
}

cipher_t
cipher_from_string(const char* name) {
    const auto* p = mbedtls_cipher_info_from_string(to_upper(name).c_str());
    if ( p == nullptr )
        return cipher_t::none;
    return from_native(p->type);
}

///////////////////////////////////////////////////////////////////////////////

buffer_t
to_hex(const unsigned char* src, size_t length) {
    buffer_t buffer(length << 1, '\0');
    unsigned char* hexdata = reinterpret_cast<unsigned char*>(&buffer.front());

    for ( size_t i = 0;    i < length;    ++i ) {
        hexdata[i << 1]       = hex_lower(src[i] >> 4);
        hexdata[(i << 1) + 1] = hex_lower(src[i] & 0x0f);
    }

    return buffer;
}

buffer_t
from_hex(const char* src, size_t length) {
    if ( length == 0 )
        length = std::strlen(src);

    if ( length == 0 ) // empty buffer
        return buffer_t{};

    if ( (length & 1) != 0 ) // size must be even
        throw exception("invalid size for hex string");

    buffer_t buffer(length >> 1, '\0');
    unsigned char* bindata = reinterpret_cast<unsigned char*>(&buffer.front());

    size_t j = 0, k = 0;
    for ( size_t i = 0;    i < length;    ++i, ++src ) {
        char s = *src;

        if      ( s >= '0'  &&  s <= '9' ) j = s - '0';
        else if ( s >= 'A'  &&  s <= 'F' ) j = s - '7';
        else if ( s >= 'a'  &&  s <= 'f' ) j = s - 'W';
        else
            throw exception("invalid character in hex string");

        k = ( ( i & 1 ) != 0 ) ? j : j << 4;
        bindata[i >> 1] = (unsigned char)( bindata[i >> 1] | k );
    }

    return buffer;
}
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
