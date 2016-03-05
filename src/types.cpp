#include "mbedcrypto/types.hpp"
#include "conversions.hpp"
#include "src/mbedtls_config.h"

#include "mbedtls/error.h"
#include <sstream>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////

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
    return mbedtls_md_info_from_string(name) != nullptr;
}

bool
supports_cipher(const char* name) {
    return mbedtls_cipher_info_from_string(name) != nullptr;
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
            mbedtls_md_info_from_string(name)
            );
    return from_native(t);
}

cipher_t
cipher_from_string(const char* name) {
    const auto* p = mbedtls_cipher_info_from_string(name);
    if ( p == nullptr )
        return cipher_t::none;
    return from_native(p->type);
}
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
