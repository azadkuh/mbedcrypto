#include "mbedcrypto/types.hpp"
#include "conversions.hpp"
#include "src/mbedtls_config.h"

#include <algorithm>
#include <cctype>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
const struct {
    padding_t   p;
    const char* n;
} gPaddings[] = {
    {padding_t::none,          "NONE"},
    {padding_t::pkcs7,         "PKCS7"},
    {padding_t::one_and_zeros, "ONE_AND_ZEROS"},
    {padding_t::zeros_and_len, "ZEROS_AND_LEN"},
    {padding_t::zeros,         "ZEROS"}
};

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

std::vector<padding_t>
installed_paddings() {
    std::vector<padding_t> my;

#if defined(MBEDTLS_CIPHER_PADDING_PKCS7)
    my.push_back(padding_t::pkcs7);
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS)
    my.push_back(padding_t::one_and_zeros);
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN)
    my.push_back(padding_t::zeros_and_len );
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS)
    my.push_back(padding_t::zeros );
#endif

    return my;
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
    for ( const auto& i : gPaddings ) {
        if ( i.p == p )
            return i.n;
    }

    return nullptr;
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

padding_t
padding_from_string(const char* name) {
    auto uname = to_upper(name);
    for ( const auto& i : gPaddings ) {
        if ( uname == i.n )
            return i.p;
    }

    return padding_t::none;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
