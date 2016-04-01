#include "mbedcrypto/types.hpp"
#include "conversions.hpp"

#include <algorithm>
#include <cctype>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
template<typename Enum>
struct name_map {
    Enum        e;
    const char* n;
};

const name_map<padding_t> gPaddings[] = {
    {padding_t::none,          "NONE"},
    {padding_t::pkcs7,         "PKCS7"},
    {padding_t::one_and_zeros, "ONE_AND_ZEROS"},
    {padding_t::zeros_and_len, "ZEROS_AND_LEN"},
    {padding_t::zeros,         "ZEROS"}
};

const name_map<pk_t> gPks[] = {
    {pk_t::none,       "NONE"},
    {pk_t::rsa,        "RSA"},
    {pk_t::eckey,      "EC"},
    {pk_t::eckey_dh,   "EC_DH"},
    {pk_t::ecdsa,      "ECDSA"},
    {pk_t::rsa_alt,    "RSA_ALT"},
    {pk_t::rsassa_pss, "RSASSA_PSS"},
};

std::string
to_upper(const char* p) {
    std::string s(p);
    std::transform(s.cbegin(), s.cend(), s.begin(),
            [](char c) {return std::toupper(c);}
            );
    return s;
}

template<typename Enum, class Array>
auto to_string(Enum e, const Array& items) {
    for ( const auto& i : items ) {
        if ( i.e == e )
            return i.n;
    }

    throw std::logic_error("invalid type");
}

template<typename Enum, class Array>
Enum from_string(const char* name, const Array& items) {
    auto uname = to_upper(name);
    for ( const auto& i : items ) {
        if ( uname == i.n )
            return i.e;
    }

    return Enum::none;
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

bool
supports(pk_t e) {
    return mbedtls_pk_info_from_type(to_native(e)) != nullptr;
}

///////////////////////////////////////////////////////////////////////////////

bool
supports_hash(const char* name) {
    auto e = hash_from_string(name);
    return (e == hash_t::none) ? false : supports(e);
}

bool
supports_cipher(const char* name) {
    auto e = cipher_from_string(name);
    return (e == cipher_t::none) ? false : supports(e);
}

bool
supports_padding(const char* name) {
    // padding_t::none is an acceptable padding
    return supports( padding_from_string(name) );
}

bool
supports_pk(const char* name) {
    auto e = pk_from_string(name);
    return (e == pk_t::none ) ? false : supports(e);
}

///////////////////////////////////////////////////////////////////////////////

const char*
to_string(hash_t e) {
    const auto* p = mbedtls_md_info_from_type(to_native(e));
    if ( p == nullptr )
        return nullptr;

    return mbedtls_md_get_name(p);
}

const char*
to_string(cipher_t e) {
    const auto* p = mbedtls_cipher_info_from_type(to_native(e));
    if ( p == nullptr )
        return nullptr;
    return p->name;
}

const char*
to_string(padding_t e) {
    if ( !supports(e) )
        return nullptr;
    return to_string<padding_t>(e, gPaddings);
}

const char*
to_string(pk_t e) {
    if ( !supports(e) )
        return nullptr;
    return to_string<pk_t>(e, gPks);
}

///////////////////////////////////////////////////////////////////////////////

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
    return from_string<padding_t>(name, gPaddings);
}

pk_t
pk_from_string(const char* name) {
    return from_string<pk_t>(name, gPks);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
