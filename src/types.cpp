#include "mbedcrypto/types.hpp"
#include "enumerator.hxx"
#include "conversions.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////

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

const name_map<cipher_bm> gBlockModes[] = {
    {cipher_bm::none,   "NONE"},
    {cipher_bm::ecb,    "ECB"},
    {cipher_bm::cbc,    "CBC"},
    {cipher_bm::cfb,    "CFB"},
    {cipher_bm::ctr,    "CTR"},
    {cipher_bm::gcm,    "GCM"},
    {cipher_bm::ccm,    "CCM"},
    {cipher_bm::stream, "STREAM"},
};

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

bool
supports(hash_t e) {
    return mbedtls_md_info_from_type(to_native(e)) != nullptr;
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
supports(cipher_bm bm) {
    switch ( bm ) {
        case cipher_bm::none:
        case cipher_bm::ecb:
            return true;    // always supported

        case cipher_bm::cbc:
            #if defined(MBEDTLS_CIPHER_MODE_CBC)
            return true;
            #else
            return false;
            #endif

        case cipher_bm::cfb:
            #if defined(MBEDTLS_CIPHER_MODE_CFB)
            return true;
            #else
            return false;
            #endif

        case cipher_bm::ctr:
            #if defined(MBEDTLS_CIPHER_MODE_CTR)
            return true;
            #else
            return false;
            #endif

        case cipher_bm::gcm:
            #if defined(MBEDTLS_GCM_C)
            return true;
            #else
            return false;
            #endif

        case cipher_bm::ccm:
            #if defined(MBEDTLS_CCM_C)
            return true;
            #else
            return false;
            #endif

        case cipher_bm::stream:
            #if defined(MBEDTLS_ARC4_C)
            return true;
            #else
            return false;
            #endif

        default:
            break;
    }

    return false;
}

bool
supports(cipher_t e) {
    return mbedtls_cipher_info_from_type(to_native(e)) != nullptr;
}

bool
supports(pk_t e) {
    return mbedtls_pk_info_from_type(to_native(e)) != nullptr;
}

// other installed_xx() are implemented in conversion.cpp
std::vector<cipher_bm>
installed_block_modes() {
    std::vector<cipher_bm> my;
    for ( auto bm : gBlockModes ) {
        if ( supports(bm.e) )
            my.push_back(bm.e);
    }

    return my;
}

///////////////////////////////////////////////////////////////////////////////

bool
supports_hash(const char* name) {
    auto e = hash_from_string(name);
    return (e == hash_t::none) ? false : supports(e);
}

bool
supports_padding(const char* name) {
    // padding_t::none is an acceptable padding
    return supports( padding_from_string(name) );
}

bool
supports_block_mode(const char* name) {
    auto bm = block_mode_from_string(name);
    return (bm == cipher_bm::none) ? false : supports(bm);
}

bool
supports_cipher(const char* name) {
    auto e = cipher_from_string(name);
    return (e == cipher_t::none) ? false : supports(e);
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
to_string(padding_t e) {
    if ( !supports(e) )
        return nullptr;
    return to_string<padding_t>(e, gPaddings);
}

const char*
to_string(cipher_bm bm) {
    if ( !supports(bm) )
        return nullptr;
    return to_string<cipher_bm>(bm, gBlockModes);
}

const char*
to_string(cipher_t e) {
    const auto* p = mbedtls_cipher_info_from_type(to_native(e));
    if ( p == nullptr )
        return nullptr;
    return p->name;
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

padding_t
padding_from_string(const char* name) {
    return from_string<padding_t>(name, gPaddings);
}

cipher_bm
block_mode_from_string(const char* name) {
    return from_string<cipher_bm>(name, gBlockModes);
}

cipher_t
cipher_from_string(const char* name) {
    const auto* p = mbedtls_cipher_info_from_string(to_upper(name).c_str());
    if ( p == nullptr )
        return cipher_t::none;
    return from_native(p->type);
}

pk_t
pk_from_string(const char* name) {
    return from_string<pk_t>(name, gPks);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
