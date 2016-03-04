#include "mbedcrypto/types.hpp"
#include "conversions.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////

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
#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    return true;
#else
#   error add padding mode to ciphers is manadatory
#endif
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
