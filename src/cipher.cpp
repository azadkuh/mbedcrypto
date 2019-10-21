#include "mbedcrypto/cipher.hpp"
#include "./conversions.hpp"

#include <mbedtls/aesni.h>
#include <mbedtls/cipher.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
//-----------------------------------------------------------------------------

const mbedtls_cipher_info_t*
find_native_info(cipher_t type) noexcept {
    if (type == cipher_t::unknown)
        return nullptr;
    return mbedtls_cipher_info_from_type(to_native(type));
}

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

size_t
block_size(cipher_t t) noexcept {
    const auto* info = find_native_info(t);
    return info == nullptr ? 0 : info->block_size;
}

size_t
iv_size(cipher_t t) noexcept {
    const auto* info = find_native_info(t);
    return info == nullptr ? 0 : info->iv_size;
}

size_t
key_bitlen(cipher_t t) noexcept {
    const auto* info = find_native_info(t);
    return info == nullptr ? 0 : info->key_bitlen;
}

cipher_bm
block_mode(cipher_t t) noexcept {
    const auto* info = find_native_info(t);
    if (info == nullptr)
        return cipher_bm::unknown;
    return from_native(info->mode);
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
