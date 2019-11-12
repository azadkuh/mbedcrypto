/** @file conversions.hpp
 * implemented in types.cpp
 *
 * @copyright (C) 2016
 * @date 2016.03.04
 * @author amir zamani <azadkuh@live.com>
 */

#ifndef MBEDCRYPTO_CONVERSIONS_HPP
#define MBEDCRYPTO_CONVERSIONS_HPP

#include "mbedcrypto_mbedtls_config.h"
#include "mbedcrypto/types.hpp"

#include <mbedtls/cipher.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------
// clang-format off

mbedtls_md_type_t        to_native(hash_t) noexcept;
mbedtls_cipher_padding_t to_native(padding_t) noexcept;
mbedtls_cipher_mode_t    to_native(cipher_bm) noexcept;
mbedtls_cipher_type_t    to_native(cipher_t) noexcept;
mbedtls_pk_type_t        to_native(pk_t) noexcept;
mbedtls_ecp_group_id     to_native(curve_t) noexcept;

hash_t                   from_native(mbedtls_md_type_t) noexcept;
padding_t                from_native(mbedtls_cipher_padding_t) noexcept;
cipher_bm                from_native(mbedtls_cipher_mode_t) noexcept;
cipher_t                 from_native(mbedtls_cipher_type_t) noexcept;
pk_t                     from_native(mbedtls_pk_type_t) noexcept;
curve_t                  from_native(mbedtls_ecp_group_id) noexcept;

// clang-format on
//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_CONVERSIONS_HPP
