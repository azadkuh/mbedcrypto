/** @file cipher.hpp
 * symmetric cryptography api
 *
 * @copyright (C) 2016
 * @date 2016.03.10
 * @author amir zamani <azadkuh@live.com>
 *
 * related cmake build options:
 * block mdoes:
 *  - MBEDCRYPTO_BM_CFB
 *  - MBEDCRYPTO_BM_OFB
 *  - MBEDCRYPTO_BM_CTR
 *  - MBEDCRYPTO_BM_XTS
 *  - MBEDCRYPTO_BM_GCM
 *  - MBEDCRYPTO_BM_CCM
 *
 * cipher types:
 *  - MBEDCRYPTO_ARIA
 *  - MBEDCRYPTO_BLOWFISH
 *  - MBEDCRYPTO_CAMELLIA
 *  - MBEDCRYPTO_CHACHA20
 *  - MBEDCRYPTO_DES
 *  - MBEDCRYPTO_ARC4
 *
 */

#ifndef MBEDCRYPTO_CIPHER_HPP
#define MBEDCRYPTO_CIPHER_HPP

#include "mbedcrypto/types.hpp"
#include "mbedcrypto/binutils.hpp"
#include "mbedcrypto/errors.hpp"

//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

/// returns block size (in bytes) for a cipher or 0 as error.
size_t block_size(cipher_t) noexcept;

/// returns iv size (in bytes) for a cipher or 0 as error.
size_t iv_size(cipher_t) noexcept;

/// returns key length (in bits) for a cipher or 0 as error.
size_t key_bitlen(cipher_t) noexcept;

/// returns block mode of a cipher type
cipher_bm block_mode(cipher_t) noexcept;

/** checks if current build and the CPU/OS supports AESNI.
 * @sa features::aes_ni
 * AESNI is an extension to the x86 instruction set architecture
 *  for microprocessors from Intel and AMD proposed by Intel in March 2008.
 *  The purpose of the instruction set is to improve the speed of
 *  applications performing encryption and decryption using AES.
 *
 * @warning mbedcrypto (mbedcrypto) automatically switches to AESNI
 *  automatically for supported systems.
 * @sa http://en.wikipedia.org/wiki/AES_instruction_set
 */
inline bool
supports_aes_ni() noexcept {
    return supports(features::aes_ni);
}

/** authenticated encryption by additional data.
 * returns true if any of MBEDCRYPTO_BM_GCM or MBEDCRYPTO_BM_CCM has been
 * activated.  @sa features::aead
 */
inline bool
supports_aead() noexcept {
    return supports(features::aead);
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_CIPHER_HPP
