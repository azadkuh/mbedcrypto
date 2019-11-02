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
namespace cipher {
//-----------------------------------------------------------------------------

struct info_t {
    cipher_t   type    = cipher_t::unknown;
    padding_t  padding = padding_t::unknown; ///< only for cipher_bm::cbc
    bin_view_t key; ///< symmetric key, @sa key_bitlen()
    bin_view_t iv;  ///< initial vector if type support, @sa iv_size()
    bin_view_t ad;  ///< optional additional data, @sa supports_aead()
};

/// check if it has valid and compatible fields.
bool is_valid(const info_t&) noexcept;

//-----------------------------------------------------------------------------

/** encrypts input and writes into output by a one-shot call.
 * if ouput.data == nullptr or output.size == 0, then computes the required
 * output size and report by updating the output.size.
 *
 * @warning: cipher_bm::ecb algorithms only operate on a single block_size() of
 * that cipher. so the input.size should be exactly N * block_size().  other
 * block modes accept any input.size via padding_t.
 */
std::error_code
encrypt(bin_edit_t& output, bin_view_t input, const info_t& ci) noexcept;

/// overlad with container adapter.
std::error_code
encrypt(obuffer_t&& output, bin_view_t input, const info_t& ci);

/// decrypts input and writes into output, @sa encrypt()
std::error_code
decrypt(bin_edit_t& output, bin_view_t input, const info_t& ci) noexcept;

/// overlad with container adapter.
std::error_code
decrypt(obuffer_t&& output, bin_view_t input, const info_t& ci);

//-----------------------------------------------------------------------------

/** makes authenticated-encryption (AEAD) of input by additional data of ci.
 * also computes and reports the tag (16bytes).
 * supports: cipher_bm:ccm/gcm/chachapoly, @sa cipher_bm
 */
std::error_code
auth_encrypt(
    bin_edit_t&   output,
    bin_edit_t&   tag,
    bin_view_t    input,
    const info_t& ci) noexcept;

/// overload with container adapter.
std::error_code
auth_encrypt(
    obuffer_t&&   output,
    obuffer_t&&   tag,
    bin_view_t    input,
    const info_t& ci) noexcept;

/** decrypts and checks the authentication tag of AEAD.
 * @sa auth_encrypt()
 */
std::error_code
auth_decrypt(
    bin_edit_t&   output,
    bin_view_t    tag,
    bin_view_t    input,
    const info_t& ci) noexcept;

/// overload with contaienr adapter.
std::error_code
auth_decrypt(
    obuffer_t&&   output,
    bin_view_t    tag,
    bin_view_t    input,
    const info_t& ci) noexcept;

//-----------------------------------------------------------------------------
} // namespace cipher
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_CIPHER_HPP
