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
 *  - MBEDCRYPTO_CIPHER_ARIA
 *  - MBEDCRYPTO_CIPHER_BLOWFISH
 *  - MBEDCRYPTO_CIPHER_CAMELLIA
 *  - MBEDCRYPTO_CIPHER_CHACHA20
 *  - MBEDCRYPTO_CIPHER_DES
 *  - MBEDCRYPTO_CIPHER_ARC4
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
 * if output.data == nullptr or output.size == 0, then computes the required
 * output size and report by updating the output.size.
 *
 * @warning: cipher_bm::ecb algorithms only operate on a single block_size of
 * that cipher. so the input.size should be exactly N * block_size. other
 * block modes accept any input.size via padding_t.
 */
std::error_code
encrypt(bin_edit_t& output, bin_view_t input, const info_t& ci) noexcept;

/// overload with container adapter.
std::error_code
encrypt(obuffer_t&& output, bin_view_t input, const info_t& ci);

/// decrypts input and writes into output, @sa encrypt()
std::error_code
decrypt(bin_edit_t& output, bin_view_t input, const info_t& ci) noexcept;

/// overload with container adapter.
std::error_code
decrypt(obuffer_t&& output, bin_view_t input, const info_t& ci);

//-----------------------------------------------------------------------------

/** makes authenticated-encryption (AEAD) of input by additional data of ci.
 * also computes and reports the tag (>=16bytes).
 * supports: cipher_bm::ccm/gcm/chachapoly, @sa cipher_bm
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

/// overload with container adapter.
std::error_code
auth_decrypt(
    obuffer_t&&   output,
    bin_view_t    tag,
    bin_view_t    input,
    const info_t& ci) noexcept;

//-----------------------------------------------------------------------------

/** encrypts/decrypts stream of data chunk by chunk.
 *
 * ex: to encrypt stream of data:
 * @code
 * cipher::stream s;
 * if (auto ec = s.start_encrypt(inf); ec) {
 *     // report error
 * }
 *
 * for (...) {
 *     const auto input = read_some_input_from_somewhere();
 *     std::vector<uint8_t> output;
 *     s.update(obuffer_t{output}, input);
 *     use_encrypted_segment(output);
 * }
 *
 * std::vector<uint8_t> last_segment;
 * s.finish(obuffer_t{last_segment});
 * use_encrypted_segment(last_segment);
 * @endcode
 */
class stream
{
public:
    explicit stream();
    ~stream();

    /// setup for encryption
    std::error_code start_encrypt(const info_t&) noexcept;
    /// setup for decryption
    std::error_code start_decrypt(const info_t&) noexcept;

    /** adds chunk of input to cipher context and computes output segment.
     * @warning you can use any cipher type with any chunk size except:
     *  - cipher_bm::ecb: requires chunk.size = block_size
     *  - cipher_bm::gcm: requires chunk.size = N * block_size
     *  - cipher_bm::xts: not supported yet, use cipher::encrypt()/decrypt()
     */
    std::error_code update(bin_edit_t& output, bin_view_t chunk) noexcept;
    /// overload with container adapter.
    std::error_code update(obuffer_t&& output, bin_view_t chukn);

    /// returns the final segment of output (w/ padding if supported)
    std::error_code finish(bin_edit_t& final_output) noexcept;
    /// overload with container adapter.
    std::error_code finish(obuffer_t&& final_output);

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // class stream

//-----------------------------------------------------------------------------
} // namespace cipher
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_CIPHER_HPP
