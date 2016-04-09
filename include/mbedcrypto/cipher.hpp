/** @file cipher.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.10
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 * related cmake build options:
 * paddings:
 *   BUILD_ALL_CIPHER_PADDINGS
 *
 * block mdoes:
 *   BUILD_CFB
 *   BUILD_CTR
 *   BUILD_GCM
 *   BUILD_CCM
 *
 * cipher types:
 *   BUILD_DES
 *   BUILD_BLOWFISH
 *   BUILD_CAMELLIA
 *   BUILD_ARC4
 *
 */

#ifndef MBEDTLSCRYPTO_CIPHER_HPP
#define MBEDTLSCRYPTO_CIPHER_HPP

#include "mbedcrypto/types.hpp"
#include <tuple>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/// block mode: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
/// hints:
/// ebc so fast, not cryptographically strong
///  input size must be = N * block_size, so no padding is required
/// cbc is slow and cryptographically strong
///  needs iv and padding
/// cfb needs iv, no padding
/// ctr is fast and strong only with ciphers that have block_size() >= 128bits
///  needs iv, does not require padding, transforms a block to stream
/// @warning in ctr and all other counter based modes,
///   the iv should be used only once per operation to be secure
/// gcm is fast and strong if tag size is not smaller than 96bits
///  also used in aead (authenticated encryption with additional data)
///  needs iv, does not require padding
/// ccm is fast, strong if the iv never be used more than once for a given key
///  only used in aead (authenticated encryption with additional data)
///  needs iv, does not require padding
enum class cipher_bm {
    none,       ///< none or unknown
    ecb,        ///< electronic codebook, input size = N * block_size
    cbc,        ///< cipher block chaining, custom input size
    cfb,        ///< cipher feedback, custom input size
    ctr,        ///< counter, custom input size
    gcm,        ///< Galois/counter mode
    stream,     ///< as in arc4_128 or null ciphers (unsecure)
    ccm,        ///< counter with cbc-mac
};

class cipher
{
public:
    /** checks if current build and the CPU/OS supports AESNI.
     * AESNI is an extension to the x86 instruction set architecture
     *  for microprocessors from Intel and AMD proposed by Intel in March 2008.
     *  The purpose of the instruction set is to improve
     *  the speed of applications performing encryption and decryption using AES.
     *
     * @warning mbedcrypto (mbedcrypto) automatically switches to AESNI
     *  automatically for supported systems.
     * @sa http://en.wikipedia.org/wiki/AES_instruction_set
     */
    static bool supports_aes_ni();

    /// returns block size (in bytes) for a cipher
    static size_t block_size(cipher_t type);

    /// returns iv size (in bytes) for a cipher
    static size_t iv_size(cipher_t type);

    /// returns key length (in bits) for a cipher
    static size_t key_bitlen(cipher_t type);

    /// return block mode of a cipher type
    static auto block_mode(cipher_t type) -> cipher_bm;

    /// encrypts the input in single shot.
    /// input can be in any size for cipher modes except ecb.
    /// for ecb the size = block_size * N, where N >= 1
    static auto encrypt(cipher_t, padding_t,
            const buffer_t& iv, const buffer_t& key,
            const buffer_t& input) -> buffer_t;

    /// decrypts the input in single shot
    /// input can be in any size for cipher modes except ecb.
    /// for ecb the size = block_size * N, where N >= 1
    static auto decrypt(cipher_t, padding_t,
            const buffer_t& iv, const buffer_t& key,
            const buffer_t& input) -> buffer_t;

public: // aead methods require BUILD_CCM or BUILD_GCM
    /// encrypts (AEAD cipher) the input and authenticate by additional data.
    /// only cipher_t::gcm and cipher_t::ccm support aead.
    /// input and additional_data could be in any size.
    /// returns the computed tag (16bytes) as the first member of tuple,
    ///  the second one is the encrypted buffer.
    static auto encrypt_aead(cipher_t,
            const buffer_t& iv, const buffer_t& key,
            const buffer_t& additional_data,
            const buffer_t& input) -> std::tuple<buffer_t, buffer_t>;

    /// decrypts (AEAD cipher) the input and authenticate by additional data and the tag.
    /// only cipher_t::gcm and cipher_t::ccm support aead.
    /// additional_data could be in any size, input and tag are computed by encrypt_aead().
    /// returns the authentication status as the first member of tuple,
    ///  the second one is the decrypted buffer.
    static auto decrypt_aead(cipher_t,
            const buffer_t& iv, const buffer_t& key,
            const buffer_t& additional_data,
            const buffer_t& input,
            const buffer_t& tag) -> std::tuple<bool, buffer_t>;


public:
    explicit cipher(cipher_t type);
    ~cipher();

    /// cipher operation mode
    enum mode {encrypt_mode, decrypt_mode};
    /// key length depends on cipher_t type
    /// @sa key_bitlen()
    auto key(const buffer_t& key_data, mode) -> cipher&;

    /// iv (initial vector or nonce) length depends on cipher algorithm.
    /// @sa iv_size()
    /// @warning some algorithms does not use iv at all, for those ciphers
    ///  this function has no effect
    auto iv(const buffer_t& iv_data) -> cipher&;

    /// set padding mode for ciphers that use padding
    auto padding(padding_t) -> cipher&;

public: // properties
    size_t block_size() const noexcept;
    size_t iv_size()    const noexcept;
    size_t key_bitlen() const noexcept;
    auto   block_mode() const noexcept -> cipher_bm;


public: // general encryption / decryption
    /// resets and makes cipher ready for update() iterations
    void start();

    /// ciphers (encrypts/decrypts) chunks of data between start()/finish() pair.
    /// input size is arbitrary except for ecb ciphers where the size must be
    ///  N * block_size
    auto update(const buffer_t& input) -> buffer_t;
    /// returns the final chunk (w/ padding)
    auto finish() -> buffer_t;

    /// overload. reads count bytes from in_index of input and write into
    ///  out_index of output. returns the actual size of bytes written into output.
    size_t update(size_t count,
            const buffer_t& input, size_t in_index,
            buffer_t& output, size_t out_index);
    /// overload, writes into out_index of output
    /// returns the actual size of bytes written into output.
    size_t finish(buffer_t& output, size_t out_index);

    /// low level overload. the output buffer must be at least input_size + block_size()
    ///  for the selected cipher_t.
    /// output_size the size of output, also will be updated by actual size.
    int  update(const unsigned char* input, size_t input_size,
            unsigned char* output, size_t& output_size) noexcept;

    /// low level overload. the output size must be block_size() + 32.
    /// output_size the size of output, also will be updated by actual size.
    int  finish(unsigned char* output, size_t& output_size) noexcept;


    /// helper function, runs start()/update()/finish() in a single call, single allocation
    auto crypt(const buffer_t& input) -> buffer_t;

public: // gcm features: requires BUILD_GCM
    /// set the additional data for a gcm encryption/decryption or throws non gcm modes.
    /// ad could be in any size, can be transmitted in plain text.
    /// @warning must be called exactly after start() and before any update().
    void gcm_additional_data(const buffer_t& ad);

    /// returns the tag computed by gcm encryption, or throws for non gcm encryption.
    /// length <= 16bytes.
    /// @warning must be called exactly after finish() of encryption.
    auto gcm_encryption_tag(size_t length) -> buffer_t;

    /// checks (authenticate) a gcm decryption tag, or throws for non gcm decryption.
    /// tag previously computed by gcm encryption, <= 16bytes.
    /// @warning must be called exactly after finish() of decryption.
    bool gcm_check_decryption_tag(const buffer_t& tag);

public:
    // move only
    cipher(const cipher&)            = delete;
    cipher(cipher&&)                 = default;
    cipher& operator=(const cipher&) = delete;
    cipher& operator=(cipher&&)      = default;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // cipher

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDTLSCRYPTO_CIPHER_HPP
