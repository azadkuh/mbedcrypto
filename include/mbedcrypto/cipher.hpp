/** @file cipher.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.10
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDTLSCRYPTO_CIPHER_HPP
#define MBEDTLSCRYPTO_CIPHER_HPP

#include "mbedcrypto/types.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/// block mode: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
enum class cipher_bm {
    none,       ///< none or unknown
    ecb,        ///< electronic codebook
    cbc,        ///< cipher block chaining
    cfb,        ///< cipher feedback
    ctr,        ///< counter
    gcm,        ///< Galois/counter mode
    stream,     ///< as in arc4_128 or null ciphers
    ccm,        ///< = cbc + mac
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

    /// encrypts the input in single shot
    static auto encrypt(cipher_t, padding_t,
            const buffer_t& iv, const buffer_t& key,
            const buffer_t& input) -> buffer_t;

    /// decrypts the input in single shot
    static auto decrypt(cipher_t, padding_t,
            const buffer_t& iv, const buffer_t& key,
            const buffer_t& input) -> buffer_t;


public:
    explicit cipher(cipher_t type);
    ~cipher();

    /// cipher operation mode
    enum mode {encrypt_mode, decrypt_mode};
    /// key length depends on cipher_t type
    /// @sa key_bitlen()
    auto key(const buffer_t& key_data, mode) -> cipher&;

    /// iv (initial vector or nonce) length depends on cipher algorithm
    /// @sa iv_size()
    /// @warning some algorithms does not use iv at all, for those ciphers
    ///  this function has no effect
    auto iv(const buffer_t& iv_data) -> cipher&;

    /// set padding mode for ciphers that use padding
    auto padding(padding_t) -> cipher&;

    /// resets and makes cipher ready for update() iterations
    void start();

    /// ciphers (encrypts/decrypts) chunks of data between start()/finish() pair.
    auto update(const buffer_t& input) -> buffer_t;
    /// low level overload. the output buffer must be at least input_size + block_size()
    ///  for the selected cipher_t.
    /// output_size the size of output, also will be updated by actual size.
    int  update(const unsigned char* input, size_t input_size,
            unsigned char* output, size_t& output_size) noexcept;

    /// returns the final chunk (w/ padding)
    auto finish() -> buffer_t;
    /// low level overload. the output size must be block_size() + 32.
    /// output_size the size of output, also will be updated by actual size.
    int  finish(unsigned char* output, size_t& output_size) noexcept;

    /// helper function, runs start()/update()/finish() in a single call, single allocation
    auto crypt(const buffer_t& input) -> buffer_t;


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


///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDTLSCRYPTO_CIPHER_HPP
