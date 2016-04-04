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
/// hints:
/// ebc so fast, not cryptographically strong
///  input size must be = N * block_size, so no padding is required
/// cbc is slow and cryptographically strong
///  needs iv and padding
/// cfb needs iv, no padding
/// ctr is fast and strong only with ciphers that have block_size() >= 128bits
///  needs iv, does not require padding, transforms a block to stream
/// gcm is fast and strong if tag size is not smaller than 96bits
///  used in aead (authenticated encryption with additional data)
///  needs iv, does not require padding
enum class cipher_bm {
    none,       ///< none or unknown
    ecb,        ///< electronic codebook, input size = N * block_size
    cbc,        ///< cipher block chaining, custom input size
    cfb,        ///< cipher feedback, custom input size
    ctr,        ///< counter, custom input size
    gcm,        ///< Galois/counter mode
    stream,     ///< as in arc4_128 or null ciphers (unsecure)
    ccm,        ///< counter with cbc-mac (not yet supported)
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

public: // properties
    size_t block_size() const noexcept;
    size_t iv_size()    const noexcept;
    size_t key_bitlen() const noexcept;
    auto   block_mode() const noexcept -> cipher_bm;


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
