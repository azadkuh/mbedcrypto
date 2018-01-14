/** @file cipher.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.10
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDTLSCRYPTO_CIPHER_HPP
#define MBEDTLSCRYPTO_CIPHER_HPP

#include "mbedcrypto/types.hpp"

#include <tuple>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/** symmetric cryptography.
 *
 * related cmake build options:
 * paddings:
 *  - BUILD_ALL_CIPHER_PADDINGS
 *
 * block mdoes:
 *  - BUILD_CFB
 *  - BUILD_CTR
 *  - BUILD_GCM
 *  - BUILD_CCM
 *
 * cipher types:
 *  - BUILD_DES
 *  - BUILD_BLOWFISH
 *  - BUILD_CAMELLIA
 *  - BUILD_ARC4
 *
 */
class cipher
{
public:
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
    static bool supports_aes_ni();

    /// returns block size (in bytes) for a cipher
    static size_t block_size(cipher_t type);

    /// returns iv size (in bytes) for a cipher
    static size_t iv_size(cipher_t type);

    /// returns key length (in bits) for a cipher
    static size_t key_bitlen(cipher_t type);

    /// return block mode of a cipher type
    static auto block_mode(cipher_t type) -> cipher_bm;

    // for the following methods, the template TBuff could be
    // buffer_t (std::string or QByteArray)

    /** encrypts the input in single shot.
     * input can be in any size for cipher modes except ecb.
     * for ecb the size = block_size * N, where N >= 1
     */
    template <typename TBuff = buffer_t>
    static auto encrypt(
        cipher_t      type,
        padding_t     padding,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t input) -> TBuff;

    /** decrypts the input in single shot.
     * input can be in any size for cipher modes except ecb.
     * for ecb the size = block_size * N, where N >= 1
     */
    template <typename TBuff = buffer_t>
    static auto decrypt(
        cipher_t      type,
        padding_t     padding,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t input) -> TBuff;

    /// same as encrypt() but prepends the iv to the result
    template <typename TBuff = buffer_t>
    static auto pencrypt(
        cipher_t      type,
        padding_t     padding,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t input) -> TBuff;

    /// same as decrypt() but reads the iv from the begining of the input.
    template <typename TBuff = buffer_t>
    static auto pdecrypt(
        cipher_t      type,
        padding_t     padding,
        buffer_view_t key,
        buffer_view_t input) -> TBuff;

public: // aead methods require BUILD_CCM or BUILD_GCM
    /** returns true if any of BUILD_GCM or BUILD_CCM has been activated.
     * @sa features::aead
     */
    static bool supports_aead();

    /** encrypts (AEAD cipher) the input and authenticate by additional
     * data.
     * only cipher_t::gcm and cipher_t::ccm support aead.
     * input and additional_data could be in any size.
     *
     * returns the computed tag (16bytes) as the first member of tuple,
     * the second one is the encrypted buffer.
     */
    static auto encrypt_aead(
        cipher_t,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t additional_data,
        buffer_view_t input) -> std::tuple<buffer_t, buffer_t>;

    /** decrypts (AEAD cipher) the input and authenticate by additional data
     * and the tag.
     * only cipher_t::gcm and cipher_t::ccm support aead.
     * additional_data could be in any size, input and tag are computed by
     * encrypt_aead().
     *
     * returns the authentication status as the first member of tuple,
     * the second one is the decrypted buffer.
     */
    static auto decrypt_aead(
        cipher_t,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t additional_data,
        buffer_view_t tag,
        buffer_view_t input) -> std::tuple<bool, buffer_t>;

    /// helper
    template <class Tuple>
    static auto decrypt_aead(
        cipher_t      ctype,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t additional_data,
        const Tuple&  tuple_aead) {
        return decrypt_aead(
            ctype,
            iv,
            key,
            additional_data,
            std::get<0>(tuple_aead),
            std::get<1>(tuple_aead));
    }


public:
    explicit cipher(cipher_t type);
    ~cipher();

    /// cipher operation mode
    enum mode { encrypt_mode, decrypt_mode };
    /** key length depends on cipher_t type.
     * @sa key_bitlen()
     */
    auto key(buffer_view_t key_data, mode) -> cipher&;

    /** iv (initial vector or nonce) length depends on cipher algorithm.
     * @sa iv_size()
     * @warning some algorithms does not use iv at all, for those ciphers this
     * function has no effect
     */
    auto iv(buffer_view_t iv_data) -> cipher&;

    /// set padding mode for ciphers that use padding
    auto padding(padding_t) -> cipher&;

public: // properties
    auto   block_mode() const noexcept -> cipher_bm;
    size_t block_size() const noexcept;
    size_t key_bitlen() const noexcept;
    size_t iv_size() const noexcept;


public: // general encryption / decryption
    /// resets and makes cipher ready for update() iterations
    void start();

    /** ciphers (encrypts/decrypts) chunks of data between start() / finish()
     * pair.
     * input size is arbitrary except for ecb ciphers where the size must
     * be N * block_size
     */
    auto update(buffer_view_t input) -> buffer_t;
    /// returns the final chunk (w/ padding)
    auto finish() -> buffer_t;

    /** overload.
     * reads count bytes from in_index of input and write into out_index of
     * output.
     *
     * returns the actual size of bytes written into output.
     */
    size_t update(
        buffer_view_t input,
        size_t        in_index,
        size_t        count,
        buffer_t&     output,
        size_t        out_index);
    /** overload, writes into out_index of output.
     * returns the actual size of bytes written into output.
     */
    size_t finish(buffer_t& output, size_t out_index);

    /** low level overload.
     * the output buffer must be at least input_size + block_size()
     * for the selected cipher_t.
     * output_size the size of output, also will be updated by actual size.
     */
    int update(
        buffer_view_t  input,
        unsigned char* output,
        size_t&        output_size) noexcept;

    /** low level overload.
     * the output size must be block_size() + 32
     * output_size the size of output, also will be updated by actual size.
     */
    int finish(unsigned char* output, size_t& output_size) noexcept;


    /** helper function, runs start() / update() / finish() in a single call,
     * single allocation
     */
    auto crypt(buffer_view_t input) -> buffer_t;

public: // gcm features: requires BUILD_GCM
    /** set the additional data for a gcm encryption/decryption or throws non
     * gcm modes.
     * ad could be in any size, can be transmitted in plain text.
     * @warning must be called exactly after start() and before any update().
     */
    void gcm_additional_data(buffer_view_t ad);

    /** returns the tag computed by gcm encryption, or throws for non gcm
     * encryption.
     * length <= 16bytes.
     * @warning must be called exactly after finish() of encryption.
     */
    auto gcm_encryption_tag(size_t length) -> buffer_t;

    /** checks (authenticate) a gcm decryption tag, or throws for non gcm
     * decryption.
     * tag previously computed by gcm encryption, <= 16bytes.
     * @warning must be called exactly after finish() of decryption.
     */
    bool gcm_check_decryption_tag(buffer_view_t tag);

public:
    // move only
    cipher(const cipher&) = delete;
    cipher(cipher&&)      = default;
    cipher& operator=(const cipher&) = delete;
    cipher& operator=(cipher&&) = default;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;

private:
    static auto _encrypt(
        cipher_t,
        padding_t,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t input) -> buffer_t;

    static auto _decrypt(
        cipher_t,
        padding_t,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t input) -> buffer_t;

    static auto _pencrypt(
        cipher_t,
        padding_t,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t input) -> buffer_t;

    static auto
    _pdecrypt(cipher_t, padding_t, buffer_view_t key, buffer_view_t input)
        -> buffer_t;

#if defined(QT_CORE_LIB)
    static QByteArray _qencrypt(
        cipher_t,
        padding_t,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t input);

    static QByteArray _qdecrypt(
        cipher_t,
        padding_t,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t input);

    static QByteArray _qpencrypt(
        cipher_t,
        padding_t,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t input);

    static QByteArray
    _qpdecrypt(cipher_t, padding_t, buffer_view_t key, buffer_view_t input);
#endif // QT_CORE_LIB
}; // cipher
///////////////////////////////////////////////////////////////////////////////
// cipher specializations

template <>
inline buffer_t
cipher::encrypt(
    cipher_t      type,
    padding_t     padding,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t input) {
    return _encrypt(type, padding, iv, key, input);
}

template <>
inline buffer_t
cipher::decrypt(
    cipher_t      type,
    padding_t     padding,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t input) {
    return _decrypt(type, padding, iv, key, input);
}

template <>
inline buffer_t
cipher::pencrypt(
    cipher_t      type,
    padding_t     padding,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t input) {
    return _pencrypt(type, padding, iv, key, input);
}

template <>
inline buffer_t
cipher::pdecrypt(
    cipher_t type, padding_t padding, buffer_view_t key, buffer_view_t input) {
    return _pdecrypt(type, padding, key, input);
}

#if defined(QT_CORE_LIB)
template <>
inline QByteArray
cipher::encrypt(
    cipher_t      type,
    padding_t     padding,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t input) {
    return _qencrypt(type, padding, iv, key, input);
}

template <>
inline QByteArray
cipher::decrypt(
    cipher_t      type,
    padding_t     padding,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t input) {
    return _qdecrypt(type, padding, iv, key, input);
}

template <>
inline QByteArray
cipher::pencrypt(
    cipher_t      type,
    padding_t     padding,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t input) {
    return _qpencrypt(type, padding, iv, key, input);
}

template <>
inline QByteArray
cipher::pdecrypt(
    cipher_t type, padding_t padding, buffer_view_t key, buffer_view_t input) {
    return _qpdecrypt(type, padding, key, input);
}
#endif // QT_CORE_LIB

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDTLSCRYPTO_CIPHER_HPP
