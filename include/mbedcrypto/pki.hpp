/** @file pki.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.20
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_PKI_HPP
#define MBEDCRYPTO_PKI_HPP
#include "mbedcrypto/pk.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/// asymmetric, public key infrastructure (deprecated)
class pki
{
public: // static helper functions

    /// checks if a public-private pair of keys matches.
    /// @warning both pki instances must be of a same type (ex pk_t::rsa)
    static bool check_pair(const pki& pub, const pki& pri);

    /// returns true only by enabled BUILD_PK_EXPORT builds.
    /// @sa pki::export_public_key() and pki::export_key()
    static bool supports_pk_export() {
        return pk::supports_key_export();
    }

    /// returns true only by enabled BUILD_RSA_KEYGEN builds.
    /// @sa pki::rsa_generate_key()
    static bool supports_rsa_keygen() {
        return pk::supports_rsa_keygen();
    }

    /// returns true only by enabled BUILD_EC builds.
    /// @sa pki::ec_generate_key();
    static bool supports_ec_keygen() {
        return pk::supports_ec_keygen();
    }

public:
    /// set the pk type explicitly, with empty key
    explicit pki(pk_t type);
    /// type will be set by key funcs: parse_xxx() or load_xxx()
    pki();
    ~pki();

    /// clears previous internal states, and setup to new type
    void reset_as(pk_t new_type);

public: // key i/o
    /// (re)initializes by private key data.
    void parse_key(const buffer_t& private_key,
            const buffer_t& password = buffer_t{});

    /// (re)initializes by public key data.
    void parse_public_key(const buffer_t& public_key);

    /// loads the private key from a file.
    void load_key(const char* file_path,
            const buffer_t& password = buffer_t{});

    /// loads public key from a file.
    void load_public_key(const char* file_path);

    /// export private key
    /// @warning requires the activation of BUILD_PK_EXPORT option
    ///  (see cmake file)
    auto export_key(pk::key_format)        -> buffer_t;
    /// export public key
    /// @warning requires the activation of BUILD_PK_EXPORT option
    ///  (see cmake file)
    auto export_public_key(pk::key_format) -> buffer_t;

public: // properties
    /// returns the type fed by constructor or key
    pk_t type()const;

    /// returns the name of current algorithm
    auto name()const noexcept -> const char*;

    /// returns the capability of this pki based on algorithms, and/or pub/priv key
    auto what_can_do()const noexcept -> pk::action_flags;

    /// returns true if the current key can do specific operation
    bool can_do(pk_t other_type)const noexcept;

    /// size of underlying key in bits, ex 2048 or ...
    /// returns 0 if the key is not initialized yet
    size_t bitlen()const noexcept;

    /// size of underlying key in bytes
    /// returns 0 if the key is not initialized yet
    size_t length()const noexcept;

    /// returns maximum size of data which is possible to encrypt() or sign()
    /// RSA is only able to encrypt data to a maximum amount of your
    ///  key size (2048 bits = 256 bytes) minus padding / header data
    //   (11 bytes for PKCS#1 v1.5 padding)
    size_t max_crypt_size()const;

    /// returns true if the key is a valid private key
    bool has_private_key()const noexcept;

public:
    /// signs a hash value (or a plain message) by the private key.
    /// hash_or_message could be a hash value or message.
    ///  if message size is larger than max_crypt_size(), it is hashed first
    ///  by hash_algo, so hash_algo is only needed for plain long messages.
    ///
    /// @note for RSA keys, the signature is padded by PKCS#1 v1.5
    auto sign(const buffer_t& hash_or_message,
            hash_t hash_algo = hash_t::none) -> buffer_t;

    /// verifies a signature and its padding if relevant
    bool verify(const buffer_t& signature,
            const buffer_t& hash_or_message,
            hash_t hash_type = hash_t::none);

    /// encrypt a hash value (or a plain message) by the public key
    /// @sa sign()
    auto encrypt(const buffer_t& hash_or_message,
            hash_t hash_algo = hash_t::none) -> buffer_t;

    /// decrypt an encrypted buffer by public key
    /// @sa max_crypt_size()
    auto decrypt(const buffer_t& encrypted_value) -> buffer_t;

public: // rsa key generation

    /// generates a key only if the type() is pk_t::rsa.
    /// @sa pki::supports_rsa_keygen()
    /// exponent rsa public exponent.
    /// only change the default exponent value if you know exactly what you're doing.
    /// @warning rsa_generate_key() requires the activation
    ///  of BUILD_RSA_KEYGEN option (see cmake file)
    void rsa_generate_key(size_t key_bitlen, size_t exponent = 65537);

public: // ec key generation
    /// generates a key only if the type is pk_t::eckey, eckey_dh or ecdsa.
    /// @sa pki::supports_ec_keygen()
    /// @warning requires the activation of BUILD_EC option (see cmake file)
    void ec_generate_key(curve_t);

public:
    // move only
    pki(const pki&)            = delete;
    pki(pki&&)                 = default;
    pki& operator=(const pki&) = delete;
    pki& operator=(pki&&)      = default;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // pki
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_PKI_HPP
