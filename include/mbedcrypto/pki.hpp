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
#include "mbedcrypto/types.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

class pki
{
public:
    explicit pki(pk_t type);
    pki();
    ~pki();

public: // parse or load public or private keys
    /// (re)initializes by private key data.
    /// @warning key data must end with a null byte
    void parse_key(const buffer_t& private_key,
            const buffer_t& password = buffer_t{});

    /// (re)initializes by public key data.
    /// @warning key data must end with a null byte
    void parse_public_key(const buffer_t& public_key);

    /// loads the private key from a file.
    void load_key(const char* file_path,
            const buffer_t& password = buffer_t{});

    /// loads public key from a file.
    void load_public_key(const char* file_path);

public: // properties
    /// returns the type fed by constructor or key
    pk_t type()const noexcept;

    /// returns the name of current algorithm
    auto name()const noexcept -> const char*;

    /// returns true if the current key can do specific operation
    bool can_do(pk_t other_type)const noexcept;

    /// size of underlying key in bits, ex 2048 or ...
    size_t bitlen()const;

    /// size of underlying key in bytes
    size_t length()const;

public:
    /// signs a hash value (or a plain message) by the private key.
    /// hash_or_message could be a hash value or message.
    ///  if message size is larger than private key, it is hashed first
    ///  by hash_algo, so hash_algo is only needed for plain messages.
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
    auto decrypt(const buffer_t& encrypted_value) -> buffer_t;


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
