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
    /// verifies a signature and its padding if relevant
    bool verify(hash_t hash_type, const buffer_t& hash_value,
            const buffer_t& signature);

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
