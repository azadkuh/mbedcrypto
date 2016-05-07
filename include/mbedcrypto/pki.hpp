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
class pki : public pk::pk_base
{
public: // static helper functions

    /// checks if a public-private pair of keys matches.
    /// @warning both pki instances must be of a same type (ex pk_t::rsa)
    static bool check_pair(const pki& pub, const pki& pri);

public:
    /// set the pk type explicitly, with empty key
    explicit pki(pk_t type);
    /// type will be set by key funcs: import_xxx() or load_xxx()
    pki();
    virtual ~pki();

public:
    /** signs a hash value (or a plain message) by the private key.
     * hash_or_message could be a hash value or message.
     *  if message size is larger than max_crypt_size(), it is hashed first
     *  by hash_algo, so hash_algo is only needed for plain long messages.
     * @note for RSA keys, the signature is padded by PKCS#1 v1.5
     */
    auto sign(const buffer_t& hash_or_message,
            hash_t hash_algo = hash_t::none) -> buffer_t;

    /// verifies a signature and its padding if relevant
    bool verify(const buffer_t& signature,
            const buffer_t& hash_or_message,
            hash_t hash_algo = hash_t::none);

    /// encrypt a hash value (or a plain message) by the public key. @sa sign()
    auto encrypt(const buffer_t& hash_or_message,
            hash_t hash_algo = hash_t::none) -> buffer_t;

    /// decrypt an encrypted buffer by public key. @sa max_crypt_size()
    auto decrypt(const buffer_t& encrypted_value) -> buffer_t;

public: // key generation

    void rsa_generate_key(size_t key_bitlen, size_t exponent = 65537) {
        pk::generate_rsa_key(context(), key_bitlen, exponent);
    }

    void ec_generate_key(curve_t ctype) {
        pk::generate_ec_key(context(), ctype);
    }

public:
    // move only
    pki(const pki&)            = delete;
    pki(pki&&)                 = default;
    pki& operator=(const pki&) = delete;
    pki& operator=(pki&&)      = default;

    virtual pk::context& context() override;
    virtual const pk::context& context() const override;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // pki
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_PKI_HPP
