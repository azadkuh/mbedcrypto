/** @file rsa.hpp
 *
 * @copyright (C) 2016
 * @date 2016.05.07
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef __MBEDCRYPTO_RSA_HPP__
#define __MBEDCRYPTO_RSA_HPP__
#include "mbedcrypto/pk.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/** rsa cryptography.
 * built by default in mbedcrypto. for more options:
 *  - BUILD_RSA_KEYGEN
 *  - BUILD_PK_EXPORT
 * @sa cmake options.
 */
class rsa : public pk::pk_base
{
public:
    explicit rsa();
    ~rsa();

    size_t max_crypt_size() const {
        return pk::max_crypt_size(context());
    }

public: // helper functions for rsa functionalities
    auto
    sign(const buffer_t& hash_or_message, hash_t hash_algo = hash_t::none) {
        return pk::sign(context(), hash_or_message, hash_algo);
    }

    bool verify(
        const buffer_t& signature,
        const buffer_t& hash_or_message,
        hash_t          hash_algo = hash_t::none) {
        return pk::verify(context(), signature, hash_or_message, hash_algo);
    }

    auto
    encrypt(const buffer_t& hash_or_message, hash_t hash_algo = hash_t::none) {
        return pk::encrypt(context(), hash_or_message, hash_algo);
    }

    auto decrypt(const buffer_t& encrypted_value) {
        return pk::decrypt(context(), encrypted_value);
    }

    void generate_key(size_t key_bitlen, size_t exponent = 65537) {
        pk::generate_rsa_key(context(), key_bitlen, exponent);
    }

public: // key information
    struct key_info {
        mpi N; ///< public modulus
        mpi E; ///< public exponent

        // only valid if the key is a private key
        mpi D;  ///< private exponent
        mpi P;  ///< 1st prime factor
        mpi Q;  ///< 2nd prime factor
        mpi DP; ///< D % (P - 1)
        mpi DQ; ///< D % (Q - 1)
        mpi QP; ///< 1 / (Q % P)
    }; // struct key_info

    // exports info of current key
    void operator>>(key_info&) const;

    auto key_info() const {
        struct key_info ki;
        *this >> ki;
        return ki;
    }

public: // move only
    rsa(const rsa&) = delete;
    rsa(rsa&&)      = default;
    rsa& operator=(const rsa&) = delete;
    rsa& operator=(rsa&&)      = default;

    virtual pk::context&       context() override;
    virtual const pk::context& context() const override;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // rsa
///////////////////////////////////////////////////////////////////////////////

/// helper function, @sa pk::check_pair()
inline bool
check_pair(const rsa& pub, const rsa& pri) {
    return pk::check_pair(pub.context(), pri.context());
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // __MBEDCRYPTO_RSA_HPP__
