/** @file rsa.hpp
 *
 * @copyright (C) 2016
 * @date 2016.05.07
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
    auto sign(buffer_view_t hash_value, hash_t hash_type) {
        return pk::sign(context(), hash_value, hash_type);
    }

    auto sign_message(buffer_view_t message, hash_t hash_type) {
        return pk::sign_message(context(), message, hash_type);
    }

    bool verify(
        buffer_view_t signature, buffer_view_t hash_value, hash_t hash_type) {
        return pk::verify(context(), signature, hash_value, hash_type);
    }

    bool verify_message(
        buffer_view_t signature, buffer_view_t message, hash_t hash_type) {
        return pk::verify_message(context(), signature, message, hash_type);
    }

    auto
    encrypt(buffer_view_t source) {
        return pk::encrypt(context(), source);
    }

    auto decrypt(buffer_view_t encrypted_value) {
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
