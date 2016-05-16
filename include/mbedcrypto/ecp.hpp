/** @file ecp.hpp
 *
 * @copyright (C) 2016
 * @date 2016.05.08
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef __MBEDCRYPTO_ECP_HPP__
#define __MBEDCRYPTO_ECP_HPP__
#include "mbedcrypto/pk.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/** elliptic curve (ec) for public key cryptography.
 * to use this ec you must build mbedcrypto with:
 *  - BUILD_EC
 *  - BUILD_ECDSA
 *  other related options:
 *  - BUILD_PK_EXPORT
 * @sa cmake options
 */
class ecp : public pk::pk_base
{
public:
    /// contructs with one of pk_t::eckey, eckey_dh or ecdsa
    explicit ecp(pk_t ptype = pk_t::eckey);

    ~ecp();

public: // helper funtions for ec functionalities
    void generate_key(curve_t curve_type) {
        pk::generate_ec_key(context(), curve_type);
    }

public: // key information
    struct key_info {
        mpi Qx;  ///< x of public point
        mpi Qy;  ///< y of public point
        mpi Qz;  ///< z of public point

        // only valid if the key is a private key
        mpi D;   ///< secret value
    }; // struct key_info

    // exports info of current key
    void operator>>(key_info&)const;

public: // move only
    ecp(const ecp&) = delete;
    ecp(ecp&&)      = default;
    ecp& operator=(const ecp&) = delete;
    ecp& operator=(ecp&&)      = default;

    virtual pk::context& context() override;
    virtual const pk::context& context()const override;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // ecp
///////////////////////////////////////////////////////////////////////////////

/// helper function, @sa pk::check_pair()
inline bool
check_pair(const ecp& pub, const ecp& pri) {
    return pk::check_pair(pub.context(), pri.context());
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // __MBEDCRYPTO_ECP_HPP__
