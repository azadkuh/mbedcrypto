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

public: // key generation

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
