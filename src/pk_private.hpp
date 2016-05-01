/** @file pk_private.hpp
 *
 * @copyright (C) 2016
 * @date 2016.05.01
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef __PK_PRIVATE_HPP__
#define __PK_PRIVATE_HPP__
#include "mbedcrypto/pk.hpp"
#include "mbedcrypto/rnd_generator.hpp"
#include "conversions.hpp"

#include "mbedtls/pk_internal.h"
#include "mbedtls/pk.h"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace pk {
///////////////////////////////////////////////////////////////////////////////
auto native_info(pk_t) -> const mbedtls_pk_info_t*;
///////////////////////////////////////////////////////////////////////////////

struct context {
    bool key_is_private_ = false;
    rnd_generator      rnd_{"mbedcrypto pki implementation"};
    mbedtls_pk_context pk_;

    context() {
        mbedtls_pk_init(&pk_);
    }

    ~context() {
        reset();
    }

    void reset() {
        key_is_private_ = false;
        mbedtls_pk_free(&pk_);
    }

    void setup(pk_t type) {
        mbedcrypto_c_call(mbedtls_pk_setup,
                &pk_,
                native_info(type)
                );
    }

    void reset_as(pk_t type) {
        reset();
        setup(type);
    }

    context(const context&)            = delete;
    context(context&&)                 = default;
    context& operator=(const context&) = delete;
    context& operator=(context&&)      = default;
}; // struct context

///////////////////////////////////////////////////////////////////////////////
struct rsa_keygen_exception : public exception {
    explicit rsa_keygen_exception() :
        exception("needs RSA_KEYGEN, check build options"){}
}; // struct rsa_keygen_exception

struct pk_export_exception : public exception {
    explicit pk_export_exception() :
        exception("needs PK_EXPORT, check build options"){}
}; // struct pk_export_exception

struct ecp_exception : public exception {
    explicit ecp_exception() :
        exception("needs EC (elliptic curves), check build options"){}
}; // struct ecp_exception

struct unknown_pk_type : public exception {
    explicit unknown_pk_type() :
        exception(MBEDTLS_ERR_PK_UNKNOWN_PK_ALG, "unsupported pk_t"){}
}; // struct unknown_pk_type
///////////////////////////////////////////////////////////////////////////////

inline const mbedtls_pk_info_t*
native_info(pk_t type) {
    const auto* pinfot = mbedtls_pk_info_from_type(to_native(type));

    if ( pinfot == nullptr )
        throw unknown_pk_type();

    return pinfot;
}


///////////////////////////////////////////////////////////////////////////////
} // namespace pk
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // __PK_PRIVATE_HPP__
