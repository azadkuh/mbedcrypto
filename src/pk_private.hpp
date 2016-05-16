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
#include "mbedcrypto/mpi.hpp"
#include "mbedcrypto/rnd_generator.hpp"
#include "conversions.hpp"

#include "mbedtls/pk_internal.h"
#include "mbedtls/bignum.h"
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
        reset(*this);
    }

    context(const context&)            = delete;
    context(context&&)                 = default;
    context& operator=(const context&) = delete;
    context& operator=(context&&)      = default;
}; // struct context

///////////////////////////////////////////////////////////////////////////////

inline const mbedtls_pk_info_t*
native_info(pk_t type) {
    const auto* pinfot = mbedtls_pk_info_from_type(to_native(type));

    if ( pinfot == nullptr )
        throw exceptions::unknown_pk{};

    return pinfot;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace pk
///////////////////////////////////////////////////////////////////////////////
struct mpi::impl
{
    mbedtls_mpi ctx_;

public:
    explicit impl() {
        mbedtls_mpi_init(&ctx_);
    }

    ~impl() {
        mbedtls_mpi_free(&ctx_);
    }

    void copy_to(mbedtls_mpi* other) const {
        mbedcrypto_c_call(mbedtls_mpi_copy, other, &ctx_);
    }

    void copy_from(const mbedtls_mpi* other) {
        mbedcrypto_c_call(mbedtls_mpi_copy, &ctx_, other);
    }

    void copy_to(impl& other) const {
        copy_to(&other.ctx_);
    }

    void copy_from(const impl& other) {
        copy_from(&other.ctx_);
    }

}; // struct mpi::impl

///////////////////////////////////////////////////////////////////////////////
/// deep copy
template<> inline void
mpi::operator<<(const mbedtls_mpi& other) {
    pimpl->copy_from(&other);
}

/// deep copy
template<> inline void
mpi::operator>>(mbedtls_mpi& other)const {
    pimpl->copy_to(&other);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // __PK_PRIVATE_HPP__
