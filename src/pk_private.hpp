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
#include "mbedtls/ecp.h"
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
        throw unknown_pk_exception{};

    return pinfot;
}

inline int
random_func(void* ctx, unsigned char* p, size_t len) {
    rnd_generator* rnd = reinterpret_cast<rnd_generator*>(ctx);
    return rnd->make(p, len);
}

///////////////////////////////////////////////////////////////////////////////


auto sign(context&,
        const buffer_t& hash_or_message,
        hash_t hash_algo = hash_t::none) -> buffer_t;

bool verify(context&,
        const buffer_t& signature,
        const buffer_t& hash_or_message,
        hash_t hash_type = hash_t::none);

auto encrypt(context&,
        const buffer_t& hash_or_message,
        hash_t hash_algo = hash_t::none) -> buffer_t;

auto decrypt(context&,
        const buffer_t& encrypted_value) -> buffer_t;

///////////////////////////////////////////////////////////////////////////////
} // namespace pk
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // __PK_PRIVATE_HPP__
