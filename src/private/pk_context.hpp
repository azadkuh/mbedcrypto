/** @file pk_context.hpp
 *
 * @copyright (C) 2019
 * @date 2019.11.12
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_PK_CONTEXT_HPP
#define MBEDCRYPTO_PK_CONTEXT_HPP

#include "mbedcrypto/pk.hpp"
#include "./conversions.hpp"
#include "./ctr_drbg.hpp"

#include <mbedtls/pk_internal.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace pk {
//-----------------------------------------------------------------------------

struct context
{
    bool               has_pri_key = false;
    ctr_drbg           rnd;
    mbedtls_pk_context pk;

    context() {
        rnd.setup("mbedcrypto pki implementation");
        mbedtls_pk_init(&pk);
    }

    ~context() {
        pk::reset(*this);
    }

    context(const context&) = delete;
    context(context&&)      = delete;
    context& operator=(const context&) = delete;
    context& operator=(context&&) = delete;
}; // struct context

inline const mbedtls_pk_info_t*
find_native_info(pk_t t) noexcept {
    return t != pk_t::unknown ? mbedtls_pk_info_from_type(to_native(t))
                              : nullptr;
}

//-----------------------------------------------------------------------------
} // namespace pk
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_PK_CONTEXT_HPP
