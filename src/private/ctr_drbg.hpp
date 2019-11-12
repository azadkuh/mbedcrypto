/** @file ctr_drbg.hpp
 *
 * @copyright (C) 2019
 * @date 2019.11.12
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_CTR_DRBG_HPP
#define MBEDCRYPTO_CTR_DRBG_HPP

#include "mbedcrypto/binutils.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

// make chunks of random data and fill output buffer
inline int
feed_all(mbedtls_ctr_drbg_context* ctx, bin_edit_t& out) noexcept {
    constexpr size_t MaxChunkSize = MBEDTLS_CTR_DRBG_MAX_REQUEST;
    auto* start = out.data;
    auto* end   = out.data + out.size;
    while (start < end) {
        const auto*  next = start + MaxChunkSize;
        const size_t len  = next < end ? MaxChunkSize : (end - start);
        int          ret  = mbedtls_ctr_drbg_random(ctx, start, len);
        if (ret != 0)
            return ret;
        start += len;
    }
    return 0; // success
}

//-----------------------------------------------------------------------------

struct ctr_drbg
{
    mbedtls_entropy_context  entropy_;
    mbedtls_ctr_drbg_context ctx_;

    ctr_drbg() noexcept = default;

    ~ctr_drbg() {
        mbedtls_entropy_free(&entropy_);
        mbedtls_ctr_drbg_free(&ctx_);
    }

    void setup(bin_view_t ad) noexcept {
        mbedtls_entropy_init(&entropy_);
        mbedtls_ctr_drbg_init(&ctx_);
        mbedtls_ctr_drbg_seed(
            &ctx_, mbedtls_entropy_func, &entropy_, ad.data, ad.size);
        mbedtls_ctr_drbg_set_prediction_resistance(&ctx_,
                                                   MBEDTLS_CTR_DRBG_PR_OFF);
    }

    std::error_code make(bin_edit_t& out) noexcept {
        if (is_empty(out))
            return make_error_code(error_t::small_output);
        int ret = feed_all(&ctx_, out);
        return ret == 0 ? std::error_code{} : mbedtls::make_error_code(ret);
    }
}; // struct ctr_drbg

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_CTR_DRBG_HPP
