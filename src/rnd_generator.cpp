#include "mbedcrypto/rnd_generator.hpp"
#include "./private/ctr_drbg.hpp"

//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

struct rnd_generator::impl : ctr_drbg {};

rnd_generator::rnd_generator(bin_view_t ad) : pimpl{std::make_unique<impl>()} {
    pimpl->setup(ad);
}

rnd_generator::~rnd_generator() = default;

std::error_code
rnd_generator::make(bin_edit_t& out) noexcept {
    return pimpl->make(out);
}

std::error_code
rnd_generator::reseed(bin_view_t cd) noexcept {
    int ret = mbedtls_ctr_drbg_reseed(&pimpl->ctx_, cd.data, cd.size);
    return ret == 0 ? std::error_code{} : mbedtls::make_error_code(ret);
}

std::error_code
rnd_generator::update(bin_view_t ad) noexcept {
    int ret = mbedtls_ctr_drbg_update_ret(&pimpl->ctx_, ad.data, ad.size);
    return ret == 0 ? std::error_code{} : mbedtls::make_error_code(ret);
}

void
rnd_generator::entropy_length(size_t len) noexcept {
    mbedtls_ctr_drbg_set_entropy_len(&pimpl->ctx_, len);
}

void
rnd_generator::reseed_interval(size_t interval) noexcept {
    mbedtls_ctr_drbg_set_reseed_interval(&pimpl->ctx_,
                                         static_cast<int>(interval));
}

void
rnd_generator::prediction_resistance(bool p) noexcept {
    mbedtls_ctr_drbg_set_prediction_resistance(
        &pimpl->ctx_, p ? MBEDTLS_CTR_DRBG_PR_ON : MBEDTLS_CTR_DRBG_PR_OFF);
}

//-----------------------------------------------------------------------------

std::error_code
make_random_bytes(bin_edit_t& out) noexcept {
    thread_local static std::unique_ptr<ctr_drbg> inst{};
    if (!inst) {
        inst = std::make_unique<ctr_drbg>();
        inst->setup({});
    }
    return inst->make(out);
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
