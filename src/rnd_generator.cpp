#include "mbedcrypto/rnd_generator.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
constexpr size_t MaxChunkSize = MBEDTLS_CTR_DRBG_MAX_REQUEST;
//-----------------------------------------------------------------------------

// make chunks of random data and fill output buffer
int
feed_all(mbedtls_ctr_drbg_context* ctx, bin_edit_t& out) noexcept {
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

struct ctr_drbg {
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
} // namespace anon
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

int
rnd_generator::make(void* opaque, uint8_t* buf, size_t len) noexcept {
    bin_edit_t out{buf, len};
    auto&      self = *reinterpret_cast<rnd_generator*>(opaque);
    return feed_all(&self.pimpl->ctx_, out);
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
