#include "mbedcrypto/rnd_generator.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
//-----------------------------------------------------------------------------

static_assert(std::is_copy_constructible<rnd_generator>::value == false, "");
static_assert(std::is_move_constructible<rnd_generator>::value == true,  "");

int
make_chunked(mbedtls_ctr_drbg_context* ctx, uint8_t* buffer, size_t length) {

    constexpr size_t MaxChunkSize = MBEDTLS_CTR_DRBG_MAX_REQUEST;

    // length is smaller than
    if (length <= MaxChunkSize) {
        return mbedtls_ctr_drbg_random(ctx, buffer, length);
    }

    // needs to make in chunks

    for (size_t i = 0; (i + MaxChunkSize) <= length; i += MaxChunkSize) {
        int ret = mbedtls_ctr_drbg_random(ctx, buffer + i, MaxChunkSize);
        if (ret != 0)
            return ret;
    }

    // last chunk
    size_t residue = length % MaxChunkSize;
    if (residue) {
        int ret =
            mbedtls_ctr_drbg_random(ctx, buffer + length - residue, residue);
        if (ret != 0)
            return ret;
    }

    return 0; // success
}

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

struct rnd_generator::impl {
    mbedtls_entropy_context  entropy_;
    mbedtls_ctr_drbg_context ctx_;

    explicit impl() noexcept {}

    ~impl() {
        mbedtls_entropy_free(&entropy_);
        mbedtls_ctr_drbg_free(&ctx_);
    }

    void setup(const uint8_t* custom, size_t length) {
        mbedtls_entropy_init(&entropy_);

        mbedtls_ctr_drbg_init(&ctx_);
        mbedtls_ctr_drbg_seed(
            &ctx_, mbedtls_entropy_func, &entropy_, custom, length);
        mbedtls_ctr_drbg_set_prediction_resistance(
            &ctx_, MBEDTLS_CTR_DRBG_PR_OFF);
    }

}; // class rnd_generator::imp

//-----------------------------------------------------------------------------

rnd_generator::rnd_generator(const buffer_t& b)
    : pimpl(std::make_unique<impl>()) {
    pimpl->setup(to_const_ptr(b), b.size());
}

rnd_generator::rnd_generator() : pimpl(std::make_unique<impl>()) {
    pimpl->setup(nullptr, 0);
}

rnd_generator::~rnd_generator() {}

void
rnd_generator::entropy_length(size_t len) noexcept {
    mbedtls_ctr_drbg_set_entropy_len(&pimpl->ctx_, len);
}

void
rnd_generator::reseed_interval(size_t interval) noexcept {
    mbedtls_ctr_drbg_set_reseed_interval(
            &pimpl->ctx_, static_cast<int>(interval));
}

void
rnd_generator::prediction_resistance(bool p) noexcept {
    mbedtls_ctr_drbg_set_prediction_resistance(
        &pimpl->ctx_, p ? MBEDTLS_CTR_DRBG_PR_ON : MBEDTLS_CTR_DRBG_PR_OFF);
}

int
rnd_generator::make(uint8_t* buffer, size_t olen) noexcept {
    return make_chunked(&pimpl->ctx_, buffer, olen);
}

int
rnd_generator::maker(void* p_rng, uint8_t* buffer, size_t olen) {
    rnd_generator* ctx = reinterpret_cast<rnd_generator*>(p_rng);
    return ctx->make(buffer, olen);
}

void
rnd_generator::reseed() {
    mbedcrypto_c_call(mbedtls_ctr_drbg_reseed, &pimpl->ctx_, nullptr, 0);
}

int
rnd_generator::reseed(const uint8_t* custom, size_t length) noexcept {
    return mbedtls_ctr_drbg_reseed(&pimpl->ctx_, custom, length);
}

void
rnd_generator::update(const uint8_t* additional, size_t length) noexcept {
    mbedtls_ctr_drbg_update(&pimpl->ctx_, additional, length);
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
