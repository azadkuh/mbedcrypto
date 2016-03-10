#include "mbedcrypto/random.hpp"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<random>::value == false, "");
static_assert(std::is_move_constructible<random>::value == true , "");

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

struct random::impl
{
    mbedtls_entropy_context   entropy_;
    mbedtls_ctr_drbg_context  ctx_;

    explicit impl() noexcept {
    }

    ~impl() {
        mbedtls_entropy_free(&entropy_);
        mbedtls_ctr_drbg_free(&ctx_);
    }

    void setup(const unsigned char* custom, size_t length) {
        mbedtls_entropy_init(&entropy_);
        mbedtls_ctr_drbg_init(&ctx_);
        mbedtls_ctr_drbg_seed(
                &ctx_,
                mbedtls_entropy_func,
                &entropy_,
                custom, length
                );
        mbedtls_ctr_drbg_set_prediction_resistance(
                &ctx_,
                MBEDTLS_CTR_DRBG_PR_OFF
                );
    }

}; // class random::imp

///////////////////////////////////////////////////////////////////////////////
random::random(const buffer_t& b) : pimpl(std::make_unique<impl>()) {
    pimpl->setup(reinterpret_cast<const unsigned char*>(b.data()), b.size());
}

random::random() : pimpl(std::make_unique<impl>()) {
    pimpl->setup(nullptr, 0);
}

random::~random() {
}

void
random::entropy_length(size_t len) noexcept {
    mbedtls_ctr_drbg_set_entropy_len(&pimpl->ctx_, len);
}

void
random::reseed_interval(size_t interval) noexcept {
    mbedtls_ctr_drbg_set_reseed_interval(&pimpl->ctx_, interval);
}

void
random::prediction_resistance(bool p) noexcept {
    mbedtls_ctr_drbg_set_prediction_resistance(
            &pimpl->ctx_,
            p ? MBEDTLS_CTR_DRBG_PR_ON : MBEDTLS_CTR_DRBG_PR_OFF
            );
}

int
random::make(unsigned char* buffer, size_t length) noexcept {
    return mbedtls_ctr_drbg_random(
            &pimpl->ctx_,
            buffer,
            length
            );
}

buffer_t
random::make(size_t length) {
    buffer_t buf(length, '\0');
    c_call(mbedtls_ctr_drbg_random,
            &pimpl->ctx_,
            reinterpret_cast<unsigned char*>(&buf.front()),
            length
          );

    return buf;
}

void
random::reseed() {
    c_call(mbedtls_ctr_drbg_reseed,
            &pimpl->ctx_, nullptr, 0
          );
}

void
random::reseed(const buffer_t& custom) {
    c_call(mbedtls_ctr_drbg_reseed,
            &pimpl->ctx_,
            reinterpret_cast<const unsigned char*>(custom.data()),
            custom.size()
          );
}

int
random::reseed(const unsigned char* custom, size_t length) noexcept {
    return mbedtls_ctr_drbg_reseed(&pimpl->ctx_, custom, length);
}

void
random::update(const buffer_t& additional) {
    mbedtls_ctr_drbg_update(
            &pimpl->ctx_,
            reinterpret_cast<const unsigned char*>(additional.data()),
            additional.size()
          );
}

void
random::update(const unsigned char* additional, size_t length) noexcept {
    mbedtls_ctr_drbg_update(
            &pimpl->ctx_, additional, length
            );
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
