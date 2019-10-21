#include "mbedcrypto/hash.hpp"
#include "./conversions.hpp"

#include <mbedtls/md.h>
#include <type_traits>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
//-----------------------------------------------------------------------------
static_assert(std::is_copy_constructible<hash>::value == false, "");
static_assert(std::is_move_constructible<hash>::value == true,  "");
static_assert(std::is_copy_assignable<hash>::value    == false, "");
static_assert(std::is_move_assignable<hash>::value    == true,  "");

static_assert(std::is_copy_constructible<hmac>::value == false, "");
static_assert(std::is_move_constructible<hmac>::value == true,  "");
static_assert(std::is_copy_assignable<hmac>::value    == false, "");
static_assert(std::is_move_assignable<hmac>::value    == true,  "");

//-----------------------------------------------------------------------------

const mbedtls_md_info_t*
find_native_info(hash_t algo) noexcept {
    if (algo == hash_t::unknown)
        return nullptr;
    return mbedtls_md_info_from_type(to_native(algo));
}

//-----------------------------------------------------------------------------

struct impl_base
{
    mbedtls_md_context_t ctx;

    void init() noexcept  { mbedtls_md_init(&ctx); }
    void reset() noexcept { mbedtls_md_free(&ctx); }

    explicit impl_base() noexcept { init(); }
    ~impl_base() { reset(); }

    int setup(const mbedtls_md_info_t* info , bool hmac) noexcept {
        if (ctx.md_info && info && info != ctx.md_info) {
            // it's a new algorithm
            reset();
            init();
        }
        return mbedtls_md_setup(&ctx, info, hmac ? 1 : 0);
    }

    size_t size() const noexcept {
        return ctx.md_info ? mbedtls_md_get_size(ctx.md_info) : 0;
    }
}; // struct impl_base

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

struct hash::impl : impl_base{};
struct hmac::impl : impl_base{};

//-----------------------------------------------------------------------------

size_t
hash_size(hash_t algo) noexcept {
    return mbedtls_md_get_size(find_native_info(algo));
}

std::error_code
make_hash(
    bin_view_t input, hash_t algo, uint8_t* output, size_t& osize) noexcept {
    const auto  capacity = osize;
    const auto* info     = find_native_info(algo);
    osize                = mbedtls_md_get_size(info);
    if (osize == 0) {
        return make_error_code(error_t::not_supported);
    } else if (output == nullptr || capacity == 0) {
    } else if (capacity < osize) {
        return make_error_code(error_t::small_output);
    } else {
        int ret = mbedtls_md(info, input.data, input.size, output);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
    }
    return std::error_code{};
}

std::error_code
make_hmac(
    bin_view_t input,
    bin_view_t key,
    hash_t     algo,
    uint8_t*   output,
    size_t&    osize) noexcept {
    const auto  capacity = osize;
    const auto* info     = find_native_info(algo);
    osize                = mbedtls_md_get_size(info);
    if (osize == 0) {
        return make_error_code(error_t::not_supported);
    } else if (output == nullptr || capacity == 0) {
    } else if (capacity < osize) {
        return make_error_code(error_t::small_output);
    } else {
        int ret = mbedtls_md_hmac(
            info, key.data, key.size, input.data, input.size, output);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
    }
    return std::error_code{};
}

std::error_code
make_file_hash(
    const char* fname, hash_t algo, uint8_t* output, size_t& osize) noexcept {
#if !defined(MBEDTLS_FS_IO)
    osize = 0;
    return make_error_code(error_t::not_supported);
#else
    const auto  capacity = osize;
    const auto* info     = find_native_info(algo);
    osize                = mbedtls_md_get_size(info);
    if (osize == 0) {
        return make_error_code(error_t::not_supported);
    } else if (output == nullptr || capacity == 0) {
    } else if (capacity < osize) {
        return make_error_code(error_t::small_output);
    } else {
        int ret = mbedtls_md_file(info, fname, output);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
    }
    return std::error_code{};
#endif
}

//-----------------------------------------------------------------------------

hash::hash() : pimpl{new impl} {}
hash::~hash() = default;

std::error_code
hash::start(hash_t algo) noexcept {
    const auto* ntype = find_native_info(algo);
    if (ntype == nullptr)
        return make_error_code(error_t::not_supported);
    int ret = pimpl->setup(ntype, false);
    if (ret != 0)
        return mbedtls::make_error_code(ret);
    ret = mbedtls_md_starts(&pimpl->ctx);
    return mbedtls::make_error_code(ret);
}

std::error_code
hash::update(bin_view_t chunk) noexcept {
    int ret = mbedtls_md_update(&pimpl->ctx, chunk.data, chunk.size);
    return mbedtls::make_error_code(ret);
}

std::error_code
hash::finish(uint8_t* output, size_t& osize) noexcept {
    const auto capacity = osize;
    osize               = pimpl->size();
    if (output == nullptr || capacity == 0) {
    } else if (capacity < osize) {
        return make_error_code(error_t::small_output);
    } else {
        int ret = mbedtls_md_finish(&pimpl->ctx, output);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
    }
    return std::error_code{};
}

//-----------------------------------------------------------------------------

hmac::hmac() : pimpl{new impl} {}
hmac::~hmac() = default;

std::error_code
hmac::start(bin_view_t key, hash_t algo) noexcept {
    const auto* ntype = find_native_info(algo);
    if (ntype == nullptr)
        return make_error_code(error_t::not_supported);
    int ret = pimpl->setup(ntype, true);
    if (ret != 0)
        return mbedtls::make_error_code(ret);
    ret = mbedtls_md_hmac_starts(&pimpl->ctx, key.data, key.size);
    return mbedtls::make_error_code(ret);
}

std::error_code
hmac::start() noexcept {
    int ret = mbedtls_md_hmac_reset(&pimpl->ctx);
    return mbedtls::make_error_code(ret);
}

std::error_code
hmac::update(bin_view_t chunk) noexcept {
    int ret = mbedtls_md_hmac_update(&pimpl->ctx, chunk.data, chunk.size);
    return mbedtls::make_error_code(ret);
}

std::error_code
hmac::finish(uint8_t* output, size_t& osize) noexcept {
    const auto capacity = osize;
    osize               = pimpl->size();
    if (output == nullptr || capacity == 0) {
    } else if (capacity < osize) {
        return make_error_code(error_t::small_output);
    } else {
        int ret = mbedtls_md_hmac_finish(&pimpl->ctx, output);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
    }
    return std::error_code{};
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
