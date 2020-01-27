#include "mbedcrypto/hash.hpp"
#include "./private/conversions.hpp"

#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
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
    mbedtls_md_context_t ctx{};

    void init() noexcept  { mbedtls_md_init(&ctx); }
    void reset() noexcept { mbedtls_md_free(&ctx); }

    impl_base() noexcept { init(); }
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
make_hash(bin_edit_t& output, bin_view_t input, hash_t algo) noexcept {
    const auto  capacity = output.size;
    const auto* info     = find_native_info(algo);
    output.size          = mbedtls_md_get_size(info);
    if (output.size == 0) {
        return make_error_code(error_t::not_supported);
    } else if (output.data == nullptr || capacity == 0) {
    } else if (capacity < output.size) {
        return make_error_code(error_t::small_output);
    } else {
        int ret = mbedtls_md(info, input.data, input.size, output.data);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
    }
    return std::error_code{};
}

std::error_code
make_hash(auto_size_t&& output, bin_view_t input, hash_t algo) {
    bin_edit_t exptected;
    auto       ec = make_hash(exptected, input, algo);
    if (ec)
        return ec;
    output.resize(exptected.size);
    return make_hash(static_cast<bin_edit_t&>(output), input, algo);
}

std::error_code
make_hmac(
    bin_edit_t& output,
    bin_view_t  input,
    bin_view_t  key,
    hash_t      algo) noexcept {
    const auto  capacity = output.size;
    const auto* info     = find_native_info(algo);
    output.size          = mbedtls_md_get_size(info);
    if (output.size == 0) {
        return make_error_code(error_t::not_supported);
    } else if (output.data == nullptr || capacity == 0) {
    } else if (capacity < output.size) {
        return make_error_code(error_t::small_output);
    } else {
        int ret = mbedtls_md_hmac(
            info, key.data, key.size, input.data, input.size, output.data);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
    }
    return std::error_code{};
}

std::error_code
make_hmac(auto_size_t&& output, bin_view_t input, bin_view_t key, hash_t algo) {
    bin_edit_t exptected;
    auto       ec = make_hmac(exptected, input, key, algo);
    if (ec)
        return ec;
    output.resize(exptected.size);
    return make_hmac(static_cast<bin_edit_t&>(output), input, key, algo);
}

std::error_code
make_hmac_pbkdf2(
    bin_edit_t& out,
    hash_t      algo,
    bin_view_t  pass,
    bin_view_t  salt,
    size_t      iters) noexcept {
    const auto* info = find_native_info(algo);
    if (info == nullptr || is_empty(out) || is_empty(pass) || iters == 0)
        return make_error_code(error_t::bad_input);
    int         ret  = 0;
    impl_base   d;
    if ((ret = d.setup(info, true)) != 0)
        return mbedtls::make_error_code(ret);
    ret = mbedtls_pkcs5_pbkdf2_hmac(
        &d.ctx,
        pass.data,
        pass.size,
        salt.data,
        salt.size,
        static_cast<unsigned int>(iters),
        static_cast<uint32_t>(out.size),
        out.data);
    if (ret != 0)
        return mbedtls::make_error_code(ret);
    return std::error_code{};
}

std::error_code
make_file_hash(bin_edit_t& output, const char* fname, hash_t algo) noexcept {
#if !defined(MBEDTLS_FS_IO)
    output.size = 0;
    return make_error_code(error_t::not_supported);
#else
    const auto  capacity = output.size;
    const auto* info     = find_native_info(algo);
    output.size          = mbedtls_md_get_size(info);
    if (output.size == 0) {
        return make_error_code(error_t::not_supported);
    } else if (output.data == nullptr || capacity == 0) {
    } else if (capacity < output.size) {
        return make_error_code(error_t::small_output);
    } else {
        int ret = mbedtls_md_file(info, fname, output.data);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
    }
    return std::error_code{};
#endif
}

std::error_code
make_file_hash(auto_size_t&& output, const char* fname, hash_t algo) noexcept {
#if !defined(MBEDTLS_FS_IO)
    return make_error_code(error_t::not_supported);
#else
    bin_edit_t exptected;
    auto       ec = make_file_hash(exptected, fname, algo);
    if (ec)
        return ec;
    output.resize(exptected.size);
    return make_file_hash(static_cast<bin_edit_t&>(output), fname, algo);
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
hash::finish(bin_edit_t& output) noexcept {
    const auto capacity = output.size;
    output.size         = pimpl->size();
    if (output.data == nullptr || capacity == 0) {
    } else if (capacity < output.size) {
        return make_error_code(error_t::small_output);
    } else {
        int ret = mbedtls_md_finish(&pimpl->ctx, output.data);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
    }
    return std::error_code{};
}

std::error_code
hash::finish(auto_size_t&& output) {
    output.resize(pimpl->size());
    return finish(static_cast<bin_edit_t&>(output));
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
hmac::finish(bin_edit_t& output) noexcept {
    const auto capacity = output.size;
    output.size         = pimpl->size();
    if (output.data == nullptr || capacity == 0) {
    } else if (capacity < output.size) {
        return make_error_code(error_t::small_output);
    } else {
        int ret = mbedtls_md_hmac_finish(&pimpl->ctx, output.data);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
    }
    return std::error_code{};
}

std::error_code
hmac::finish(auto_size_t&& output) {
    output.resize(pimpl->size());
    return finish(static_cast<bin_edit_t&>(output));
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
