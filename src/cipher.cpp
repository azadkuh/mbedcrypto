#include "mbedcrypto/cipher.hpp"
#include "./conversions.hpp"

#include <mbedtls/aesni.h>
#include <mbedtls/cipher.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
//-----------------------------------------------------------------------------
using mode_t = mbedtls_operation_t;
using info_t = cipher::info_t;
//-----------------------------------------------------------------------------

const mbedtls_cipher_info_t*
find_native_info(cipher_t type) noexcept {
    if (type == cipher_t::unknown)
        return nullptr;
    return mbedtls_cipher_info_from_type(to_native(type));
}

bool
is_valid(const info_t& ci, const mbedtls_cipher_info_t* inf) noexcept {
    return (ci.key.size << 3) == inf->key_bitlen // in bit
           && ci.iv.size      == inf->iv_size;
}

//-----------------------------------------------------------------------------

struct impl {
    mbedtls_cipher_context_t ctx_;

    impl() noexcept       { mbedtls_cipher_init(&ctx_);  }
    ~impl()               { mbedtls_cipher_free(&ctx_);  }
    void reset() noexcept { mbedtls_cipher_reset(&ctx_); }

    auto info() const noexcept { return ctx_.cipher_info; }

    std::error_code setup(cipher_t t) noexcept {
        const auto* native = find_native_info(t);
        if (native == nullptr)
            return make_error_code(error_t::bad_cipher);
        return mbedtls::make_error_code(mbedtls_cipher_setup(&ctx_, native));
    }

    std::error_code setup(const info_t& ci, mbedtls_operation_t op) noexcept {
        const auto* inf = find_native_info(ci.type);
        if (inf == nullptr)
            return make_error_code(error_t::usage);
        int ret = mbedtls_cipher_setup(&ctx_, inf);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        // key size in bitlen
        ret = mbedtls_cipher_setkey(&ctx_, ci.key.data, ci.key.size << 3, op);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        ret = mbedtls_cipher_set_iv(&ctx_, ci.iv.data, ci.iv.size);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        ret = try_set_padding(ci.padding);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CHACHAPOLY_C)
        if (!is_empty(ci.ad)) {
            ret = mbedtls_cipher_update_ad(&ctx_, ci.ad.data, ci.ad.size);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
        }
#endif // defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CHACHAPOLY_C)
        return std::error_code{};
    }

    std::error_code
    crypt(bin_edit_t& des, bin_view_t in, const info_t& ci, mode_t m) noexcept {
        const auto* ninf = find_native_info(ci.type);
        if (ninf == nullptr || !is_valid(ci, ninf))
            return make_error_code(error_t::bad_cipher);
        const size_t min_size = // only crypts the fix size for ECB block modes
            in.size + (ninf->mode == MBEDTLS_MODE_ECB ? 0 : ninf->block_size);
        if (des.data == nullptr || des.size == 0) {
            des.size = min_size;
        } else if (des.size < min_size) {
            return make_error_code(error_t::small_output);
        } else {
            int ret = mbedtls_cipher_setup(&ctx_, ninf);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
            ret =
                mbedtls_cipher_setkey(&ctx_, ci.key.data, ci.key.size << 3, m);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
            ret = try_set_padding(ci.padding);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
            ret = mbedtls_cipher_crypt(
                &ctx_,
                ci.iv.size ? ci.iv.data : nullptr,
                ci.iv.size,
                in.data,
                in.size,
                des.data,
                &des.size);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
        }
        return std::error_code{};
    }

    std::error_code
    crypt(obuffer_t&& des, bin_view_t in, const info_t& ci, mode_t m) {
        bin_edit_t expected;
        auto       ec = crypt(expected, in, ci, m);
        if (ec)
            return ec;
        des.resize(expected.size);
        ec = crypt(static_cast<bin_edit_t&>(des), in, ci, m);
        if (!ec) // if there is no error, adjust the exact size
            des.resize(des.size);
        return ec;
    }

    int try_set_padding(padding_t p) noexcept {
        if (p == padding_t::unknown || p == padding_t::none)
            return 0; // no padding is required
        const auto npad = to_native(p);
        return mbedtls_cipher_set_padding_mode(&ctx_, npad);
    }

}; // struct impl

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

size_t
block_size(cipher_t t) noexcept {
    const auto* info = find_native_info(t);
    return info == nullptr ? 0 : info->block_size;
}

size_t
iv_size(cipher_t t) noexcept {
    const auto* info = find_native_info(t);
    return info == nullptr ? 0 : info->iv_size;
}

size_t
key_bitlen(cipher_t t) noexcept {
    const auto* info = find_native_info(t);
    return info == nullptr ? 0 : info->key_bitlen;
}

cipher_bm
block_mode(cipher_t t) noexcept {
    const auto* info = find_native_info(t);
    if (info == nullptr)
        return cipher_bm::unknown;
    return from_native(info->mode);
}

//-----------------------------------------------------------------------------
namespace cipher {
//-----------------------------------------------------------------------------

bool
is_valid(const info_t& ci) noexcept {
    if (ci.type == cipher_t::unknown || is_empty(ci.key))
        return false;
    const auto* info = find_native_info(ci.type);
    return info ? mbedcrypto::is_valid(ci, info) : false;
}

std::error_code
encrypt(bin_edit_t& output, bin_view_t input, const info_t& ci) noexcept {
    return impl{}.crypt(output, input, ci, MBEDTLS_ENCRYPT);
}

std::error_code
encrypt(obuffer_t&& output, bin_view_t input, const info_t& ci) {
    return impl{}.crypt(std::forward<obuffer_t>(output), input, ci, MBEDTLS_ENCRYPT);
}

std::error_code
decrypt(bin_edit_t& output, bin_view_t input, const info_t& ci) noexcept {
    return impl{}.crypt(output, input, ci, MBEDTLS_DECRYPT);
}

std::error_code
decrypt(obuffer_t&& output, bin_view_t input, const info_t& ci) {
    return impl{}.crypt(std::forward<obuffer_t>(output), input, ci, MBEDTLS_DECRYPT);
}

//-----------------------------------------------------------------------------
} // namespace cipher
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
