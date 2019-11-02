#include "mbedcrypto/cipher.hpp"
#include "./conversions.hpp"

#include <mbedtls/aesni.h>
#include <mbedtls/cipher.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
//-----------------------------------------------------------------------------
using copmode_t = mbedtls_operation_t;
using cinfo_t   = mbedtls_cipher_info_t;
using info_t    = cipher::info_t;

constexpr size_t MinTagSize = 16;
//-----------------------------------------------------------------------------

const cinfo_t*
find_native_info(cipher_t type) noexcept {
    if (type == cipher_t::unknown)
        return nullptr;
    return mbedtls_cipher_info_from_type(to_native(type));
}

bool
has_padding(padding_t p) noexcept {
    return !(p == padding_t::none || p == padding_t::unknown);
}

bool
is_valid(const info_t& ci, const cinfo_t* inf) noexcept {
    return (ci.key.size << 3) == inf->key_bitlen // in bit
           && ci.iv.size      == inf->iv_size;
}

bool
is_valid(bin_view_t input, const info_t& ci, const cinfo_t* inf) noexcept {
    if (!is_valid(ci, inf))
        return false;
    if (inf->mode == MBEDTLS_MODE_CBC) {
        if ((input.size % inf->block_size) && !has_padding(ci.padding))
            return false; // requires padding when input.size != N * block_size
    }
    if (inf->mode == MBEDTLS_MODE_ECB) {
        if (input.size % inf->block_size)
            return false; // input.size must be N * block_size
    }
    if (inf->mode == MBEDTLS_MODE_CCM && is_empty(ci.ad))
        return false; // requires additional data
    if (inf->mode == MBEDTLS_MODE_CHACHAPOLY && is_empty(ci.ad))
        return false; // requires additional data
    return true;
}

size_t
min_output_size(size_t input, const mbedtls_cipher_info_t& inf) noexcept {
    return input + (inf.mode == MBEDTLS_MODE_CBC ? inf.block_size : 0);
}

//-----------------------------------------------------------------------------

struct engine {
    mbedtls_cipher_context_t ctx_;

    engine() noexcept     { mbedtls_cipher_init(&ctx_);  }
    ~engine()             { mbedtls_cipher_free(&ctx_);  }
    void reset() noexcept { mbedtls_cipher_reset(&ctx_); }

    const auto& info() const noexcept { return *ctx_.cipher_info; }

    std::error_code setup(cipher_t t) noexcept {
        const auto* native = find_native_info(t);
        if (native == nullptr)
            return make_error_code(error_t::bad_cipher);
        return mbedtls::make_error_code(mbedtls_cipher_setup(&ctx_, native));
    }

    std::error_code setup(const info_t& ci, copmode_t op) noexcept {
        const auto* inf = find_native_info(ci.type);
        if (inf == nullptr || !is_valid(ci, inf))
            return make_error_code(error_t::cipher_args);
        int ret = mbedtls_cipher_setup(&ctx_, inf);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CHACHAPOLY_C)
        if (!is_empty(ci.ad)) {
            ret = mbedtls_cipher_update_ad(&ctx_, ci.ad.data, ci.ad.size);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
        }
#endif // defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CHACHAPOLY_C)
        // key size in bitlen
        ret = mbedtls_cipher_setkey(&ctx_, ci.key.data, ci.key.size << 3, op);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        ret = try_set_padding(ci.padding);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        if (ci.iv.size) {
            ret = mbedtls_cipher_set_iv(&ctx_, ci.iv.data, ci.iv.size);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
        }
        return std::error_code{};
    }

    std::error_code update(bin_edit_t& out, bin_view_t in) noexcept {
        const size_t min_size = min_output_size(in.size, info());
        if (is_empty(out)) {
            out.size = min_size;
        } else if (out.size < min_size) {
            return make_error_code(error_t::small_output);
        } else {
            int ret = mbedtls_cipher_update(
                &ctx_, in.data, in.size, out.data, &out.size);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
        }
        return std::error_code{};
    }

    std::error_code update(obuffer_t&& out, bin_view_t in) {
        bin_edit_t expected;
        auto       ec = update(expected, in);
        if (ec)
            return ec;
        out.resize(expected.size);
        ec = update(static_cast<bin_edit_t&>(out), in);
        if (!ec && out.size != expected.size)
            out.resize(out.size);
        return ec;
    }

    std::error_code finish(bin_edit_t& out) noexcept {
        const size_t min_size = info().block_size;
        if (is_empty(out)) {
            out.size = min_size;
        } else if (out.size < min_size) {
            return make_error_code(error_t::small_output);
        } else {
            int ret = mbedtls_cipher_finish(&ctx_, out.data, &out.size);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
        }
        return std::error_code{};
    }

    std::error_code finish(obuffer_t&& out) {
        bin_edit_t expected;
        auto       ec = finish(expected);
        if (ec)
            return ec;
        out.resize(expected.size);
        ec = finish(static_cast<bin_edit_t&>(out));
        if (!ec && out.size != expected.size)
            out.resize(out.size);
        return ec;
    }

    std::error_code
    crypt(bin_edit_t& out, bin_view_t in, const info_t& ci, copmode_t m) noexcept {
        const auto* ninf = find_native_info(ci.type);
        if (ninf == nullptr || !is_valid(in, ci, ninf))
            return make_error_code(error_t::cipher_args);
        const size_t min_size = min_output_size(in.size, *ninf);
        if (is_empty(out)) {
            out.size = min_size;
        } else if (out.size < min_size) {
            return make_error_code(error_t::small_output);
        } else {
            int ret = mbedtls_cipher_setup(&ctx_, ninf);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
            if (ninf->mode == MBEDTLS_MODE_CHACHAPOLY) {
#if defined(MBEDTLS_CHACHAPOLY_C)
                // just right after setup and before any other funcs
                ret = mbedtls_cipher_update_ad(&ctx_, ci.ad.data, ci.ad.size);
                if (ret != 0)
                    return mbedtls::make_error_code(ret);
#endif // MBEDTLS_CHACHAPOLY_C
            }
            ret =
                mbedtls_cipher_setkey(&ctx_, ci.key.data, ci.key.size << 3, m);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
            if (ninf->mode == MBEDTLS_MODE_ECB) {
                // break down to block size
                const auto bsize = ninf->block_size;
                for (size_t idx = 0; idx < in.size; idx += bsize) {
                    size_t written = bsize;
                    ret = mbedtls_cipher_update(
                        &ctx_, in.data + idx, bsize, out.data + idx, &written);
                    if (ret != 0)
                        return mbedtls::make_error_code(ret);
                }
            } else {
                ret = try_set_padding(ci.padding);
                if (ret != 0)
                    return mbedtls::make_error_code(ret);
                ret = mbedtls_cipher_crypt(
                    &ctx_,
                    ci.iv.size ? ci.iv.data : nullptr,
                    ci.iv.size,
                    in.data,
                    in.size,
                    out.data,
                    &out.size);
                if (ret != 0)
                    return mbedtls::make_error_code(ret);
            }
        }
        return std::error_code{};
    }

    std::error_code
    crypt(obuffer_t&& out, bin_view_t in, const info_t& ci, copmode_t m) {
        bin_edit_t expected;
        auto       ec = crypt(expected, in, ci, m);
        if (ec)
            return ec;
        out.resize(expected.size);
        ec = crypt(static_cast<bin_edit_t&>(out), in, ci, m);
        if (!ec && out.size != expected.size) // if there is no error, adjust the exact size
            out.resize(out.size);
        return ec;
    }

    int try_set_padding(padding_t p) noexcept {
        if (!has_padding(p))
            return 0; // no padding is required
        const auto npad = to_native(p);
        return mbedtls_cipher_set_padding_mode(&ctx_, npad);
    }


#if defined(MBEDTLS_CIPHER_MODE_AEAD)
    // authenticated encryptoin/decryption

    std::error_code auth_encrypt(
        bin_edit_t&   out,
        bin_edit_t&   tag,
        bin_view_t    in,
        const info_t& ci) noexcept {
        const auto* ninf = find_native_info(ci.type);
        if (is_empty(ci.ad) || ninf == nullptr || !is_valid(in, ci, ninf))
            return make_error_code(error_t::cipher_args);
        if (is_empty(out) || is_empty(tag)) {
            out.size = in.size;
            tag.size = MinTagSize;
        } else if (out.size < in.size || tag.size < MinTagSize) {
            return make_error_code(error_t::small_output);
        } else {
            int ret = mbedtls_cipher_setup(&ctx_, ninf);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
            ret = mbedtls_cipher_setkey(
                &ctx_, ci.key.data, ci.key.size << 3, MBEDTLS_ENCRYPT);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
            ret = mbedtls_cipher_auth_encrypt(&ctx_,
                ci.iv.data, ci.iv.size,
                ci.ad.data, ci.ad.size,
                in.data,    in.size,
                out.data,   &out.size,
                tag.data,   tag.size);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
        }
        return std::error_code{};
    }

    std::error_code auth_decrypt(
        bin_edit_t&   out,
        bin_view_t    tag,
        bin_view_t    in,
        const info_t& ci) noexcept {
        const auto* ninf = find_native_info(ci.type);
        if (is_empty(ci.ad) || ninf == nullptr || !is_valid(in, ci, ninf))
            return make_error_code(error_t::cipher_args);
        if (tag.size < MinTagSize || is_empty(in))
            return make_error_code(error_t::cipher_args);
        if (is_empty(out)) {
            out.size = in.size;
        } else if (out.size < in.size) {
            return make_error_code(error_t::small_output);
        } else {
            int ret = mbedtls_cipher_setup(&ctx_, ninf);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
            ret = mbedtls_cipher_setkey(
                &ctx_, ci.key.data, ci.key.size << 3, MBEDTLS_DECRYPT);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
            ret = mbedtls_cipher_auth_decrypt(&ctx_,
                ci.iv.data, ci.iv.size,
                ci.ad.data, ci.ad.size,
                in.data,    in.size,
                out.data,   &out.size,
                tag.data,   tag.size);
            if (ret == MBEDTLS_ERR_CIPHER_AUTH_FAILED)
                return make_error_code(error_t::cipher_auth);
            else if (ret != 0)
                return mbedtls::make_error_code(ret);
        }
        return std::error_code{};
    }

    std::error_code auth_encrypt(
        obuffer_t&& out, obuffer_t&& tag, bin_view_t in, const info_t& ci) {
        bin_edit_t oex, tex;
        auto       ec = auth_encrypt(oex, tex, in, ci);
        if (ec)
            return ec;
        out.resize(oex.size);
        tag.resize(tex.size);
        ec = auth_encrypt(
            static_cast<bin_edit_t&>(out),
            static_cast<bin_edit_t&>(tag),
            in,
            ci);
        if (!ec) {
            if (out.size != oex.size)
                out.resize(out.size);
            if (tag.size != tex.size)
                tag.resize(tag.size);
        }
        return ec;
    }

    std::error_code auth_decrypt(
        obuffer_t&& out, bin_view_t tag, bin_view_t in, const info_t& ci) {
        bin_edit_t expected;
        auto       ec = auth_decrypt(expected, tag, in, ci);
        if (ec)
            return ec;
        out.resize(expected.size);
        ec = auth_decrypt(static_cast<bin_edit_t&>(out), tag, in, ci);
        if (!ec && out.size != expected.size)
            out.resize(out.size);
        return ec;
    }

#endif // defined(MBEDTLS_CIPHER_MODE_AEAD)

}; // struct engine

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
    return engine{}.crypt(output, input, ci, MBEDTLS_ENCRYPT);
}

std::error_code
encrypt(obuffer_t&& output, bin_view_t input, const info_t& ci) {
    return engine{}.crypt(std::forward<obuffer_t>(output), input, ci, MBEDTLS_ENCRYPT);
}

std::error_code
decrypt(bin_edit_t& output, bin_view_t input, const info_t& ci) noexcept {
    return engine{}.crypt(output, input, ci, MBEDTLS_DECRYPT);
}

std::error_code
decrypt(obuffer_t&& output, bin_view_t input, const info_t& ci) {
    return engine{}.crypt(std::forward<obuffer_t>(output), input, ci, MBEDTLS_DECRYPT);
}

std::error_code
auth_encrypt(
    bin_edit_t&   output,
    bin_edit_t&   tag,
    bin_view_t    input,
    const info_t& ci) noexcept {
#if defined(MBEDTLS_CIPHER_MODE_AEAD)
    return engine{}.auth_encrypt(output, tag, input, ci);
#else
    return make_error_code(error_t::not_supported);
#endif
}

std::error_code
auth_encrypt(
    obuffer_t&&   out,
    obuffer_t&&   tag,
    bin_view_t    in,
    const info_t& ci) noexcept {
#if defined(MBEDTLS_CIPHER_MODE_AEAD)
    return engine{}.auth_encrypt(
        std::forward<obuffer_t>(out), std::forward<obuffer_t>(tag), in, ci);
#else
    return make_error_code(error_t::not_supported);
#endif
}

std::error_code
auth_decrypt(
    bin_edit_t&   output,
    bin_view_t    tag,
    bin_view_t    input,
    const info_t& ci) noexcept {
#if defined(MBEDTLS_CIPHER_MODE_AEAD)
    return engine{}.auth_decrypt(output, tag, input, ci);
#else
    return make_error_code(error_t::not_supported);
#endif
}

/// overload with contaienr adapter.
std::error_code
auth_decrypt(
    obuffer_t&&   out,
    bin_view_t    tag,
    bin_view_t    in,
    const info_t& ci) noexcept {
#if defined(MBEDTLS_CIPHER_MODE_AEAD)
    return engine{}.auth_decrypt(std::forward<obuffer_t>(out), tag, in, ci);
#else
    return make_error_code(error_t::not_supported);
#endif
}

//-----------------------------------------------------------------------------

struct stream::impl : public engine {};

stream::stream() : pimpl{std::make_unique<impl>()} {
}

stream::~stream() = default;


std::error_code
stream::start_encrypt(const info_t& ci) noexcept {
    auto& d = *pimpl;
    d.reset();
    return d.setup(ci, MBEDTLS_ENCRYPT);
}

std::error_code
stream::start_decrypt(const info_t& ci) noexcept {
    auto& d = *pimpl;
    d.reset();
    return d.setup(ci, MBEDTLS_DECRYPT);
}

std::error_code
stream::update(bin_edit_t& out, bin_view_t in) noexcept {
    return pimpl->update(out, in);
}

std::error_code
stream::update(obuffer_t&& out, bin_view_t in) {
    return pimpl->update(std::forward<obuffer_t>(out), in);
}

std::error_code
stream::finish(bin_edit_t& out) noexcept {
    return pimpl->finish(out);
}

std::error_code
stream::finish(obuffer_t&& out) {
    return pimpl->finish(std::forward<obuffer_t>(out));
}

//-----------------------------------------------------------------------------
} // namespace cipher
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
