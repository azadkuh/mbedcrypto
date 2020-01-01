/** @file mpi_impl.hpp
 *
 * @copyright (C) 2019
 * @date 2019.11.09
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_MPI_IMPL_HPP
#define MBEDCRYPTO_MPI_IMPL_HPP

#include "mbedcrypto/mpi.hpp"

#include <mbedtls/bignum.h>

//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

struct mpi_impl {
    mbedtls_mpi ctx_;

    mpi_impl() noexcept {
        mbedtls_mpi_init(&ctx_);
    }

    mpi_impl(const mpi_impl& o) noexcept {
        mbedtls_mpi_init(&ctx_);
        mbedtls_mpi_copy(&ctx_, &o.ctx_);
    }

    mpi_impl(mpi_impl&& o) noexcept {
        mbedtls_mpi_init(&ctx_);
        operator=(std::forward<mpi_impl>(o));
    }

    ~mpi_impl() {
        reset();
    }

    void reset() noexcept {
        mbedtls_mpi_free(&ctx_);
    }

    size_t bitlen() const noexcept {
        return mbedtls_mpi_bitlen(&ctx_);
    }

    size_t size() const noexcept {
        return mbedtls_mpi_size(&ctx_);
    }

    mpi_impl& operator=(const mbedtls_mpi& o) noexcept {
        mbedtls_mpi_copy(&ctx_, &o);
        return *this;
    }

    mpi_impl& operator=(const mpi_impl& o) noexcept {
        return operator =(o.ctx_);
    }

    mpi_impl& operator=(mpi_impl&& o) noexcept {
        mbedtls_mpi_swap(&ctx_, &o.ctx_);
        mbedtls_mpi_free(&o.ctx_);
        return *this;
    }

    int compare(const mpi_impl& other) const noexcept {
        return mbedtls_mpi_cmp_mpi(&ctx_, &other.ctx_);
    }

    std::error_code to_string(bin_edit_t& out, int radix) const noexcept {
        size_t olen = 0;
        mbedtls_mpi_write_string(&ctx_, radix, nullptr, 0, &olen);
        if (is_empty(out)) {
            out.size = olen;
        } else if (out.size < olen) {
            return make_error_code(error_t::small_output);
        } else {
            int ret = mbedtls_mpi_write_string(
                &ctx_,
                radix,
                reinterpret_cast<char*>(out.data),
                out.size,
                &olen);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
            out.size = olen;
        }
        return std::error_code{};
    }

    std::error_code to_string(auto_size_t&& out, int radix) const {
        bin_edit_t expected;
        auto       ec = to_string(expected, radix);
        if (ec)
            return ec;
        out.resize(expected.size);
        return to_string(static_cast<bin_edit_t&>(out), radix);
    }

    std::error_code from_string(const char* s, int radix) noexcept {
        int ret = mbedtls_mpi_read_string(&ctx_, radix, s);
        return ret == 0 ? std::error_code{} : mbedtls::make_error_code(ret);
    }

    std::error_code to_binary(bin_edit_t& out) const noexcept {
        if (out.size < size())
            return make_error_code(error_t::small_output);
        int ret = mbedtls_mpi_write_binary(&ctx_, out.data, out.size);
        return ret == 0 ? std::error_code{} : mbedtls::make_error_code(ret);
    }

    std::error_code to_binary(auto_size_t&& out) const {
        out.resize(size());
        return to_binary(static_cast<bin_edit_t&>(out));
    }

    std::error_code from_binary(bin_view_t in) noexcept {
        int ret = mbedtls_mpi_read_binary(&ctx_, in.data, in.size);
        return ret == 0 ? std::error_code{} : mbedtls::make_error_code(ret);
    }

}; // struct mpi_impl

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_MPI_IMPL_HPP
