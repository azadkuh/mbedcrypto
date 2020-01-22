/** @file mpi.hpp
 *
 * @copyright (C) 2016
 * @date 2016.05.15
 * @author amir zamani <azadkuh@live.com>
 */

#ifndef MBEDCRYPTO_MPI_HPP
#define MBEDCRYPTO_MPI_HPP

#include "mbedcrypto/binutils.hpp"
#include "mbedcrypto/errors.hpp"

#include <memory>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

/** multi-precision integer (bignum).
 * mpi can be a large (4096bit or what so ever) number.
 * used as key parameters for rsa and ecp algorithms.
 * @sa rsa::key_info and @sa ecp::key_info
 */
struct mpi
{
    mpi();
    ~mpi(); ///< also calls reset()

    /// manually resets and clears the value
    void reset() noexcept;

    /// returns the integer size in byte (ex: 512 for a 4096bit integer)
    size_t size() const noexcept;
    /// returns the integer bitsize
    size_t bitlen() const noexcept;

    /// returns true only if the mpi has a valid value
    explicit operator bool() const noexcept {
        return bitlen() > 0;
    }

    /// returns 1, 0, -1 if is greater, equal or less than other
    int compare(const mpi& other) const noexcept;

    /// dumps the MPI as a null-terminated string
    std::error_code to_string(bin_edit_t& out, int radix) const noexcept;
    std::error_code to_string(auto_size_t&& out, int radix) const;

    /// reads from a null-terminated string
    std::error_code from_string(const char* cstr, int radix) noexcept;

    /// dumps the MPI to a portable binary buffer.
    std::error_code to_binary(bin_edit_t& out) const noexcept;
    std::error_code to_binary(auto_size_t&& out) const;

    /// reads from a binary buffer
    std::error_code from_binary(bin_view_t bin) noexcept;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // struct mpi

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_MPI_HPP
