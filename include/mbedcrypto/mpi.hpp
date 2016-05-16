/** @file mpi.hpp
 *
 * @copyright (C) 2016
 * @date 2016.05.15
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef __MBEDCRYPTO_MPI_HPP__
#define __MBEDCRYPTO_MPI_HPP__

#include "mbedcrypto/types.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/** multi-precision integer (bignum).
 * used as key parameters for rsa and ecp algorithms.
 * @sa rsa::key_info and @sa ecp::key_info
 */
class mpi
{
public:
   explicit mpi();
   ~mpi();

   /// resets and clears the value
   void reset();

public:
    /// returns true only if the mpi has a valid value
    operator bool()const noexcept { return bitlen() > 0; }
    /// returns the integer size in byte (ex: 512 for a 4096bit integer)
    size_t   size()const noexcept;
    /// returns the integer bitsize
    size_t   bitlen()const noexcept;
    /// writes the integer into string with defined radix(16 or 10)
    auto     to_string(int radix=16)const -> std::string;
    /// writes the integer into unsigned binary data (big endian)
    auto     dump()const -> std::string;

public: // move only
   mpi(const mpi&)            = delete;
   mpi(mpi&&)                 = default;
   mpi& operator=(const mpi&) = delete;
   mpi& operator=(mpi&&)      = default;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
public:
    auto context()const -> const impl&;
    auto context() -> impl&;
}; // mpi
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // __MBEDCRYPTO_MPI_HPP__
