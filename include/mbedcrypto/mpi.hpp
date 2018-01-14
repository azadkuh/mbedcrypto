/** @file mpi.hpp
 *
 * @copyright (C) 2016
 * @date 2016.05.15
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
 * mpi can be a large (4096bit or what so ever) number.
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
    explicit operator bool() const noexcept {
        return bitlen() > 0;
    }
    bool operator==(bool b) const noexcept {
        return static_cast<bool>(*this) == b;
    }
    /// returns the integer size in byte (ex: 512 for a 4096bit integer)
    size_t size() const noexcept;
    /// returns the integer bitsize
    size_t bitlen() const noexcept;

    /// writes the integer into string with defined radix(16 or 10)
    auto to_string(int radix = 16) const -> std::string;
    /// writes the integer into unsigned binary data (big endian)
    auto dump() const -> std::string;

    /** compares the properties of two mpi.
     * returns 1, 0, -1 if a is greater, equal or less than b
     */
    static int compare(const mpi& a, const mpi& b) noexcept;

public: // copy/move-able
    mpi(const mpi&);
    mpi(mpi&&);
    mpi& operator=(const mpi&);
    mpi& operator=(mpi&&);

    // private usage
    template <typename T> void operator<<(const T&);
    template <typename T> void operator>>(T&) const;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // mpi

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////

inline bool
operator==(const mbedcrypto::mpi& a, const mbedcrypto::mpi& b) noexcept {
    return mbedcrypto::mpi::compare(a, b) == 0;
}

inline bool
operator>(const mbedcrypto::mpi& a, const mbedcrypto::mpi& b) noexcept {
    return mbedcrypto::mpi::compare(a, b) > 0;
}

inline bool
operator<(const mbedcrypto::mpi& a, const mbedcrypto::mpi& b) noexcept {
    return mbedcrypto::mpi::compare(a, b) < 0;
}
///////////////////////////////////////////////////////////////////////////////
#endif // __MBEDCRYPTO_MPI_HPP__
