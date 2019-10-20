/** @file hash.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.05
 * @author amir zamani <azadkuh@live.com>
 */

#ifndef MBEDCRYPTO_HASH_HPP
#define MBEDCRYPTO_HASH_HPP

#include "mbedcrypto/types.hpp"
#include "mbedcrypto/binutils.hpp"
#include "mbedcrypto/errors.hpp"

//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

/// returns the length of a hash algorithm in byte or zero as error.
size_t hash_size(hash_t) noexcept;

/// makes the hash value for a buffer in single operation.
/// the output and output_size should be large enough @sa hash_size()
std::error_code
make_hash(
    bin_view_t input,
    hash_t     algorithm,
    uint8_t*   output,
    size_t&    output_size) noexcept;

/// makes the hash value for a file.
/// the output and output_size should be large enough @sa hash_size()
std::error_code
make_file_hash(
    const char* filename,
    hash_t      algorithm,
    uint8_t*    output,
    size_t&     output_size) noexcept;

//-----------------------------------------------------------------------------

struct hash
{
    hash();
    ~hash();

    hash(hash&&) noexcept = default;
    hash& operator=(hash&&) noexcept = default;

    std::error_code start(hash_t) noexcept;
    std::error_code update(bin_view_t chunk) noexcept;
    std::error_code finish(uint8_t* output, size_t& output_size) noexcept;

    template <class Container> auto finish(Container& output) {
        size_t osize = 0;
        finish(nullptr, osize);
        output.resize(osize);
        return finish(reinterpret_cast<uint8_t*>(&output[0]), osize);
    }

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // class hash


//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_HASH_HPP
