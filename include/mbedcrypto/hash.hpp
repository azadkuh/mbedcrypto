/** @file hash.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.05
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_HASH_HPP
#define MBEDCRYPTO_HASH_HPP

#include <memory>
#include "mbedcrypto/types.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////
class hash
{
public:
    /// returns the length of a hash algorithm in byte.
    static size_t   length(hash_t type);

    /// makes the hash value for a buffer in single operation
    static buffer_t make(hash_t type, const unsigned char* src, size_t src_length);

    static buffer_t make(hash_t type, const buffer_t& src) {
        return make(type,
                reinterpret_cast<const unsigned char*>(src.data()),
                src.size()
                );
    }

    static buffer_t of_file(hash_t type, const char* filePath);

public:
    explicit hash();
    ~hash();


protected:
    class impl;
    std::unique_ptr<impl> d_ptr;
}; // hash

///////////////////////////////////////////////////////////////////////////////

inline size_t   hash_size(hash_t type) {
    return hash::length(type);
}

inline buffer_t make_hash(hash_t type, const buffer_t& src) {
    return hash::make(type, src);
}


///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_HASH_HPP
