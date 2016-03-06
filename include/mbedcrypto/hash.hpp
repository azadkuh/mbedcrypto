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

    /// overload
    static buffer_t make(hash_t type, const buffer_t& src) {
        return make(type,
                reinterpret_cast<const unsigned char*>(src.data()),
                src.size()
                );
    }

    /// makes the hash value of a file content
    static buffer_t of_file(hash_t type, const char* filePath);

public:
    explicit hash(hash_t type);
    ~hash();

    /// resets and prepares the object to digest a new message.
    void start();

    /// updates the hash by chunks of data.
    /// may be called repeatedly between start() and finish().
    void update(const unsigned char* chunk, size_t chunk_size);

    void update(const buffer_t& chunk) {
        return update(reinterpret_cast<const unsigned char*>(chunk.data()),
                chunk.size()
                );
    }

    /// returns the final digest of previous updates.
    buffer_t finish();

protected:
    struct impl;
    std::unique_ptr<impl> d_ptr;
}; // hash

///////////////////////////////////////////////////////////////////////////////

class hmac
{
public:
    /// makes a generic HMAC checksum by custom key.
    /// HMAC key size could be of any size
    static buffer_t make(hash_t type, const buffer_t& key,
            const unsigned char* src, size_t src_length);

    /// overload
    static buffer_t make(hash_t type, const buffer_t& key, const buffer_t& src) {
        return make(type, key,
                reinterpret_cast<const unsigned char*>(src.data()),
                src.size()
                );
    }

public:
    explicit hmac(hash_t type);
    ~hmac();

    /// resets and prepares the object to digest a new message.
    void start(const buffer_t& key);
    /// same as above, but does not change the previous key.
    void start();


    /// updates the hash by chunks of data.
    /// may be called repeatedly between start() and finish().
    void update(const unsigned char* chunk, size_t chunk_size);

    void update(const buffer_t& chunk) {
        return update(reinterpret_cast<const unsigned char*>(chunk.data()),
                chunk.size()
                );
    }

    /// returns the final digest of previous updates.
    buffer_t finish();

protected:
    struct impl;
    std::unique_ptr<impl> d_ptr;
}; // hmac

///////////////////////////////////////////////////////////////////////////////

inline size_t   hash_size(hash_t type) {
    return hash::length(type);
}

inline buffer_t make_hash(hash_t type, const buffer_t& src) {
    return hash::make(type, src);
}

inline buffer_t make_hmac(hash_t type, const buffer_t& key,
        const buffer_t& src) {
    return hmac::make(type, key, src);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_HASH_HPP
