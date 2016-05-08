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
/** a class for computing hash (message digest) values for buffer or files.
 *
 * related cmake build options:
 *   BUILD_MD2
 *   BUILD_MD4
 *   BUILD_RIPEMD160
 *
 * sample:
 * @code
 *  hash sha1(hash_t::sha1);
 *  ...
 *  sha1.start();
 *  sha1.update(...);
 *  sha1.update(...);
 *  auto h1 = sha1.finish();
 *  sha1.start(); //start again
 *  sha1.update(...); // any updates ...
 *  auto h2 = sha1.finish();
 * @endcode
 *
 */
class hash
{
public: // single-shot hash computation
    /// returns the length of a hash algorithm in byte.
    static size_t   length(hash_t type);

    /// makes the hash value for a buffer in single operation
    static buffer_t make(hash_t type, const unsigned char* src, size_t src_length);

    /// overload
    static buffer_t make(hash_t type, const buffer_t& src) {
        return make(type,
                to_const_ptr(src),
                src.size()
                );
    }

    /// makes the hash value of a file content
    static buffer_t of_file(hash_t type, const char* filePath);

public: // iterative usage, reusing the instance
    explicit hash(hash_t type);
    ~hash();

    /// resets and prepares the object to digest a new message.
    void start();

    /** updates the hash by chunks of data.
     * may be called repeatedly between start() and finish().
     */
    void update(const unsigned char* chunk, size_t chunk_size);

    void update(const buffer_t& chunk) {
        return update(to_const_ptr(chunk), chunk.size());
    }

    /// returns the final digest of previous updates.
    buffer_t finish();

    // this class is move-only
    hash(const hash&) = delete;
    hash(hash&&)      = default;
    hash& operator=(const hash&) = delete;
    hash& operator=(hash&&)      = default;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // hash

///////////////////////////////////////////////////////////////////////////////

/** HMAC (hash-based message authentication code) implementation.
 * use the available hash algorithms to compute hmac value.
 *
 * sample:
 * @code
 *  hmac hms(hash_t::sha256);
 *  ...
 *  hms.start("an string or binary key"); // a key is mandatory for first time
 *  hms.update(...);
 *  hms.update(...);
 *  auto h1 = hms.finish();
 *  hms.start(); // do not change the previous key
 *  hms.update(...); // multiple updates ...
 *  hms.update(...);
 *  auto h2 = hms.finish();
 * @endcode
 *
 */
class hmac
{
public: // single-shot hamc computation
    /** makes a generic HMAC checksum by custom key.
     * HMAC key could be of any size
     */
    static buffer_t make(hash_t type, const buffer_t& key,
            const unsigned char* src, size_t src_length);

    /// overload
    static buffer_t make(hash_t type, const buffer_t& key, const buffer_t& src) {
        return make(type, key, to_const_ptr(src), src.size());
    }

public: // iterative or reuse

    explicit hmac(hash_t type);
    ~hmac();

    /// resets and prepares the object to digest a new message.
    void start(const buffer_t& key);
    /// same as above, but does not change the previous key.
    void start();


    /** updates the hash by chunks of data.
     * may be called repeatedly between start() and finish().
     */
    void update(const unsigned char* chunk, size_t chunk_size);

    void update(const buffer_t& chunk) {
        return update(to_const_ptr(chunk), chunk.size());
    }

    /// returns the final digest of previous updates.
    buffer_t finish();

    // this class is move-only
    hmac(const hmac&) = delete;
    hmac(hmac&&)      = default;
    hmac& operator=(const hmac&) = delete;
    hmac& operator=(hmac&&)      = default;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
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
