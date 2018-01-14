/** @file hash.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.05
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_HASH_HPP
#define MBEDCRYPTO_HASH_HPP

#include "mbedcrypto/types.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////
/** a class for computing hash (message digest) values for buffer or files.
 *
 * related cmake build options:
 *  - BUILD_MD2
 *  - BUILD_MD4
 *  - BUILD_RIPEMD160
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
    static size_t length(hash_t type);

    /// makes the hash value for a buffer in single operation
    static buffer_t
    make(hash_t type, buffer_view_t src);

    /// makes the hash value of a file content
    static buffer_t of_file(hash_t type, const char* filePath);

public: // iterative usage, reusing the instance
    explicit hash(hash_t type); ///< throws if type is not supported
    ~hash();

    size_t length() const noexcept;

    /// resets and prepares the object to digest a new message.
    void start();

    /** updates the hash by chunks of data.
     * may be called repeatedly between start() and finish().
     */
    void update(const unsigned char* chunk, size_t chunk_size);

    void update(buffer_view_t chunk) {
        return update(chunk.data(), chunk.size());
    }

    /// returns the final digest of previous updates.
    buffer_t finish();

    // this class is move-only
    hash(const hash&) = delete;
    hash(hash&&)      = default;
    hash& operator=(const hash&) = delete;
    hash& operator=(hash&&)      = default;

#if defined(QT_CORE_LIB)
    static QByteArray make(hash_t type, const QByteArray& src);
#endif // QT_CORE_LIB

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
    static buffer_t make(hash_t type, buffer_view_t key, buffer_view_t src);

public: // iterative or reuse
    explicit hmac(hash_t type);
    ~hmac();

    /// resets and prepares the object to digest a new message.
    void start(buffer_view_t key);
    /// same as above, but does not change the previous key.
    void start();


    /** updates the hash by chunks of data.
     * may be called repeatedly between start() and finish().
     */
    void update(const unsigned char* chunk, size_t chunk_size);

    void update(buffer_view_t chunk) {
        return update(chunk.data(), chunk.size());
    }

    /// returns the final digest of previous updates.
    buffer_t finish();

    // this class is move-only
    hmac(const hmac&) = delete;
    hmac(hmac&&)      = default;
    hmac& operator=(const hmac&) = delete;
    hmac& operator=(hmac&&)      = default;

#if defined(QT_CORE_LIB)
    static QByteArray
    make(hash_t type, const QByteArray& key, const QByteArray& src);
#endif // QT_CORE_LIB

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // hmac

///////////////////////////////////////////////////////////////////////////////

inline size_t
hash_size(hash_t type) {
    return hash::length(type);
}

template <class T>
inline T
make_hash(hash_t type, const T& src) {
    return hash::make(type, src);
}

template<class T>
inline T
make_hmac(hash_t type, const T& key, const T& src) {
    return hmac::make(type, key, src);
}

template <class T>
inline T
to_sha1(const T& src) {
    return hash::make(hash_t::sha1, src);
}

template <class T>
inline T
to_sha256(const T& src) {
    return hash::make(hash_t::sha256, src);
}

template <class T>
inline T
to_sha512(const T& src) {
    return hash::make(hash_t::sha512, src);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_HASH_HPP
