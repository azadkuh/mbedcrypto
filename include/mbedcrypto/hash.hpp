/** @file hash.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.05
 * @author amir zamani <azadkuh@live.com>
 *
 * related cmake build options:
 *  - MBEDCRYPTO_MD2
 *  - MBEDCRYPTO_MD4
 *  - MBEDCRYPTO_RIPEMD160
 *
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
/// the output,data and output.size should be large enough @sa hash_size()
std::error_code
make_hash(bin_edit_t& output, bin_view_t input, hash_t algorithm) noexcept;
/// overload with contaienr apdapter
std::error_code
make_hash(obuffer_t&& output, bin_view_t input, hash_t algorithm);

/// makes the HMAC of an input/key pair.
std::error_code
make_hmac(
    bin_edit_t& output,
    bin_view_t  input,
    bin_view_t  key,
    hash_t      algorithm) noexcept;
/// overload with contaienr apdapter
std::error_code
make_hmac(
    obuffer_t&& output,
    bin_view_t  input,
    bin_view_t  key,
    hash_t      algorithm);

/// makes the hash value for a file.
/// the output and output_size should be large enough @sa hash_size()
std::error_code
make_file_hash(
    bin_edit_t& output, const char* filename, hash_t algorithm) noexcept;
/// overload with contaienr apdapter
std::error_code
make_file_hash(obuffer_t& output, const char* filename, hash_t algorithm);

//-----------------------------------------------------------------------------

/** a reusable hash utility.
 *
 * @code
 * hash h;
 *
 * h.start(hash_t::sha256);
 * for (...) {
 *     ...
 *     h.update(chunk);
 *     ...
 * }
 * std::vector<uint8_t> digest;
 * h.finish(digest);
 *
 * h.start(hash_t::sha512);
 * h.update(...);
 * h.finish(digest);
 *
 * @endcode
 */
struct hash
{
    /// resets and starts digesting by specified algorithm.
    std::error_code start(hash_t) noexcept;
    /** feeds a chunk of data into an ongoing message-digest computation.
     * call start() before calling this function. you may call this function
     * multiple times. afterwards, call finish().
     */
    std::error_code update(bin_view_t chunk) noexcept;
    /** finishes the digest operation and writes into output.
     * if output.data == nullptr or output.size == 0, returns the required hash
     * size into output.size.
     */
    std::error_code finish(bin_edit_t& output) noexcept;
    /// overload with container adapter
    std::error_code finish(obuffer_t&& output);

    // move only
    hash();
    hash(hash&&) noexcept = default;
    ~hash();
    hash& operator=(hash&&) noexcept = default;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // struct hash

//-----------------------------------------------------------------------------

struct hmac
{
    /// resets and starts digesting by specified algorithm.
    std::error_code start(bin_view_t key, hash_t) noexcept;
    /// resets and restart with the previous settings
    std::error_code start() noexcept;
    /** feeds a chunk of data into an ongoing hmac computation.
     * call start() before calling this function. you may call this function
     * multiple times. afterwards, call finish().
     */
    std::error_code update(bin_view_t chunk) noexcept;
    /** finishes the hmac operation and writes into output.
     * if output.data == nullptr or output.size == 0, returns the required hash
     * size into output.size.
     */
    std::error_code finish(bin_edit_t& output) noexcept;
    /// overload with container adapter
    std::error_code finish(obuffer_t&& output);

    // move only
    hmac();
    hmac(hmac&&) noexcept = default;
    ~hmac();
    hmac& operator=(hmac&&) noexcept = default;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // struct hmac

//-----------------------------------------------------------------------------
// hash overloads

template <class Container>
inline std::pair<Container, std::error_code>
make_hash(bin_view_t input, hash_t algo) {
    Container digest;
    auto      ec = make_hash(obuffer_t{digest}, input, algo);
    return {digest, ec};
}

template <class Container>
inline auto
make_sha1(bin_view_t input) {
    return make_hash<Container>(input, hash_t::sha1);
}

template <class Container>
inline auto
make_sha256(bin_view_t input) {
    return make_hash<Container>(input, hash_t::sha256);
}

template <class Container>
inline auto
make_sha512(bin_view_t input) {
    return make_hash<Container>(input, hash_t::sha512);
}

//-----------------------------------------------------------------------------
// hmac overloads

template <class Container>
inline std::pair<Container, std::error_code>
make_hmac(bin_view_t input, bin_view_t key, hash_t algo) {
    Container digest;
    auto      ec = make_hmac(obuffer_t{digest}, input, key, algo);
    return {digest, ec};
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_HASH_HPP
