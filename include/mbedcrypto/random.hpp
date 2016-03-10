/** @file random.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.07
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_RANDOM_HPP
#define MBEDCRYPTO_RANDOM_HPP

#include "exception.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/// counter mode deterministic random byte generator (CTR_DRBG).
/// @note mbedtls (mbedcrypto) CTR_DRBG based on AES-256 (NIST SP 800-90) and
///  internally uses an entropy collection modules.
class random
{
public:
    /// initializes both entropy collector and CTR_DRBG
    random();

    /// optional custom data can be provided in addition to the more generic entropy source.
    /// useful when using random objects (possibly on different threads).
    ///  each thread can have a unique custom byte for better security.
    /// This makes sure that the random generators between the different
    ///  threads have the least amount of correlation possible and can
    ///  thus be considered as independent as possible.
    explicit random(const buffer_t& custom);

    ~random();

    /// returns a random binary buffer with specified length
    /// @note automatically reseeds if reseed_interval is passed.
    auto make(size_t length) -> buffer_t;
    /// low level overload
    int  make(unsigned char* buffer, size_t length)noexcept;

public: // auxiliary methods
    /// set entropy read length. default: 32/48 (sha256/sha512).
    /// based on build configs, uses sha256 or sha512
    void entropy_length(size_t) noexcept;
    /// set reseeding interval. default: 10000 calls
    void reseed_interval(size_t) noexcept;
    /// if set to true, entropy is used with each call! quite expensive but more secure.
    /// default: false
    void prediction_resistance(bool) noexcept;

    /// reseeds (extract data from entropy)
    void reseed();
    /// overload with custom data
    void reseed(const buffer_t& custom);
    /// low level overload, nullptr, 0 are valid
    int  reseed(const unsigned char* custom, size_t length) noexcept;

    /// updates CTR_DRBG internal state with additional (custom) data
    void update(const buffer_t& additional);
    /// low level overload
    void update(const unsigned char* additional, size_t length) noexcept;

    // move only
    random(const random&)            = delete;
    random(random&&)                 = default;
    random& operator=(const random&) = delete;
    random& operator=(random&&)      = default;

protected:
    struct impl;
    std::unique_ptr<impl> d_ptr;
}; // random

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_RANDOM_HPP

