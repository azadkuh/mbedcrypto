/** @file rnd_generator.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.07
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_RND_GENERATOR_HPP
#define MBEDCRYPTO_RND_GENERATOR_HPP

#include "mbedcrypto/types.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/** cryptographically secure pseudo-random byte generator.
 * this feature is based on counter mode deterministic random
 *  byte generator (CTR_DRBG) by AES-256 (NIST SP 800-90) and
 *  internally uses an entropy collection modules.
 * this approach is known to be secure and safe.
 *
 * @warning a not-so-secure random generator is a serious flaw for security.
 * never ever use a generator if it's not been specially certified for
 * cryptography or prepare for the eventual disaster.
 *
 * @warning entropy and random byte generator are not so cheap and fast by the
 *  their nature and depend on OS, hardware, amount of available entropy to the
 *  system at runtime and ... the execution time may differs a lot. so use them
 *  efficiently.
 */
class rnd_generator
{
public:
    /// initializes both entropy collector and CTR_DRBG
    rnd_generator();

    /** optional custom data can be provided in addition to the more generic
     * entropy source.
     *  useful when using random objects (possibly on different threads).
     *  each thread can have a unique custom byte for better security.
     *  This makes sure that the random generators between the different
     *  threads have the least amount of correlation possible and can
     *  thus be considered as independent as possible.
     */
    explicit rnd_generator(const buffer_t& custom);

    ~rnd_generator();

    /** returns a random binary buffer with specified length.
     * @note automatically reseeds if reseed_interval is passed.
     * length can be in any size because underlying class makes random in
     * chunks.
     */
    template<class TBuff = buffer_t>
    TBuff make(size_t length) {
        using length_t = decltype(TBuff().size());
        TBuff rnd_bytes(static_cast<length_t>(length), '\0');
        make(to_ptr(rnd_bytes), length);
        return rnd_bytes;
    }

    /// low level overload
    int make(uint8_t* buffer, size_t length) noexcept;

    /** equivalent for mbedtls_ctr_drbg_random().
     * p_rng must be the address of a rnd_generator instance.
     * @code
     * rnd_generator my_rnd{"ecdsa randomizer"};
     * ret = mbedtls_ecdsa_genkey(&ctx_sign,
     *     ECPARAMS,
     *     rnd_generator::maker,
     *     &my_rnd
     *     );
     * @endcode
     * @sa mbedtls_ctr_drbg_random()
     */
    static int maker(void* p_rng, uint8_t*, size_t);

public: // auxiliary methods
    /** set entropy read length. default: 32/48 (sha256/sha512).
     * based on build configs, uses sha256 or sha512
     */
    void entropy_length(size_t) noexcept;

    /// set reseeding interval. default: 10000 calls
    void reseed_interval(size_t) noexcept;

    /** if set to true, entropy is used with each call!
     * quite expensive but more secure.
     * default: false
     */
    void prediction_resistance(bool) noexcept;

    /// reseeds (extract data from entropy)
    void reseed();
    /// overload with custom data
    void reseed(buffer_view_t custom) {
        reseed(custom.data(), custom.size());
    }
    /// low level overload, nullptr, 0 are valid
    int reseed(const uint8_t* custom, size_t length) noexcept;

    /// updates CTR_DRBG internal state with additional (custom) data
    void update(buffer_view_t additional) {
        update(additional.data(), additional.size());
    }
    /// low level overload
    void update(const uint8_t* additional, size_t length) noexcept;

    // move only
    rnd_generator(const rnd_generator&) = delete;
    rnd_generator(rnd_generator&&)      = default;
    rnd_generator& operator = (const rnd_generator&) = delete;
    rnd_generator& operator = (rnd_generator&&)      = default;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // rnd_generator

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_RND_GENERATOR_HPP
