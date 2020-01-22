/** @file rnd_generator.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.07
 * @author amir zamani <azadkuh@live.com>
 *
 * cryptographically secure pseudo-random byte generator.
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

#ifndef MBEDCRYPTO_RND_GENERATOR_HPP
#define MBEDCRYPTO_RND_GENERATOR_HPP

#include "mbedcrypto/binutils.hpp"
#include "mbedcrypto/errors.hpp"

#include <memory>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

/// makes and writes output.size of random bytes into output.data
std::error_code make_random_bytes(bin_edit_t& output) noexcept;

inline auto
make_random_bytes(auto_size_t&& output, size_t length) {
    output.resize(length);
    return make_random_bytes(static_cast<bin_edit_t&>(output));
}

template <typename Container>
inline std::pair<Container, std::error_code>
make_random_bytes(size_t length) {
    Container out;
    auto      ec = make_random_bytes(auto_size_t{out}, length);
    return {out, ec};
}

//-----------------------------------------------------------------------------

/// a utility class with more properties and custom seeds.
class rnd_generator
{
public:
    /** optional custom data can be provided in addition to the more generic
     * entropy source.
     * useful when using random objects (possibly on different threads).
     * each thread can have a unique custom byte for better security.
     * This makes sure that the random generators between the different threads
     * have the least amount of correlation possible and can thus be considered
     * as independent as possible.
     */
    explicit rnd_generator(bin_view_t custom);

    /// initializes both entropy collector and CTR_DRBG
    rnd_generator() : rnd_generator{bin_view_t{}} {}

    ~rnd_generator();

    /// makes and writes output.size of random bytes into ouput.data
    std::error_code make(bin_edit_t& output) noexcept;

    inline auto make(auto_size_t&& output, size_t length) {
        output.resize(length);
        return make(static_cast<bin_edit_t&>(output));
    }

    /// low level overload, empty bin_view_t is also valid
    std::error_code reseed(bin_view_t custom_data) noexcept;

    /// reseeds (extract data from entropy)
    std::error_code reseed() noexcept { return reseed(bin_view_t{}); }

    /// updates CTR_DRBG internal state with additional (custom) data
    std::error_code update(bin_view_t additional_data) noexcept;

public: // properties
    /** set entropy read length.
     * default: 32/48 (sha256/sha512).
     * based on build configs, uses sha256 or sha512
     */
    void entropy_length(size_t) noexcept;

    /// set reseeding interval. default: 10000 calls
    void reseed_interval(size_t) noexcept;

    /** if set to true, entropy is gathered before each call.
     * default: false
     * @warning: only use this if you have ample supply of good entropy, or the
     * random byte generation would be slow and expensive.
     */
    void prediction_resistance(bool) noexcept;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // class rnd_generator

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_RND_GENERATOR_HPP
