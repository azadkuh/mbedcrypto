/** @file mbedtls_wrapper.hxx
 *
 * @copyright (C) 2016
 * @date 2016.04.25
 * @author amir zamani <azadkuh@live.com>
 */

#ifndef MBEDTLS_WRAPPER_HXX
#define MBEDTLS_WRAPPER_HXX

#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>

#include <sstream>
#include <stdexcept>

//-----------------------------------------------------------------------------
/** helper c++ utils for adding RAII and exceptions to mbedtls's c api.
 * @sa wrapper for usage example
 */
namespace mbedtls {
namespace details { // forward declarations
//-----------------------------------------------------------------------------
/// mbedtls_xxx_init() wrapper
template <class T, class... Args>
inline void
initializer(T*, Args&&...) noexcept;

/// mbedtls_xxx_free() wraper
template <class T>
inline void
cleanup(T*) noexcept;
} // namespace details
//-----------------------------------------------------------------------------

/// a light RAII wrapper utility for mbedtls high level functions.
template <class T> class wrapper final
{
    T ctx_;

public:
    template <class... Args> explicit wrapper(Args&&... args) {
        using namespace details;
        initializer(&ctx_, std::forward<Args&&>(args)...);
    }

    ~wrapper() {
        using namespace details;
        cleanup(&ctx_);
    }

    const T& ref() const noexcept { return ctx_; }
    const T* ptr() const noexcept { return &ctx_; }
    const T* operator->() const noexcept { return &ctx_; }
    operator const T*() const noexcept { return &ctx_; }
    T& ref() noexcept { return ctx_; }
    T* ptr() noexcept { return &ctx_; }
    T* operator->() noexcept { return &ctx_; }
    operator T*() noexcept { return &ctx_; }

    // move only
    wrapper(const wrapper&) = delete;
    wrapper(wrapper&&)      = default;
    wrapper& operator=(const wrapper&) = delete;
    wrapper& operator=(wrapper&&) = default;
}; // c_wrap

using md      = wrapper<mbedtls_md_context_t>;
using cipher  = wrapper<mbedtls_cipher_context_t>;
using pki     = wrapper<mbedtls_pk_context>;
using rnd_gen = wrapper<mbedtls_ctr_drbg_context>;
using entropy = wrapper<mbedtls_entropy_context>;


//-----------------------------------------------------------------------------
namespace details {

template <>
inline void
initializer(mbedtls_md_context_t* p) noexcept {
    mbedtls_md_init(p);
}

template <>
inline void
initializer(mbedtls_cipher_context_t* p) noexcept {
    mbedtls_cipher_init(p);
}

template <>
inline void
initializer(mbedtls_ctr_drbg_context* p) noexcept {
    mbedtls_ctr_drbg_init(p);
}

template <>
inline void
initializer(mbedtls_entropy_context* p) noexcept {
    mbedtls_entropy_init(p);
}

template <>
inline void
initializer(mbedtls_pk_context* p) noexcept {
    mbedtls_pk_init(p);
}

template <>
inline void
cleanup(mbedtls_md_context_t* p) noexcept {
    mbedtls_md_free(p);
}

template <>
inline void
cleanup(mbedtls_cipher_context_t* p) noexcept {
    mbedtls_cipher_free(p);
}

template <>
inline void
cleanup(mbedtls_ctr_drbg_context* p) noexcept {
    mbedtls_ctr_drbg_free(p);
}

template <>
inline void
cleanup(mbedtls_entropy_context* p) noexcept {
    mbedtls_entropy_free(p);
}

template <>
inline void
cleanup(mbedtls_pk_context* p) noexcept {
    mbedtls_pk_free(p);
}

/** calls the mbedtls function with given arguments.
 * throws a std::runtime_error{} if there is any error
 * @sa wrapper
 */
template <class Func, class... Args>
inline void
c_call_impl(const char* func_name, Func&& c_func, Args&&... args) {

    auto err = c_func(std::forward<Args&&>(args)...);

    if (err != 0) {                      // oops! an error
        constexpr size_t KMaxSize = 160; // max size of error message
        char             buffer[KMaxSize + 1] = {0};
        mbedtls_strerror(err, buffer, KMaxSize);

        std::stringstream ss;
        ss << ((func_name == nullptr) ? "mbedtls" : func_name) << "(-0x"
           << std::hex << -1 * err << "): " << buffer;

        throw std::runtime_error(ss.str());
    }
}

//-----------------------------------------------------------------------------
} // namespace details
} // namespace mbedtls
//-----------------------------------------------------------------------------

/// helper macro, prepends function name as an string
#define mbedtls_c_call(FUNC, ...)                                              \
    mbedtls::details::c_call_impl(#FUNC, FUNC, __VA_ARGS__)

//-----------------------------------------------------------------------------

/** @class mbedtls::wrapper
 * a light RAII wrapper utility for mbedtls high level functions.
 * by using this tool, you do not need to manually free mbedtls
 * contexes as the dtor of mbedtls::wrapper<> will do the job.
 *
 * @warning this wrapper is not used in mbedcrypto directly, only
 * provided for helping low level programming with mbedtls safer and
 * cleaner.
 *
 * usage:
 * @code
 * mbedtls::md md;
 *
 * int err = mbedtls_md_setup(md,
 *                            mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
 *                            0);
 * if ( err != 0 ) {
 *   // handle error
 *   return;
 * }
 *
 * err = mbedtls_md_starts(md);
 * if ( err != 0 ) {
 *   // handle error
 *   return;
 * }
 *
 * ...
 * @endcode
 *
 * or to use std::exceptions:
 * @code
 * try {
 *   mbedtls::md md;
 *
 *   mbedtls_c_call(mbedtls_md_setup,
 *                  md,
 *                  mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
 *                  0);
 *
 *   mbedtls_c_call(mbedtls_md_starts,
 *                  md);
 *   // and so on
 *
 * } catch ( std::exception& cerr ) {
 *   // full mbedtls error code and message
 *   std::cerr << cerr.what() << std::endl;
 * }
 * @endcode
 *
 * for other types simply add following lines to your hpp or cpp code:
 * @code
 * // add RAII for ecdsa:
 * namespace mbedtls {
 * namespace details {
 * template<> inline void initializer(mbedtls_ecdsa_context* ctx) noexcept{
 *     mbedtls_ecdsa_init(ctx);
 * }
 * template<> inline void cleanup(mbedtls_ecdsa_context* ctx) noexcept{
 *     mbedtls_ecdsa_free(ctx);
 * }
 * } // namespace details
 *
 * using ecdsa = wrapper<mbedtls_ecdsa_context>;
 *
 * } // namespace mbedtls
 * @endcode
 */

//-----------------------------------------------------------------------------
#endif // MBEDTLS_WRAPPER_HXX
