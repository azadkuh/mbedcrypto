/** @file mbedtls_wrapper.hxx
 *
 * @copyright (C) 2016
 * @date 2016.04.25
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
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
 * int err = mbedtls_md_setup(md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
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
 * or
 * @code
 * try {
 *   mbedtls::md md;
 *   mbedtls_c_call(mbedtls_md_setup, md,
 *                  mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
 *   mbedtls_c_call(mbedtls_md_starts, md);
 *   ...
 * } catch ( std::exception& cerr ) {
 *   std::cerr << cerr.what() << std::endl;
 * }
 */

#ifndef __MBEDTLS_WRAPPER_HXX__
#define __MBEDTLS_WRAPPER_HXX__

#include <stdexcept>
#include <sstream>

#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"

///////////////////////////////////////////////////////////////////////////////
namespace mbedtls {

    namespace details { // forward declarations
        template<class T, class... Args> inline
        void initializer(T*, Args&&...) noexcept;

        template<class T> inline
        void cleanup(T*) noexcept;
    } // namespace details

    template<class T>
    class wrapper final
    {
        T      data;

    public:
        template<class... Args>
        explicit wrapper(Args&&... args) {
            using namespace details;
            initializer(&data, std::forward<Args&&>(args)...);
        }

        ~wrapper() {
            using namespace details;
            cleanup(&data);
        }

        T&  ref() noexcept     { return data;  }
        T*  ptr() noexcept     { return &data; }
        operator T*() noexcept { return &data; }

        wrapper(const wrapper&)            = delete;
        wrapper(wrapper&&)                 = default;
        wrapper& operator=(const wrapper&) = delete;
        wrapper& operator=(wrapper&&)      = default;
    }; // c_wrap

    using md      = wrapper<mbedtls_md_context_t>;
    using cipher  = wrapper<mbedtls_cipher_context_t>;
    using pki     = wrapper<mbedtls_pk_context>;
    using rnd_gen = wrapper<mbedtls_ctr_drbg_context>;
    using entropy = wrapper<mbedtls_entropy_context>;


    namespace details {

        template<> inline void initializer(mbedtls_md_context_t* p) noexcept {
            mbedtls_md_init(p);
        }

        template<> inline void initializer(mbedtls_cipher_context_t* p) noexcept {
            mbedtls_cipher_init(p);
        }

        template<> inline void initializer(mbedtls_ctr_drbg_context* p) noexcept {
            mbedtls_ctr_drbg_init(p);
        }

        template<> inline void initializer(mbedtls_entropy_context* p) noexcept {
            mbedtls_entropy_init(p);
        }

        template<> inline void initializer(mbedtls_pk_context* p) noexcept {
            mbedtls_pk_init(p);
        }

        template<> inline void cleanup(mbedtls_md_context_t* p) noexcept {
            mbedtls_md_free(p);
        }

        template<> inline void cleanup(mbedtls_cipher_context_t* p) noexcept {
            mbedtls_cipher_free(p);
        }

        template<> inline void cleanup(mbedtls_ctr_drbg_context* p) noexcept {
            mbedtls_ctr_drbg_free(p);
        }

        template<> inline void cleanup(mbedtls_entropy_context* p) noexcept {
            mbedtls_entropy_free(p);
        }

        template<> inline void cleanup(mbedtls_pk_context* p) noexcept {
            mbedtls_pk_free(p);
        }

        template<class Func, class... Args> inline
        void c_call_impl(const char* func_name, Func&& c_func, Args&&... args) {

                auto err = c_func(std::forward<Args&&>(args)...);

                if ( err != 0 ) {
                    constexpr size_t KMaxSize = 160;
                    char buffer[KMaxSize+1] = {0};
                    mbedtls_strerror(err, buffer, KMaxSize);

                    std::stringstream ss;
                    ss << ((func_name == nullptr) ? "mbedtls" : func_name)
                        << "(-0x" << std::hex << -1*err << "): "
                        << buffer;

                    throw std::runtime_error(ss.str());
                }
            }
    } // namespace details

} // namespace mbedtls

///////////////////////////////////////////////////////////////////////////////
#define mbedtls_c_call(FUNC, ...) mbedtls::details::c_call_impl(#FUNC, FUNC, __VA_ARGS__)
///////////////////////////////////////////////////////////////////////////////
#endif // __MBEDTLS_WRAPPER_HXX__
