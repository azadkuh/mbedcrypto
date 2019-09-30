/** @file exception.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.07
 * @author amir zamani <azadkuh@live.com>
 */

#ifndef MBEDCRYPTO_EXCEPTION_HPP
#define MBEDCRYPTO_EXCEPTION_HPP

#include "mbedcrypto/configs.hpp"

#include <stdexcept>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

/// returns as: message(code): error string of err.
/// if err == 0, just returns the message
std::string
mbedtls_error_string(int err, const char* message = nullptr);

//-----------------------------------------------------------------------------

/** the exception used in entire library.
 * reports the exceptional or underlying mbedtls errors.
 */
struct exception : public std::runtime_error {
    using std::runtime_error::runtime_error;

    /// constructs by mbedtls's error code and optional message
    explicit exception(int code, const char* message = "")
        : std::runtime_error(mer(code, message)), code_(code) {}

    /// constructs by mbedtls's error code and a message
    explicit exception(int code, const std::string& message)
        : std::runtime_error(mer(code, message.c_str())), code_(code) {}

    /// converts the error content into readable string
    auto to_string() const {
        return what();
    }

    /// returns the mbedtls error code
    int code() const noexcept {
        return code_;
    }

    /** the error string by mbledtls for the current code_ or an empty string
     * if there is no error (code_ = 0).
     */
    auto error_string() const {
        return mbedtls_error_string(code_);
    }

protected:
    int code_ = 0; ///< mbedtls c-api error code

    static auto mer(int code, const char* message) -> std::string {
        return mbedtls_error_string(code, message);
    }
}; // struct exception

inline auto
to_string(const exception& cerr) {
    return cerr.what();
}

//-----------------------------------------------------------------------------
namespace exceptions {
//-----------------------------------------------------------------------------

/// invalid or unknown type, or conversion error
struct type_error : public exception {
    explicit type_error();
};

/// not supported and/or not implemented yet
struct support_error : public exception {
    explicit support_error();
};

/// wrong usage or invalid argument
struct usage_error : public exception {
    using exception::exception;
};

/// unsupported hash type
struct unknown_hash : public exception {
    explicit unknown_hash();
};

/// unsupported cipher type
struct unknown_cipher : public exception {
    explicit unknown_cipher();
};

/// needs CCM or GCM module, check build options
struct aead_error : public exception {
    explicit aead_error();
};

/// needs GCM module, check build options
struct gcm_error : public exception {
    explicit gcm_error();
};

/// unsupported pk_t or feature
struct unknown_pk : public exception {
    explicit unknown_pk();
};

/// needs PK_EXPORT, check build options
struct pk_export_missed : public exception {
    explicit pk_export_missed();
};

/// needs RSA_KEYGEN, check build options
struct rsa_keygen_missed : public exception {
    explicit rsa_keygen_missed();
};

/// needs EC (elliptic curves), check build options
struct ecp_missed : public exception {
    explicit ecp_missed();
};

//-----------------------------------------------------------------------------
} // namespace exceptions
//-----------------------------------------------------------------------------

/// helper function used internally for throwing an exception if a c mbedtls
/// function fails.
template <class Func, class... Args>
inline void
c_call_impl(const char* error_tag, Func&& c_func, Args&&... args) {
    auto ret = c_func(std::forward<Args&&>(args)...);
    if (ret != 0)
        throw exception(ret, error_tag);
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------

/// helper macro for calling c api of mbedtls in a managed fashion
#define mbedcrypto_c_call(FUNC, ...)                                           \
    mbedcrypto::c_call_impl(#FUNC, FUNC, __VA_ARGS__)

//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_EXCEPTION_HPP
