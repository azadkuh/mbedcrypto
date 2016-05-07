/** @file exception.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.07
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */


#ifndef MBEDCRYPTO_EXCEPTION_HPP
#define MBEDCRYPTO_EXCEPTION_HPP

#include <stdexcept>

#include "configs.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/// returns as: message(code): error string of err
/// if err == 0, just returns the message
auto mbedtls_error_string(int err, const char* message = nullptr) -> std::string;

///////////////////////////////////////////////////////////////////////////////
/// the exception used in entire library
struct exception : public std::runtime_error
{
    using std::runtime_error::runtime_error;

    explicit exception(int code, const char* message = "")
        : std::runtime_error(mer(code, message)), code_(code) {}

    explicit exception(int code, const std::string& message)
        : std::runtime_error(mer(code, message.c_str())), code_(code) {}

    auto to_string()const { return what(); }

    int  code()const noexcept { return code_;}

    /// mbedtls error string for code_, empty if code_ is not available (0)
    auto error_string()const { return mbedtls_error_string(code_); }

protected:
    int code_ = 0; ///< mbedtls c-api error code

    static auto mer(int code, const char* message) -> std::string {
        return mbedtls_error_string(code, message);
    }
}; // struct exception

inline auto to_string(const exception& cerr) {
    return cerr.what();
}
///////////////////////////////////////////////////////////////////////////////

/// invalid or unknown type
struct type_exception : public exception {
    explicit type_exception();
};

/// not supported and/or not implemented yet
struct support_exception : public exception {
    explicit support_exception();
};

/// wrong usage or invalid argument
struct usage_exception : public exception {
    using exception::exception;
};

struct unknown_hash_exception : public exception {
    explicit unknown_hash_exception();
};

/// unsupported cipher type of feature
struct unknown_cipher_exception : public exception {
    explicit unknown_cipher_exception();
};

/// needs CCM or GCM module, check build options
struct aead_exception : public exception {
    explicit aead_exception();
};

/// needs GCM module, check build options
struct gcm_exception : public exception {
    explicit gcm_exception();
};

/// unsupported pk_t or feature
struct unknown_pk_exception : public exception {
    explicit unknown_pk_exception();
};

/// needs PK_EXPORT, check build options
struct pk_export_exception : public exception {
    explicit pk_export_exception();
};

/// needs RSA_KEYGEN, check build options
struct rsa_keygen_exception : public exception {
    explicit rsa_keygen_exception();
};

/// needs EC (elliptic curves), check build options
struct ecp_exception : public exception {
    explicit ecp_exception();
};

///////////////////////////////////////////////////////////////////////////////
/// helper function used internally for throwing an exception if a c mbedtls function fails.
template<class Func, class... Args> inline void
c_call_impl(const char* error_tag, Func&& c_func, Args&&... args) {
    auto ret = c_func(std::forward<Args&&>(args)...);
    if ( ret != 0 )
        throw exception(ret, error_tag);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
#define mbedcrypto_c_call(FUNC, ...) \
    mbedcrypto::c_call_impl(#FUNC, FUNC, __VA_ARGS__)
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_EXCEPTION_HPP
