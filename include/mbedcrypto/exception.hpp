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

/// the exception used in entire library
struct exception : public std::runtime_error
{
    using std::runtime_error::runtime_error;

    explicit exception(int code, const char* message = "")
        : std::runtime_error(message), code_(code) {}

    explicit exception(int code, const std::string& message)
        : std::runtime_error(message), code_(code) {}

    int     code()const noexcept { return code_;}

    /// mbedtls error string for code_, empty if code_ is not available (0)
    auto    error_string()const -> std::string;

    /// returns as: what (code): error_string
    /// remove each part if it's not specified
    auto    to_string()const -> std::string;

protected:
    int     code_ = 0; ///< mbedtls c-api error code
}; // struct exception

inline auto to_string(const exception& cerr) {
    return cerr.to_string();
}
///////////////////////////////////////////////////////////////////////////////
/// returns as: (code): error string
auto mbedtls_error_string(int err) -> std::string;

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
