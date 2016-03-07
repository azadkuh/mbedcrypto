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


///////////////////////////////////////////////////////////////////////////////

/// helper function used internally for throwing an exception if a c mbedtls function fails.
template<class Func, class... Args> inline void
c_call(Func&& c_func, Args&&... args) {
    auto ret = c_func(std::forward<Args&&>(args)...);
    if ( ret != 0 )
        throw exception(ret, "underlying mbedtls function failed");
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_EXCEPTION_HPP
