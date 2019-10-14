/** @file errors.hpp
 *
 * @copyright (C) 2019
 * @date 2019.10.02
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_ERRORS_HPP
#define MBEDCRYPTO_ERRORS_HPP

#include <system_error>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------
namespace mbedtls {

const std::error_category& error_category();

inline auto
error_message(int err) {
    return error_category().message(err);
}

inline auto
make_error_code(int err) {
    return std::error_code{err, error_category()};
}

} // namespace mbedtls
//-----------------------------------------------------------------------------

enum class error_t : int {
    success         = 0,   ///< success: no error
    type            = 1,   ///< invalid or unknown type
    usage           = 2,   ///< bad api call or invalid argument
    not_supported   = 10,  ///< not supported by this build
    invalid_size    = 20,  ///< invalid size
    invalid_content = 21,  ///< invalid content/data
    bad_hash        = 100, ///< invalid or unsupported hash type
    bad_cipher      = 200, ///< invalid or unsupported cipher type
    aead            = 210, ///< requires CCM or GCM modules, check build options
    gcm             = 211, ///< requires CGM module, check build options
    pk              = 500, ///< invalid or unsupported PK type
    pk_export       = 501, ///< requires PE_EXPORT module, check build options
    rsa_keygen      = 502, ///< requires RSA_KEYGEN, check build options
    ecp             = 800, ///< invalid or unsupported EC (elliptic curve) type
    unknown         = -1,  ///< unknown error
}; // enum error_t

//-----------------------------------------------------------------------------

const std::error_category& error_category();

inline auto
make_error_code(error_t err) {
    return std::error_code{static_cast<int>(err), error_category()};
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_ERRORS_HPP
