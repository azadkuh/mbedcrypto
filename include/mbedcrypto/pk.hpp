/** @file pk.hpp
 *
 * @copyright (C) 2016
 * @date 2016.05.01
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef __PK_HPP__
#define __PK_HPP__
#include "mbedcrypto/types.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace pk {
///////////////////////////////////////////////////////////////////////////////

/// base context for pk data
struct context;

/// ASN.1 key formats supported by this class to import(initialize) and export from.
/// @warning with pem keys:
///  - parse_xxx() / load_xxx(): the pem data must include a null ('\0') terminating byte.
///  - export_xxx(): returns the pem data as a null terminating buffer_t.
enum key_format {
    pem_format,     ///< plain text
    der_format,     ///< binary data
};

/// the capability of a pk key based on algorithms and key validity
struct action_flags {
    bool encrypt = false;   ///< can do the encryption?
    bool decrypt = false;   ///< can do the decryption?
    bool sign    = false;   ///< can do the signing?
    bool verify  = false;   ///< can do the verification?

    explicit action_flags(bool e, bool d, bool s, bool v)
        : encrypt(e), decrypt(d), sign(s), verify(v) {}

    bool operator==(const action_flags& o)const {
        return encrypt == o.encrypt && decrypt == o.decrypt
            && sign == o.sign && verify == o.verify;
    }
}; // struct capability_flags

///////////////////////////////////////////////////////////////////////////////
/// checks if a public-private pair of keys matches.
bool check_pair(const context& pub, const context& pri);

/// (re)initializes by private key data.
void import_key(context&,
        const buffer_t& private_key_data,
        const buffer_t& password = buffer_t{});

/// (re)initializes by public key data.
void import_public_key(context&,
        const buffer_t& public_key_data);

/// loads the private key from a file.
void load_key(context&,
        const char* file_path,
        const buffer_t& password = buffer_t{});

/// loads public key from a file.
void load_public_key(context&, const char* file_path);

/// exports private key
/// @warning requires the activation of BUILD_PK_EXPORT option
///  (see cmake file)
auto export_key(context&, pk::key_format) -> buffer_t;
/// exports public key
/// @warning requires the activation of BUILD_PK_EXPORT option
///  (see cmake file)
auto export_public_key(context&, pk::key_format) -> buffer_t;

/// returns true only by enabled BUILD_PK_EXPORT builds.
/// @sa pki::export_public_key() and pki::export_key()
bool supports_key_export();

/// returns true only by enabled BUILD_RSA_KEYGEN builds.
/// @sa pki::rsa_generate_key()
bool supports_rsa_keygen();

/// returns true only by enabled BUILD_EC builds.
/// @sa pki::ec_generate_key();
bool supports_ec_keygen();

///////////////////////////////////////////////////////////////////////////////
} // namespace pk
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // __PK_HPP__
