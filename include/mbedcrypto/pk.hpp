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

/** base context for pk data.
 *
 * related cmake build options:
 *   BUILD_PK_EXPORT
 *   BUILD_RSA_KEYGEN
 *   BUILD_EC
 *   BUILD_ECDSA
 *
 */
struct context;

/** supproted ASN.1 key formats to import(initialize) and export from.
 * @warning with pem keys:
 * - import_xxx() / load_xxx(): the pem data must include a null ('\0')
 *   aka terminating byte.
 * - export_xxx(): returns the pem data with a null terminating byte.
 */
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

/// returns the type of a pk context
pk_t type_of(const context&);

/// size of underlying key in bits, ex 2048 or ... or 0 if uninitialized
size_t key_bitlen(const context&) noexcept;

/// size of underlying key or 0 if uninitialized
size_t key_length(const context&) noexcept;

/// returns true if the current key can do specific operation
bool can_do(const context&, pk_t other_type);

/// checks if a public-private pair of keys matches.
bool check_pair(const context& pub, const context& pri);

/// (re)initializes the context by private key data.
void import_key(context&,
        const buffer_t& private_key_data,
        const buffer_t& password = buffer_t{});

/// (re)initializes the context by public key data.
void import_public_key(context&,
        const buffer_t& public_key_data);

/// (re)initializes the context by loading the private key from a file.
void load_key(context&,
        const char* file_path,
        const buffer_t& password = buffer_t{});

/// (re)initializes the context by loading the public key from a file.
void load_public_key(context&, const char* file_path);

/** exports private key if BUILD_PK_EXPORT has been set.
 * @sa supports_pk_export()
 */
auto export_key(context&, pk::key_format) -> buffer_t;

/** exports public key if BUILD_PK_EXPORT has been set.
 * @sa supports_pk_export()
 */
auto export_public_key(context&, pk::key_format) -> buffer_t;

/// returns true only by enabled BUILD_PK_EXPORT builds
bool supports_key_export() noexcept;

/// returns true only by enabled BUILD_RSA_KEYGEN builds
bool supports_rsa_keygen() noexcept;

/// returns true only by enabled BUILD_EC builds
bool supports_ec_keygen() noexcept;

///////////////////////////////////////////////////////////////////////////////
} // namespace pk
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // __PK_HPP__
