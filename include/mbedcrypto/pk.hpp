/** @file pk.hpp
 * pk (public-key) is basic infrastructure for RSA/EC asymmetric algorithms.
 *
 * @copyright (C) 2019
 * @date 2019.11.12
 * @author amir zamani <azadkuh@live.com>
 *
 * related cmake build options:
 * - MBEDCRYPTO_PK_EXPORT
 * - MBEDCRYPTO_RSA_KEYGEN
 * - MBEDCRYPTO_EC
 *
 */

#ifndef MBEDCRYPTO_PK_HPP
#define MBEDCRYPTO_PK_HPP

#include "mbedcrypto/binutils.hpp"
#include "mbedcrypto/errors.hpp"
#include "mbedcrypto/types.hpp"

//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace pk {
//-----------------------------------------------------------------------------

/// generic context of rsa/ec algorithms
struct context;

/** supported ASN.1 key formats to import(initialize) and export from.
 * @warning with pem keys:
 * - import_xxx() / open_xxx(): the pem data must include a null ('\0')
 *   aka terminating byte.
 * - export_xxx(): returns the pem data with a null terminating byte.
 */
enum class key_io_t {
    pem, ///< plain text format
    der, ///< binary data format
};

/// the capability of a pk key based on algorithms and key validity
struct capability {
    bool encrypt = false; ///< can do the encryption?
    bool decrypt = false; ///< can do the decryption?
    bool sign    = false; ///< can do the signing?
    bool verify  = false; ///< can do the verification?
};

//-----------------------------------------------------------------------------

constexpr inline bool
operator==(const capability& a, const capability& b) {
    return a.encrypt == b.encrypt
        && a.decrypt == b.decrypt
        && a.sign == b.sign
        && a.verify == b.verify;
}

/// returns true only by enabled MBEDCRYPTO_PK_EXPORT builds
bool supports_key_export() noexcept;

/// returns true only by enabled MBEDCRYPTO_RSA_KEYGEN builds
bool supports_rsa_keygen() noexcept;

/// returns true only by enabled MBEDCRYPTO_EC builds
bool supports_ec_keygen() noexcept;

/// resets and clean up the memory
void reset(context&) noexcept;

/// resets and initialize to the new type if it is compatible.
std::error_code reset_as(context&, pk_t new_type) noexcept;

/// returns the type of a pk context
pk_t type_of(const context&) noexcept;

/// returns the name of current algorithm
const char* name_of(const context&) noexcept;

/// size of underlying key in bits, ex 2048 or ... or 0 if uninitialized
size_t key_bitlen(const context&) noexcept;

/// size of underlying key or 0 if uninitialized
size_t key_size(const context&) noexcept;

/** maximum size of data (in bytes) for a pk context to sign or verify.
 * returns zero as error.
 * @warning RSA is only able to encrypt data to a maximum amount of your
 *  key size (2048 bits = 256 bytes) minus padding / header data
 *  (11 bytes for PKCS#1 v1.5 padding)
 */
size_t max_crypt_size(const context&) noexcept;

/// returns true if the key is a valid private key
bool has_private_key(const context&) noexcept;

/// returns true if the current context can do specific operation
bool can_do(const context&, pk_t other_type) noexcept;

/// returns capability based on algorithms, and/or pub/priv key.
capability what_can_do(const context&) noexcept;

/// checks if a public-private pair of keys matches.
bool check_pair(const context& pub, const context& pri) noexcept;

//-----------------------------------------------------------------------------
// key i/o

/// (re)initializes the context by private key data.
std::error_code import_pri_key(
    context&,
    bin_view_t private_key_data,
    bin_view_t password = bin_view_t{}) noexcept;

/// (re)initializes the context by public key data.
std::error_code import_pub_key(context&, bin_view_t public_key_data) noexcept;

/** (re)initializes the context by loading the private key from a file.
 * password is a nullptr or a classic null terminated c string
 */
std::error_code
open_pri_key(context&, const char* file_path, const char* password = nullptr) noexcept;

/// (re)initializes the context by loading the public key from a file.
std::error_code open_pub_key(context&, const char* file_path) noexcept;

/** exports private key if MBEDCRYPTO_PK_EXPORT has been set.
 * @sa supports_pk_export()
 */
std::error_code
export_pri_key(bin_edit_t& out, context&, key_io_t) noexcept;

/// overload with container adapter.
std::error_code export_pri_key(obuffer_t&& out, context&, key_io_t);

/** exports public key if MBEDCRYPTO_PK_EXPORT has been set.
 * @sa supports_pk_export()
 */
std::error_code
export_pub_key(bin_edit_t& out, context&, key_io_t) noexcept;

/// overload with container adapter.
std::error_code export_pub_key(obuffer_t&& out, context&, key_io_t);

//-----------------------------------------------------------------------------
} // namespace pk
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_PK_HPP
