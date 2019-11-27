/** @file pk.hpp
 * pk (public-key) is basic infrastructure for RSA/EC asymmetric algorithms.
 *
 * @copyright (C) 2019
 * @date 2019.11.12
 * @author amir zamani <azadkuh@live.com>
 *
 * related cmake build options:
 * - MBEDCRYPTO_PK_KEYGEN
 * - MBEDCRYPTO_PK_EC
 *
 * please note that RSA is always enabled in mbedcrypto.
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

/// ASN.1 format to import/export public or private keys.
/// @sa import_xxx_key() / export_xxx_key()
enum class key_io_t {
    pem, ///< plain text format, must include a null terminator ('\0')
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
        && a.sign    == b.sign
        && a.verify  == b.verify;
}

/// @sa MBEDCRYPTO_PK_KEYGEN
inline bool
supports_rsa_keygen() noexcept {
    return supports(features::pk_keygen);
}

/// @sa MBEDCRYPTO_PK_KEYGEN and MBEDCRYPTO_PK_EC
inline bool
supports_ec_keygen() noexcept {
    return supports(features::pk_keygen) && supports(features::pk_ec);
}

inline bool
is_rsa(pk_t t) noexcept {
    switch (t) {
    case pk_t::rsa:
    case pk_t::rsa_alt:
    case pk_t::rsassa_pss:
        return true;
    default:
        return false;
    }
}

inline bool
is_ec(pk_t t) noexcept {
    switch (t) {
    case pk_t::ec:
    case pk_t::ecdh:
    case pk_t::ecdsa:
        return true;
    default:
        return false;
    }
}

//-----------------------------------------------------------------------------
// public-key api

/// generic context for rsa/ec algorithms
struct context;

using unique_ptr = std::unique_ptr<context, void(*)(context*)>;

/// makes an empty PK context and manages its life time.
pk::unique_ptr make_context();

/// resets and initializes to the new compatible type.
/// you rarely need to call this function directly.
std::error_code setup(context&, pk_t new_type) noexcept;

//-----------------------------------------------------------------------------

/** returns false if the context is uninitialized.
 * note: the context is valid even if it has not any associated key, so
 * manually setup() a context, gives a valid context without any key.
 */
bool is_valid(const context&) noexcept;

/// returns the type of a pk context
pk_t type_of(const context&) noexcept;

/// returns the name of current algorithm or unknown if it is not valid
inline auto name_of(const context& c) noexcept { return to_string(type_of(c)); }

/// size of underlying key in bits, or 0 if it has no key
size_t key_bitlen(const context&) noexcept;

/// size of underlying key or 0 if it has no key
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

//-----------------------------------------------------------------------------
// cryptographic facilities

/// signs a hashed message by private key of context.
/// the output may be padded (PKCS#1 v1.5 for rsa keys).
/// @warning: the size of hashed_msg must be equal to the hash size.
std::error_code
sign(bin_edit_t& out, context&, bin_view_t hashed_msg, hash_t) noexcept;

/// overload
std::error_code
sign(obuffer_t&& out, context&, bin_view_t hashed_msg, hash_t);

/// verifies a signature and a hashed-message by public key of context.
/// returns error if the signature fails
std::error_code
verify(context&, bin_view_t hashed_msg, hash_t, bin_view_t signature) noexcept;

/// encrypts input by public key (adds padding if relevant).
/// the output may be padded (PKCS#1 v1.5 for rsa keys).
/// @warning: input.size < max_crypt_size() or reports an error.
std::error_code encrypt(bin_edit_t& out, context&, bin_view_t input) noexcept;

/// overload
std::error_code encrypt(obuffer_t&& out, context&, bin_view_t input);

/// encrypts input by public key (adds padding if relevant).
/// @sa encrypt()
std::error_code decrypt(bin_edit_t& out, context&, bin_view_t input) noexcept;

/// overload
std::error_code decrypt(obuffer_t&& out, context&, bin_view_t input);

//-----------------------------------------------------------------------------
// key tools

/** creates an RSA (private) key.
 * change the default exponent value if you know exactly what you're doing.
 * @sa supports_rsa_keygen()
 */
std::error_code
make_rsa_key(context&, size_t key_bitlen, size_t exponent = 65537) noexcept;

/** creates an EC (private) key by an ec algorithm.
 * @sa supports_ec_keygen() and is_ec()
 */
std::error_code make_ec_key(context&, pk_t algorithm, curve_t) noexcept;

inline std::error_code
make_ec_key(context& d, curve_t c) noexcept {
    return make_ec_key(d, pk_t::ec, c);
}

/// checks if a public-private pair of keys matches.
bool is_pri_pub_pair(const context& pri, const context& pub) noexcept;

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

/// exports private key
std::error_code
export_pri_key(bin_edit_t& out, context&, key_io_t) noexcept;

/// overload with container adapter.
std::error_code export_pri_key(obuffer_t&& out, context&, key_io_t);

/// exports public key
std::error_code
export_pub_key(bin_edit_t& out, context&, key_io_t) noexcept;

/// overload with container adapter.
std::error_code export_pub_key(obuffer_t&& out, context&, key_io_t);

//-----------------------------------------------------------------------------
} // namespace pk
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_PK_HPP
