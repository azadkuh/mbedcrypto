/** @file pk.hpp
 *
 * @copyright (C) 2016
 * @date 2016.05.01
 * @author amir zamani <azadkuh@live.com>
 */

#ifndef MBEDCRYPTO_PK_HPP
#define MBEDCRYPTO_PK_HPP

#include "mbedcrypto/mpi.hpp"
#include "mbedcrypto/hash.hpp"

#include <tuple>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
class rnd_generator;
//-----------------------------------------------------------------------------
namespace pk {
//-----------------------------------------------------------------------------

/** base context for pk data.
 *
 * related cmake build options:
 *   MBEDCRYPTO_PK_EXPORT
 *   MBEDCRYPTO_RSA_KEYGEN
 *   MBEDCRYPTO_EC
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
    pem_format, ///< plain text
    der_format, ///< binary data
};

/// the capability of a pk key based on algorithms and key validity
struct action_flags {
    bool encrypt = false; ///< can do the encryption?
    bool decrypt = false; ///< can do the decryption?
    bool sign    = false; ///< can do the signing?
    bool verify  = false; ///< can do the verification?

    explicit action_flags(bool e, bool d, bool s, bool v)
        : encrypt(e), decrypt(d), sign(s), verify(v) {}

    bool operator==(const action_flags& o) const {
        return std::make_tuple(encrypt, decrypt, sign, verify) ==
               std::make_tuple(o.encrypt, o.decrypt, o.sign, o.verify);
    }
}; // struct capability_flags

//-----------------------------------------------------------------------------

/// resets and clean up the memory
void
reset(context&) noexcept;

/** resets and initalize to the new type.
 * throws if ptype is not compatible with current type.
 * (ex reset an eckey_dh to rsa will throw)
 */
void
reset_as(context&, pk_t ptype);

/// returns the type of a pk context
pk_t
type_of(const context&);

/// returns the name of current algorithm
auto
name_of(const context&) noexcept -> const char*;

/// size of underlying key in bits, ex 2048 or ... or 0 if uninitialized
size_t
key_bitlen(const context&) noexcept;

/// size of underlying key or 0 if uninitialized
size_t
key_length(const context&) noexcept;

/** maximum size of data (in bytes) for a pk context to sign or verify.
 * @warning RSA is only able to encrypt data to a maximum amount of your
 *  key size (2048 bits = 256 bytes) minus padding / header data
 *  (11 bytes for PKCS#1 v1.5 padding)
 */
size_t
max_crypt_size(const context&);

/// returns true if the key is a valid private key
bool
has_private_key(const context&) noexcept;

/// returns true if the current context can do specific operation
bool
can_do(const context&, pk_t other_type);

/// returns the capability of this context based on algorithms, and/or pub/priv
/// key
auto
what_can_do(const context&) -> action_flags;

/// checks if a public-private pair of keys matches.
bool
check_pair(const context& pub, const context& pri);

/// (re)initializes the context by private key data.
void
import_key(
    context&,
    buffer_view_t private_key_data,
    buffer_view_t password = buffer_view_t{nullptr});

/// (re)initializes the context by public key data.
void
import_public_key(context&, buffer_view_t public_key_data);

/** (re)initializes the context by loading the private key from a file.
 * password is a nullptr or a classic null terminated c string */
void
load_key(context&, const char* file_path, const char* password = nullptr);

/// (re)initializes the context by loading the public key from a file.
void
load_public_key(context&, const char* file_path);

/** exports private key if MBEDCRYPTO_PK_EXPORT has been set.
 * @sa supports_pk_export()
 */
buffer_t
export_key(context&, pk::key_format);

/** exports public key if MBEDCRYPTO_PK_EXPORT has been set.
 * @sa supports_pk_export()
 */
buffer_t
export_public_key(context&, pk::key_format);

/// returns true only by enabled MBEDCRYPTO_PK_EXPORT builds
bool
supports_key_export() noexcept;

/// returns true only by enabled MBEDCRYPTO_RSA_KEYGEN builds
bool
supports_rsa_keygen() noexcept;

/// returns true only by enabled MBEDCRYPTO_EC builds
bool
supports_ec_keygen() noexcept;

/** generates an RSA (private) key.
 * @sa supports_rsa_keygen()
 * exponent rsa public exponent. only change the default exponent value if you
 *  know exactly what you're doing.
 * @warning requires the MBEDCRYPTO_RSA_KEYGEN option (see cmake file)
 */
void
generate_rsa_key(context&, size_t key_bitlen, size_t exponent = 65537);

/** generates an EC (private) key.
 * @sa supports_ec_keygen()
 * @warning requires the MBEDCRYPTO_EC option (see cmake file)
 */
void
generate_ec_key(context&, curve_t);

/** signs a hash value (of a message) by the private key.
 * @note for RSA keys, the signature is padded by PKCS#1 v1.5
 * @sa what_can_do()
 */
buffer_t
sign(context&, buffer_view_t hash_value, hash_t hash_type);

/// sing helper, message could be in any size
inline auto
sign_message(context& ctx, buffer_view_t message, hash_t hash_type) {
    return sign(ctx, hash::make(hash_type, message), hash_type);
}

/** verifies an pk signature and its padding, @sa sign()
 * @sa what_can_do()
 */
bool
verify(
    context&,
    buffer_view_t signature,
    buffer_view_t hash_value,
    hash_t        hash_type);

/// verify overload
inline bool
verify_message(
    context&      ctx,
    buffer_view_t signature,
    buffer_view_t message,
    hash_t        hash_type) {
    return verify(ctx, signature, hash::make(hash_type, message), hash_type);
}

/** encrypts source data (includes padding if relevant) by pk.
 * @warning source size must be smaller than max_crypt_size()
 * @sa sign() and what_can_do()
 */
buffer_t
encrypt(context&, buffer_view_t source);

/** decrypts an encrypted buffer by pk.
 * @sa encrypt()
 */
buffer_t
decrypt(context&, buffer_view_t encrypted_value);

//-----------------------------------------------------------------------------

/// a base class for public key implementation. @sa rsa and ecp
struct pk_base {
    virtual ~pk_base()                         = default;
    virtual pk::context&       context()       = 0;
    virtual const pk::context& context() const = 0;

    void reset_as(pk_t ptype) {
        pk::reset_as(context(), ptype);
    }

    auto type() const {
        return pk::type_of(context());
    }

    auto name() const {
        return pk::name_of(context());
    }

    auto key_bitlen() const {
        return pk::key_bitlen(context());
    }

    auto key_length() const {
        return pk::key_length(context());
    }

    bool has_private_key() const {
        return pk::has_private_key(context());
    }

    bool can_do(pk_t ptype) const {
        return pk::can_do(context(), ptype);
    }

    auto what_can_do() const {
        return pk::what_can_do(context());
    }

    auto rnd() -> rnd_generator&;

public: // key i/o
    void import_key(
        buffer_view_t pri_data, buffer_view_t password = buffer_view_t{nullptr}) {
        pk::import_key(context(), pri_data, password);
    }

    void import_public_key(buffer_view_t pub_data) {
        pk::import_public_key(context(), pub_data);
    }

    void
    load_key(const char* file_path, const char* password = nullptr) {
        pk::load_key(context(), file_path, password);
    }

    void load_public_key(const char* file_path) {
        pk::load_public_key(context(), file_path);
    }

    auto export_key(pk::key_format fmt) {
        return pk::export_key(context(), fmt);
    }

    auto export_public_key(pk::key_format fmt) {
        return pk::export_public_key(context(), fmt);
    }

}; // struct pk_base

//-----------------------------------------------------------------------------
} // namespace pk
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_PK_HPP
