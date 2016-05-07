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

/// resets and clean up the memory
void reset(context&) noexcept;

/// resets and initalize as the new type
void reset_as(context&, pk_t ptype);

/// returns the type of a pk context
pk_t type_of(const context&);

/// returns the name of current algorithm
auto name_of(const context&) noexcept -> const char*;

/// size of underlying key in bits, ex 2048 or ... or 0 if uninitialized
size_t key_bitlen(const context&) noexcept;

/// size of underlying key or 0 if uninitialized
size_t key_length(const context&) noexcept;

/** maximum size of data (in bytes) for a pk context to sign or verify.
 * @warning RSA is only able to encrypt data to a maximum amount of your
 *  key size (2048 bits = 256 bytes) minus padding / header data
 *  (11 bytes for PKCS#1 v1.5 padding)
 */
size_t max_crypt_size(const context&);

/// returns true if the key is a valid private key
bool has_private_key(const context&) noexcept;

/// returns true if the current context can do specific operation
bool can_do(const context&, pk_t other_type);

/// returns the capability of this context based on algorithms, and/or pub/priv key
auto what_can_do(const context&) -> action_flags;

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
buffer_t export_key(context&, pk::key_format);

/** exports public key if BUILD_PK_EXPORT has been set.
 * @sa supports_pk_export()
 */
buffer_t export_public_key(context&, pk::key_format);

/// returns true only by enabled BUILD_PK_EXPORT builds
bool supports_key_export() noexcept;

/// returns true only by enabled BUILD_RSA_KEYGEN builds
bool supports_rsa_keygen() noexcept;

/// returns true only by enabled BUILD_EC builds
bool supports_ec_keygen() noexcept;

/** generates an RSA (private) key.
 * @sa supports_rsa_keygen()
 * exponent rsa public exponent. only change the default exponent value if you
 *  know exactly what you're doing.
 * @warning requires the BUILD_RSA_KEYGEN option (see cmake file)
 */
void generate_rsa_key(context&, size_t key_bitlen, size_t exponent = 65537);

/** generates an EC (private) key.
 * @sa supports_ec_keygen()
 * @warning requires the BUILD_EC option (see cmake file)
 */
void generate_ec_key(context&, curve_t);

/** signs a hash value (or a plain message) by the rsa private key.
 * hash_or_message could be a hash value or message.
 *  if message size is larger than max_crypt_size(), it will be hashed
 *  by hash_algo first, so hash_algo is only needed for plain long messages.
 *  if you have a short or already made the message digest, simply pass
 *  hash_t::none.
 * @note for RSA keys, the signature is padded by PKCS#1 v1.5
 * @sa what_can_do()
 */
buffer_t sign(context&,
        const buffer_t& hash_or_message,
        hash_t hash_algo = hash_t::none);

/** verifies an rsa signature and its padding, @sa sign()
 * @sa what_can_do()
 */
bool verify(context&,
        const buffer_t& signature,
        const buffer_t& hash_or_message,
        hash_t hash_type = hash_t::none);

/** encrypts a hash value (or a plain message) by the rsa public key.
 * @sa sign()
 * @sa what_can_do()
 */
buffer_t encrypt(context&,
        const buffer_t& hash_or_message,
        hash_t hash_algo = hash_t::none);

/** decrypts an encrypted buffer by rsa public key.
 * @sa max_crypt_size()
 * @sa what_can_do()
 */
buffer_t decrypt(context&,
        const buffer_t& encrypted_value);

///////////////////////////////////////////////////////////////////////////////
struct pk_base {
    virtual ~pk_base() = default;
    virtual pk::context& context() = 0;
    virtual const pk::context& context() const = 0;

    void reset_as(pk_t ptype) {
        pk::reset_as(context(), ptype);
    }

    auto type()const {
        return pk::type_of(context());
    }

    auto name()const {
        return pk::name_of(context());
    }

    auto key_bitlen()const {
        return pk::key_bitlen(context());
    }

    auto key_length()const {
        return pk::key_length(context());
    }

    bool has_private_key()const {
        return pk::has_private_key(context());
    }

    bool can_do(pk_t ptype) const {
        return pk::can_do(context(), ptype);
    }

    auto what_can_do() const {
        return pk::what_can_do(context());
    }

public: // key i/o
    void import_key(const buffer_t& pri_data,
            const buffer_t& password = buffer_t{}) {
        pk::import_key(context(), pri_data, password);
    }

    void import_public_key(const buffer_t& pub_data) {
        pk::import_public_key(context(), pub_data);
    }

    void load_key(const char* file_path,
            const buffer_t& password = buffer_t{}) {
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

///////////////////////////////////////////////////////////////////////////////
} // namespace pk
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // __PK_HPP__
