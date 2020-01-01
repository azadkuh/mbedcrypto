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

/// curve data (only short-Weierstrass curves are supported)
struct curve_info_t {
    uint16_t tls_id = 0;
    size_t   bitlen = 0;
};

//-----------------------------------------------------------------------------

constexpr inline bool
operator==(const capability& a, const capability& b) {
    return a.encrypt == b.encrypt
        && a.decrypt == b.decrypt
        && a.sign    == b.sign
        && a.verify  == b.verify;
}

constexpr inline bool
is_valid(const curve_info_t ci) noexcept {
    return ci.tls_id > 0 && ci.bitlen > 0;
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

/// returns invalid (empty) info if curve is not supported (Montgomery curves)
curve_info_t curve_info(curve_t) noexcept;

//-----------------------------------------------------------------------------
// public-key api

/// generic context for rsa/ec algorithms
struct context;

using unique_context = std::unique_ptr<context, void(*)(context*)>;

/// makes an empty PK context and manages its life time.
unique_context make_context();

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

inline bool is_rsa(const context& d) noexcept { return is_rsa(type_of(d)); }
inline bool is_ec(const context& d)  noexcept { return is_ec(type_of(d));  }

//-----------------------------------------------------------------------------
// cryptographic facilities

/** signs a hashed message by private key of context.
 * @warning: the size of hashed_msg must be equal to the hash_t size.
 *
 * - supports both pk_t::rsa and pk_t::ec/ecdsa.
 * - out should be large enough to hold the signature:
 *   * rsa:   16 + max_crypt_size()
 *   * ecdsa:  9 + (key_size() * 2)
 * - the final size of the out depends on algorithms, key size or padding
 *   (PKCS#1 v1.5 for rsa keys).
 * - if the hash_t size is larger than the key size (ecdsa), then the trimmed
 *   hash value will be used as standard.
 */
std::error_code
sign(bin_edit_t& out, context&, bin_view_t hashed_msg, hash_t) noexcept;

/// overload
std::error_code
sign(auto_size_t&& out, context&, bin_view_t hashed_msg, hash_t);

/// verifies a signature and a hashed-message by public key of context.
/// returns error if the signature fails
/// supports both pk_t::rsa and pk_t::ec/ecdsa
std::error_code
verify(context&, bin_view_t hashed_msg, hash_t, bin_view_t signature) noexcept;

/// encrypts input by public rsa key (adds padding if relevant).
/// the output may be padded (PKCS#1 v1.5).
/// @warning: input.size < max_crypt_size() or reports an error.
/// @warning: only supports pk_t::rsa
std::error_code encrypt(bin_edit_t& out, context&, bin_view_t input) noexcept;

/// overload
std::error_code encrypt(auto_size_t&& out, context&, bin_view_t input);

/// encrypts input by private rsa key (adds padding if relevant).
/// @sa encrypt()
/// @warning: only supports pk_t::rsa
std::error_code decrypt(bin_edit_t& out, context&, bin_view_t input) noexcept;

/// overload
std::error_code decrypt(auto_size_t&& out, context&, bin_view_t input);

//-----------------------------------------------------------------------------
// key tools

/** creates an RSA (private) key.
 * change the default exponent value if you know exactly what you're doing.
 * @sa supports_rsa_keygen()
 */
std::error_code
make_rsa_key(context&, size_t key_bitlen, size_t exponent = 65537) noexcept;

/** creates an EC (private) key by an EC algorithm.
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
// @warning: ecdh (ephemeral) keys are not supported by these i/o functions.

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
std::error_code export_pri_key(auto_size_t&& out, context&, key_io_t);

/// exports public key
std::error_code
export_pub_key(bin_edit_t& out, context&, key_io_t) noexcept;

/// overload with container adapter.
std::error_code export_pub_key(auto_size_t&& out, context&, key_io_t);

//-----------------------------------------------------------------------------
// ecdh and secure key exchange
//
// usage #1: by using the same curve & point format on both client/server sides:
//                                        curve_t    curve = ...;
//                                        ec_point_t fmt{};
// # server side #                                  |  # client side #
// auto srv = make_context();                       |  auto cli = make_context();
// auto ec = make_ec_key(*srv, pk_t::ecdh, curve);  |  auto ec = make_ec_key(*cli, pk_t::ecdh, curve);
// std::vector<uint8_t> srv_pub, key;               |  std::vector<uint8_t> cli_pub, key;
// ec = export_pub_key(                             |  ec = export_pub_key(
//      auto_size_t{srv_pub}, *srv, fmt);           |       auto_size_t{cli_pub}, *cli, fmt);
// # send srv_pub to client                 ---> #  |  # <--- send cli_pub to server #
// # receive cli_pub from client                    |  # receive srv_pub from server
// ec = make_shared_secret(                         |  ec = make_shared_secret(
//      auto_size_t{key}, *srv, cli_pub, fmt);      |       auto_size_t{key}, *cli, srv_pub, fmt);
// # now both the client and the server have the same key.

/// elliptic curve point format
struct ec_point_t {
    enum pack_t {
        tls,    ///< rfc-4492: ECC Cipher Suites for TLS
        binary, ///< compatible with mbedcrypto::mpi funcs
    };
    pack_t pack       = pack_t::tls;
    bool   compressed = false; ///< deprecated by rfc-8422 and newer
};

/// exports the public key as an EC point
std::error_code
export_pub_key(bin_edit_t& out, context&, ec_point_t) noexcept;

/// overload with container adapter.
std::error_code
export_pub_key(auto_size_t&& out, context&, ec_point_t);

/** calculates the shared secret by the peer's public key.
 * the shared secret is actually a big integer (@sa mbedcrypto::mpi)
 * @warning: the peer_pub should be in non-compressed format as it is
 * deprecated by newer TLS.
 */
std::error_code
make_shared_secret(
    bin_edit_t& out, context&, bin_view_t peer_pub, ec_point_t) noexcept;

/// overload with container adapter.
std::error_code
make_shared_secret(auto_size_t&& out, context&, bin_view_t peer_pub, ec_point_t);

//-----------------------------------------------------------------------------
//
// usage #2: by using TLS ServerKeyExchange & ClientKeyExchange format.
// in this scenario only server decides the curve type.
//
// # server side #                       |  # client side #
// auto srv = make_context();            |  auto cli = make_context();
// std::vector<uint8_t> skex, key;       |  std::vector<uint8_t> ckex, key;
// curve_t curve = ...;                  |
// ec = make_tls_server_kex(             |
//      auto_size_t{skex}, *srv, curve); |
// #          send skex to client --> #  |
//                                       |  # receive skex from server
//                                       |  ec = make_tls_client_kex(
//                                       |       auto_size_t{ckex}, auto_size_t{key}, *cli, skex);
//                                       |  # <-- send ckex to server
// # receive ckex from client #          |
// ec = make_tls_server_secret(          |
//      auto_size_t{key}, *srv, ckex);   |
// # now both the client and the server have the same key.

/** checks if curve is supported by TLS ServerKeyExchange.
 * only a limited number of curves are supported by TLS (depend on TLS
 * versions), @sa rfc-4492, rfc-8422, rfc-8446
 */
bool support_tls_kex(curve_t) noexcept;

/** makes server's context by curve and exports the TLS ServerKeyExchange.
 * the skex (ServerKeyExchange) contains the curve-id and the server's public
 * key in TLS format.
 * @sa support_tls_kex()
 */
std::error_code
make_tls_server_kex(bin_edit_t& skex, context&, curve_t curve) noexcept;

/// overload with container adapter.
std::error_code
make_tls_server_kex(auto_size_t&& skex, context&, curve_t curve);

/** makes client's context by curve-id of skex, then exports the client's
 * public key as ckex (ClientKeyExchange) and finally calculates the shared
 * secret by skex's public key.
 */
std::error_code
make_tls_client_kex(
    bin_edit_t& ckex, bin_edit_t& secret, context&, bin_view_t skex) noexcept;

/// overload with container adapter.
std::error_code
make_tls_client_kex(
    auto_size_t&& ckex, auto_size_t&& secret, context&, bin_view_t skex);

/// calculates the shared secret by client's public key (ckex)
inline std::error_code
make_tls_server_secret(
    bin_edit_t& secret, context& d, bin_view_t ckex) noexcept {
    return make_shared_secret(secret, d, ckex, {ec_point_t::tls, false});
}

/// overload with container adapter.
inline std::error_code
make_tls_server_secret(auto_size_t&& secret, context& d, bin_view_t ckex) {
    return make_shared_secret(
        std::forward<auto_size_t>(secret), d, ckex, {ec_point_t::tls, false});
}

//-----------------------------------------------------------------------------
} // namespace pk
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_PK_HPP
