/** @file types.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.03
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_TYPES_HPP
#define MBEDCRYPTO_TYPES_HPP

#include "mbedcrypto/exception.hpp"

#include <vector>
///////////////////////////////////////////////////////////////////////////////
/** the availability of the following types depends on configuration and build
 * options.
 * types can be added or removed from compilation to optimize final binary size.
 * for each type there is a utility function to check the availability at
 * runtime.  @sa supports()
 */
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/** all possible supported hash (message-digest) types in mbedcrypto.
 * hints:
 * - @warning md2 is insecure and deprecated, md4 is no much better.
 * - @warning using md5 and sha1 are insecure for password hashing,
 * and more susceptible to hardware-accelerated attacks.
 */
enum class hash_t {
    none,      ///< invalid or unknown
    md2,       ///< insecure and unacceptable
    md4,       ///< not recommended
    md5,       ///<
    sha1,      ///<
    sha224,    ///<
    sha256,    ///<
    sha384,    ///<
    sha512,    ///<
    ripemd160, ///< no publicly known attack, but old and outdated bit size
               ///(160)
};

/// all possible paddings, pkcs7 is included in default build.
enum class padding_t {
    none,          ///< never pad (full blocks only)
    pkcs7,         ///< PKCS7 padding (default)
    one_and_zeros, ///< ISO/IEC 7816-4 padding
    zeros_and_len, ///< ANSI X.923 padding
    zeros,         ///< zero padding (not reversible!)
};

/** block mode: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation.
 * hints:
 * - ebc so fast, not cryptographically strong
 * input size must be = N * block_size, so no padding is required
 * - cbc is slow and cryptographically strong
 * needs iv and padding
 * - cfb needs iv, no padding
 * - ctr is fast and strong only with ciphers that have block_size() >= 128bits
 * needs iv, does not require padding, transforms a block to stream
 * @warning in ctr and all other counter based modes,
 * the iv should be used only once per operation to be secure
 * - gcm is fast and strong if tag size is not smaller than 96bits
 * also used in aead (authenticated encryption with additional data)
 * needs iv, does not require padding
 * - ccm is fast, strong if the iv never be used more than once for a given key
 * only used in aead (authenticated encryption with additional data)
 * needs iv, does not require padding
 */
enum class cipher_bm {
    none,   ///< none or unknown
    ecb,    ///< electronic codebook, input size = N * block_size
    cbc,    ///< cipher block chaining, custom input size
    cfb,    ///< cipher feedback, custom input size
    ctr,    ///< counter, custom input size
    gcm,    ///< Galois/counter mode
    ccm,    ///< counter with cbc-mac
    stream, ///< as in arc4_128 or null ciphers (insecure)
};

/** all possible supported cipher types in mbedcrypto.
 * hints:
 * - @warning blowfish is known to be susceptible to attacks when using weak
 * keys, you'd be better to use aes or twofish instead.
 * - @warning arc4 is a stream cipher with serious weaknesses in its initial
 * stream output, Its use is strongly discouraged. arc4 does not use mode
 * constructions.
 */
enum class cipher_t {
    none, ///< invalid or unknown
    null,
    aes_128_ecb,
    aes_192_ecb,
    aes_256_ecb,
    aes_128_cbc,
    aes_192_cbc,
    aes_256_cbc,
    aes_128_cfb128,
    aes_192_cfb128,
    aes_256_cfb128,
    aes_128_ctr,
    aes_192_ctr,
    aes_256_ctr,
    aes_128_gcm,
    aes_192_gcm,
    aes_256_gcm,
    camellia_128_ecb,
    camellia_192_ecb,
    camellia_256_ecb,
    camellia_128_cbc,
    camellia_192_cbc,
    camellia_256_cbc,
    camellia_128_cfb128,
    camellia_192_cfb128,
    camellia_256_cfb128,
    camellia_128_ctr,
    camellia_192_ctr,
    camellia_256_ctr,
    camellia_128_gcm,
    camellia_192_gcm,
    camellia_256_gcm,
    des_ecb,
    des_cbc,
    des_ede_ecb,
    des_ede_cbc,
    des_ede3_ecb,
    des_ede3_cbc,
    blowfish_ecb,
    blowfish_cbc,
    blowfish_cfb64,
    blowfish_ctr,
    arc4_128,
    aes_128_ccm,
    aes_192_ccm,
    aes_256_ccm,
    camellia_128_ccm,
    camellia_192_ccm,
    camellia_256_ccm,
};

/// all possible public key algorithms (PKI types), RSA is included in default
/// build.
enum class pk_t {
    none,       ///< unknown or invalid
    rsa,        ///< RSA (default)
    eckey,      ///< elliptic curve key
    eckey_dh,   ///< elliptic curve key for Diffie–Hellman key exchange
    ecdsa,      ///< elliptic curve key for digital signature algorithm
    rsa_alt,    ///<
    rsassa_pss, ///< RSA standard signature algorithm, probabilistic signature
                /// scheme
};

/** all supported EC curves.
 * Only curves over prime fields are supported.
 *
 * @warning This library does not support validation of arbitrary domain
 *  parameters. Therefore, only well-known domain parameters from trusted
 *  sources should be used.
 */
enum class curve_t {
    none,
    secp192r1,  ///< 192-bits NIST curve
    secp224r1,  ///< 224-bits NIST curve
    secp256r1,  ///< 256-bits NIST curve
    secp384r1,  ///< 384-bits NIST curve
    secp521r1,  ///< 521-bits NIST curve
    secp192k1,  ///< 192-bits "Koblitz" curve
    secp224k1,  ///< 224-bits "Koblitz" curve
    secp256k1,  ///< 256-bits "Koblitz" curve
    bp256r1,    ///< 256-bits Brainpool curve
    bp384r1,    ///< 384-bits Brainpool curve
    bp512r1,    ///< 512-bits Brainpool curve
    curve25519, ///< Curve25519. limited support (only for ecdh)
};

/** additional features which the mbedcrypto provieds.
 * availability of these features depend on build options
 *  defined by cmake.
 * @sa supports()
 */
enum class features {
    aes_ni,     ///< hardware accelerated AES. @sa cipher::supports_aes_ni()
    aead,       ///< authenticated encryption by additional data. @sa
                /// cipher::supports_aead()
    pk_export,  ///< pem/der export of pri/pub keys. @sa
                /// pk::supports_key_export()
    rsa_keygen, ///< RSA key generator. @sa pk::supports_rsa_keygen()
    ec_keygen,  ///< EC key generator. @sa pk::supports_ec_keygen()
};
///////////////////////////////////////////////////////////////////////////////
// clang-format off

/// returns true if an algorithm or a type is present at runtime.
bool supports(hash_t);
bool supports(padding_t);
bool supports(cipher_bm);
bool supports(cipher_t);
bool supports(pk_t);
bool supports(curve_t);
bool supports(features);

/// list all installed algorithms, built into library
auto installed_hashes()      -> std::vector<hash_t>;
auto installed_paddings()    -> std::vector<padding_t>;
auto installed_block_modes() -> std::vector<cipher_bm>;
auto installed_ciphers()     -> std::vector<cipher_t>;
auto installed_pks()         -> std::vector<pk_t>;
auto installed_curves()      -> std::vector<curve_t>;


// returns true if an algorithm or a type is present at runtime (by name
// string).
// both lower or upper case names are supported.
bool supports_hash(const char*);
bool supports_padding(const char*);
bool supports_block_mode(const char*);
bool supports_cipher(const char*);
bool supports_pk(const char*);
bool supports_curve(const char*);

auto to_string(hash_t)    -> const char*;
auto to_string(padding_t) -> const char*;
auto to_string(cipher_bm) -> const char*;
auto to_string(cipher_t)  -> const char*;
auto to_string(pk_t)      -> const char*;
auto to_string(curve_t)   -> const char*;

auto hash_from_string(const char*)       -> hash_t;
auto padding_from_string(const char*)    -> padding_t;
auto block_mode_from_string(const char*) -> cipher_bm;
auto cipher_from_string(const char*)     -> cipher_t;
auto pk_from_string(const char*)         -> pk_t;
auto curve_from_string(const char*)      -> curve_t;

template <typename T> T
from_string(const char* name, T* = nullptr);

template <> inline auto
from_string(const char* name, hash_t*) -> hash_t {
    return hash_from_string(name);
}

template <> inline auto
from_string(const char* name, padding_t*) -> padding_t {
    return padding_from_string(name);
}

template <> inline auto
from_string(const char* name, cipher_bm*) -> cipher_bm {
    return block_mode_from_string(name);
}

template <> inline auto
from_string(const char* name, cipher_t*) -> cipher_t {
    return cipher_from_string(name);
}

template <> inline auto
from_string(const char* name, pk_t*) -> pk_t {
    return pk_from_string(name);
}

template <> inline auto
from_string(const char* name, curve_t*) -> curve_t {
    return curve_from_string(name);
}

// clang-format on
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_TYPES_HPP
