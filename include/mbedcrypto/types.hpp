/** @file types.hpp
 * the availability of the following types depends on configuration and build
 * options.
 * types can be added or removed from compilation to optimize final binary size.
 * for each type there is a utility function to check the availability at
 * runtime.  @sa supports()
 *
 * @copyright (C) 2016
 * @date 2016.03.03
 * @author amir zamani <azadkuh@live.com>
 */

#ifndef MBEDCRYPTO_TYPES_HPP
#define MBEDCRYPTO_TYPES_HPP

#include <vector>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

/** all possible supported hash (message-digest) types in mbedcrypto.
 * hints:
 * - @warning md2 is insecure and deprecated, md4 is no much better.
 * - @warning using md5 and sha1 are insecure for password hashing,
 * and more susceptible to hardware-accelerated attacks.
 */
enum class hash_t {
    md2,       ///< insecure and unacceptable
    md4,       ///< not recommended
    md5,       ///<
    sha1,      ///<
    sha224,    ///<
    sha256,    ///<
    sha384,    ///<
    sha512,    ///<
    ripemd160, ///< no publicly known attack, but old and outdated bitsize
    unknown,   ///< invalid or unknown
};

/// all possible paddings, pkcs7 is included in default build.
enum class padding_t {
    none,          ///< never pad (full blocks only)
    pkcs7,         ///< PKCS7 padding (default)
    one_and_zeros, ///< ISO/IEC 7816-4 padding
    zeros_and_len, ///< ANSI X.923 padding
    zeros,         ///< zero padding (not reversible!)
    unknown,       ///< invalid or unknown
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
    ecb,        ///< electronic codebook, input size = N * block_size
    cbc,        ///< cipher block chaining, custom input size
    cfb,        ///< cipher feedback, custom input size
    ofb,        ///< output feedback, custom input size
    ctr,        ///< counter, custom input size
    gcm,        ///< Galois/counter mode
    ccm,        ///< counter with cbc-mac
    xts,        ///< cipher text stealing of aes-xts
    stream,     ///< as in arc4_128 or null ciphers (insecure)
    chachapoly, ///< only is used in chaha-poly ciphers
    unknown,    ///< none or unknown
};

/** all possible supported cipher types in mbedcrypto.
 * hints:
 * - @warning blowfish is known to be susceptible to attacks when using weak
 * keys, you'd be better to use aes or twofish instead.
 * - @warning arc4 is a stream cipher with serious weaknesses in its initial
 * stream output, Its use is strongly discouraged. arc4 does not use mode
 * constructions.
 * naming: chipher id + key bit len + possible blocking mode
 */
enum class cipher_t {
    null, ///< identity cipher (no-op cipher)
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
    aria_128_ecb,
    aria_192_ecb,
    aria_256_ecb,
    aria_128_cbc,
    aria_192_cbc,
    aria_256_cbc,
    aria_128_cfb128,
    aria_192_cfb128,
    aria_256_cfb128,
    aria_128_ctr,
    aria_192_ctr,
    aria_256_ctr,
    aria_128_gcm,
    aria_192_gcm,
    aria_256_gcm,
    aria_128_ccm,
    aria_192_ccm,
    aria_256_ccm,
    aes_128_ofb,
    aes_192_ofb,
    aes_256_ofb,
    aes_128_xts,
    aes_256_xts,
    chacha20,
    chacha20_poly1305,
    unknown, ///< invalid or unknown
};

/// all possible public key algorithms (PKI types), RSA is included in default
/// build.
enum class pk_t {
    rsa,        ///< RSA (default)
    eckey,      ///< elliptic curve key
    eckey_dh,   ///< elliptic curve key for Diffie–Hellman key exchange
    ecdsa,      ///< elliptic curve key for digital signature algorithm
    rsa_alt,    ///<
    rsassa_pss, ///< RSA standard signature algorithm, probabilistic signature scheme
    unknown,    ///< unknown or invalid
};

/** all supported EC curves.
 * Only curves over prime fields are supported.
 *
 * @warning This library does not support validation of arbitrary domain
 *  parameters. Therefore, only well-known domain parameters from trusted
 *  sources should be used.
 */
enum class curve_t {
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
    unknown,    ///< unknown or invalid
};

/** additional features which the mbedcrypto provieds.
 * availability of these features depend on build options
 *  defined by cmake.
 * @sa supports()
 */
enum class features {
    aes_ni,     ///< hardware accelerated AES. @sa cipher::supports_aes_ni()
    aead,       ///< authenticated encryption by additional data. @sa cipher::supports_aead()
    pk_export,  ///< pem/der export of pri/pub keys. @sa pk::supports_key_export()
    rsa_keygen, ///< RSA key generator. @sa pk::supports_rsa_keygen()
    ec_keygen,  ///< EC key generator. @sa pk::supports_ec_keygen()
};

//-----------------------------------------------------------------------------
// clang-format off

const char* to_string(hash_t) noexcept;
const char* to_string(padding_t) noexcept;
const char* to_string(cipher_bm) noexcept;
const char* to_string(cipher_t) noexcept;
const char* to_string(pk_t) noexcept;
const char* to_string(curve_t) noexcept;

// these funcs support both lower and upper case names.
void from_string(const char*, hash_t&) noexcept;
void from_string(const char*, padding_t&) noexcept;
void from_string(const char*, cipher_bm&) noexcept;
void from_string(const char*, cipher_t&) noexcept;
void from_string(const char*, pk_t&) noexcept;
void from_string(const char*, curve_t&) noexcept;

template<typename Enum>
inline Enum from_string(const char* name) noexcept {
    auto e = Enum::unknown;
    from_string(name, e);
    return e;
}

//-----------------------------------------------------------------------------

// return true if an algorithm or a type is present in this configuration (build).
bool supports(hash_t) noexcept;
bool supports(padding_t) noexcept;
bool supports(cipher_bm) noexcept;
bool supports(cipher_t) noexcept;
bool supports(pk_t) noexcept;
bool supports(curve_t) noexcept;
bool supports(features) noexcept;

// overloads: check by name
inline bool supports_hash(const char* name) noexcept {
    return supports(from_string<hash_t>(name));
}

inline bool supports_padding(const char* name) noexcept {
    return supports(from_string<padding_t>(name));
}

inline bool supports_block_mode(const char* name) noexcept{
    return supports(from_string<cipher_bm>(name));
}

inline bool supports_cipher(const char* name) noexcept{
    return supports(from_string<cipher_t>(name));
}

inline bool supports_pk(const char* name) noexcept{
    return supports(from_string<pk_t>(name));
}

inline bool supports_curve(const char* name) noexcept{
    return supports(from_string<curve_t>(name));
}


/// list all algorithms (regardless of build options)
std::vector<hash_t>    all_hashes();
std::vector<padding_t> all_paddings();
std::vector<cipher_bm> all_block_modes();
std::vector<cipher_t>  all_ciphers();
std::vector<pk_t>      all_pks();
std::vector<curve_t>   all_curves();

/// list all supported algorithms (enabled by build options)
std::vector<hash_t>    supported_hashes();
std::vector<padding_t> supported_paddings();
std::vector<cipher_bm> supported_block_modes();
std::vector<cipher_t>  supported_ciphers();
std::vector<pk_t>      supported_pks();
std::vector<curve_t>   supported_curves();

// clang-format on
//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_TYPES_HPP
