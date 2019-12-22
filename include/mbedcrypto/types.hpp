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
/// helps cipher_bm::cbc to accept any input size.
enum class padding_t {
    none,          ///< never pad (full blocks only)
    pkcs7,         ///< PKCS7 padding (default)
    one_and_zeros, ///< ISO/IEC 7816-4 padding
    zeros_and_len, ///< ANSI X.923 padding
    zeros,         ///< zero padding (not reversible!)
    unknown,       ///< invalid or unknown
};

/** ciphering block mode.
 * @sa https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation.
 *
 * hits:
 * | block_mode | uses iv | aead | input size             |
 * | :---       | :---    | :--- | :---                   |
 * | ecb        |         |      | N * block_size()       |
 * | cbc        | +       |      | any size via padding_t |
 * | cfb        | +       |      | any size               |
 * | ofb        | +       |      | any size               |
 * | ctr        | +       |      | any size               |
 * | gcm        | +       | +/-  | any size               |
 * | ccm        | +       | +    | any size               |
 * | xts        | +       |      | any size               |
 * | stream     | +/-     |      | any size               |
 * | chachapoly | +       | +    | any size               |
 *
 * gcm:        usable with or without AEAD
 * ccm:        only with AEAD
 * stream:     uses iv for chacha20 algorithm but no iv for arc4
 * chachapoly: always needs additional data
 */
enum class cipher_bm {
    ecb,        ///< electronic codebook. is fast but not cryptographically strong
    cbc,        ///< cipher block chaining
    cfb,        ///< cipher feedback
    ofb,        ///< output feedback
    ctr,        ///< counter. is fast, only strong with block_size() >= 128bits
    gcm,        ///< Galois/counter mode. is fast and secure for tag.size >= 96bit
    ccm,        ///< counter with cbc-mac. is fast and strong if iv is unique for each operation.
    xts,        ///< cipher text stealing of aes-xts.
    stream,     ///< stream is fast but not secure via arc4.
    chachapoly, ///< only is used in chahapoly20 ciphers
    unknown,    ///< none or unknown
};

/** all possible supported cipher types in mbedcrypto.
 * hints:
 * - @warning blowfish is known to be susceptible to attacks when using weak
 *   keys, you'd be better to use aes or twofish instead.
 * - @warning arc4 is a stream cipher with serious weaknesses in its initial
 *   stream output, Its use is strongly discouraged. arc4 does not use mode
 *   constructions.
 * - @warning xts requires two independent AES keys, one for the data and one
 *   for hte tweak sector number, so the key size of aes_128_xts is 265bit and
 *   for aes_256_xts is 512bit.
 *
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
    rsa_alt,    ///< RSA alternative
    rsassa_pss, ///< RSA standard signature algorithm, probabilistic signature scheme
    ec,         ///< elliptic curve
    ecdh,       ///< elliptic curve for Diffie–Hellman key exchange
    ecdsa,      ///< elliptic curve for digital signature algorithm
    unknown,    ///< unknown or invalid
};

/** all supported EC curves.
 * Only curves over prime fields are supported:
 * - short Weierstrass: y^2 = x^3 + A x   + B mod P @sa rfc-4492/sec1
 * - Montgomery:        y^2 = x^3 + A x^2 + x mod P
 *
 * @warning This library does not support validation of arbitrary domain
 *  parameters. Therefore, only well-known domain parameters from trusted
 *  sources should be used.
 */
enum class curve_t {
    // short Weierstrass:
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
    // Montgomery:
    curve25519, ///< 255-bits limited support (only for ecdh)
    curve448,   ///< 448-bits limited support (only for ecdh)
    unknown,    ///< unknown or invalid
};

/** additional features which the mbedcrypto provieds.
 * availability of these features depend on build options
 *  defined by cmake.
 * @sa supports()
 */
enum class features {
    aes_ni,     ///< hardware accelerated AES. @sa supports_aes_ni()
    aead,       ///< authenticated encryption by additional data. @sa supports_aead()
    pk_keygen,  ///< public-key generator
    pk_ec,      ///< any of elliptic-curve algorithms
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

/** checks if current build and the CPU/OS supports AESNI.
 * @sa features::aes_ni
 * AESNI is an extension to the x86 instruction set architecture
 *  for microprocessors from Intel and AMD proposed by Intel in March 2008.
 *  The purpose of the instruction set is to improve the speed of
 *  applications performing encryption and decryption using AES.
 *
 * @warning mbedcrypto (mbedcrypto) automatically switches to AESNI
 *  automatically for supported systems.
 * @sa http://en.wikipedia.org/wiki/AES_instruction_set
 */
inline bool
supports_aes_ni() noexcept {
    return supports(features::aes_ni);
}

/** authenticated encryption by additional data.
 * returns true if any of MBEDCRYPTO_BM_GCM or MBEDCRYPTO_BM_CCM has been
 * activated.  @sa features::aead
 */
inline bool
supports_aead() noexcept {
    return supports(features::aead);
}

// clang-format on
//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_TYPES_HPP
