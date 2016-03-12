/** @file types.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.03
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_TYPES_HPP
#define MBEDCRYPTO_TYPES_HPP

#include "exception.hpp"
#include <vector>
///////////////////////////////////////////////////////////////////////////////
/** the availability of the following types depends on configuraion and build options.
 * types can be added or removed from compilation to optimize final binary size.
 * for each type there is a utility function to check the availability at runtime.
 * @sa supports()
 */
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/// all possible supported hash (message-digest) types in mbedtls.
enum class hash_t {
    none,        ///< invalid or unknown
    md2,
    md4,
    md5,
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
    ripemd160,
};

/// all possible supported cipher types in mbedtls.
enum class cipher_t {
    none,             ///< invalid or unknown
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

/// all possible paddings, pkcs7 is included in default build.
enum class padding_t {
    none,             ///< never pad (full blocks only)
    pkcs7,            ///< PKCS7 padding (default)
    one_and_zeros,    ///< ISO/IEC 7816-4 padding
    zeros_and_len,    ///< ANSI X.923 padding
    zeros,            ///< zero padding (not reversible!)
};

/// all possible public key algorithms (PKI types), RSA is included in default build.
enum class pk_t {
    none,           ///< unknwon or invalid
    rsa,
    eckey,
    eckey_dh,
    ecdsa,
    rsa_alt,
    rsassa_pss,
};

///////////////////////////////////////////////////////////////////////////////

// returns true if an algorithm or a type is present at runtime.
bool supports(hash_t);
bool supports(cipher_t);
bool supports(padding_t);
bool supports(pk_t);

// list all installed algorithms, built into library
auto installed_hashes()   -> std::vector<hash_t>;
auto installed_ciphers()  -> std::vector<cipher_t>;
auto installed_paddings() -> std::vector<padding_t>;


// returns true if an algorithm or a type is present at runtime (by name string).
// both lower or upper case names are supported.

bool supports_hash(const char*);
bool supports_cipher(const char*);

auto to_string(hash_t)    -> const char*;
auto to_string(cipher_t)  -> const char*;
auto to_string(padding_t) -> const char*;

auto hash_from_string(const char*)    -> hash_t;
auto cipher_from_string(const char*)  -> cipher_t;
auto padding_from_string(const char*) -> padding_t;

template<typename T>
T from_string(const char* name, T* = nullptr);

template<> inline
auto from_string(const char* name, hash_t*) -> hash_t {
    return hash_from_string(name);
}

template<> inline
auto from_string(const char* name, cipher_t*) -> cipher_t {
    return cipher_from_string(name);
}

template<> inline
auto from_string(const char* name, padding_t*) -> padding_t {
    return padding_from_string(name);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_TYPES_HPP
