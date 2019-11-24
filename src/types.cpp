#include "mbedcrypto/types.hpp"

#include "./private/enumerator.hxx"
#include "./private/conversions.hpp"

#include <mbedtls/aesni.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
//-----------------------------------------------------------------------------

template <typename Array, typename Enum = decltype(std::declval<Array>()[0].e)>
inline auto
list_all(const Array& all) {
    std::vector<Enum> v;
    v.reserve(std::extent<Array>::value);
    for (const auto& i : all) {
        if (i.e != Enum::unknown)
            v.push_back(i.e);
    }
    return v;
}

template <typename Array, typename Enum = decltype(std::declval<Array>()[0].e)>
inline auto
list_supported(const Array& all) {
    std::vector<Enum> v;
    v.reserve(std::extent<Array>::value);
    for (const auto& i : all) {
        if (i.e != Enum::unknown && supports(i.e))
            v.push_back(i.e);
    }
    return v;
}

//-----------------------------------------------------------------------------
// clang-format off
const details::enum_name<hash_t> gHashes[] = {
    {hash_t::md2,       "md2"},
    {hash_t::md4,       "md4"},
    {hash_t::md5,       "md5"},
    {hash_t::sha1,      "sha1"},
    {hash_t::sha224,    "sha224"},
    {hash_t::sha256,    "sha256"},
    {hash_t::sha384,    "sha384"},
    {hash_t::sha512,    "sha512"},
    {hash_t::ripemd160, "ripemd160"},
    {hash_t::unknown,   "unknown"},
};

const details::enum_name<padding_t> gPaddings[] = {
    {padding_t::none,          "none"},
    {padding_t::pkcs7,         "pkcs7"},
    {padding_t::one_and_zeros, "one_and_zeros"},
    {padding_t::zeros_and_len, "zeros_and_len"},
    {padding_t::zeros,         "zeros"},
    {padding_t::unknown,       "unknown"},
};

const details::enum_name<cipher_bm> gBlockModes[] = {
    {cipher_bm::ecb,        "ecb"},
    {cipher_bm::cbc,        "cbc"},
    {cipher_bm::cfb,        "cfb"},
    {cipher_bm::ofb,        "ofb"},
    {cipher_bm::ctr,        "ctr"},
    {cipher_bm::gcm,        "gcm"},
    {cipher_bm::ccm,        "ccm"},
    {cipher_bm::xts,        "xts"},
    {cipher_bm::stream,     "stream"},
    {cipher_bm::chachapoly, "chachapoly"},
    {cipher_bm::unknown,    "unknown"},
};

const details::enum_name<cipher_t> gCiphers[] = {
    {cipher_t::null,                "null"},
    {cipher_t::aes_128_ecb,         "aes_128_ecb"},
    {cipher_t::aes_192_ecb,         "aes_192_ecb"},
    {cipher_t::aes_256_ecb,         "aes_256_ecb"},
    {cipher_t::aes_128_cbc,         "aes_128_cbc"},
    {cipher_t::aes_192_cbc,         "aes_192_cbc"},
    {cipher_t::aes_256_cbc,         "aes_256_cbc"},
    {cipher_t::aes_128_cfb128,      "aes_128_cfb128"},
    {cipher_t::aes_192_cfb128,      "aes_192_cfb128"},
    {cipher_t::aes_256_cfb128,      "aes_256_cfb128"},
    {cipher_t::aes_128_ctr,         "aes_128_ctr"},
    {cipher_t::aes_192_ctr,         "aes_192_ctr"},
    {cipher_t::aes_256_ctr,         "aes_256_ctr"},
    {cipher_t::aes_128_gcm,         "aes_128_gcm"},
    {cipher_t::aes_192_gcm,         "aes_192_gcm"},
    {cipher_t::aes_256_gcm,         "aes_256_gcm"},
    {cipher_t::camellia_128_ecb,    "camellia_128_ecb"},
    {cipher_t::camellia_192_ecb,    "camellia_192_ecb"},
    {cipher_t::camellia_256_ecb,    "camellia_256_ecb"},
    {cipher_t::camellia_128_cbc,    "camellia_128_cbc"},
    {cipher_t::camellia_192_cbc,    "camellia_192_cbc"},
    {cipher_t::camellia_256_cbc,    "camellia_256_cbc"},
    {cipher_t::camellia_128_cfb128, "camellia_128_cfb128"},
    {cipher_t::camellia_192_cfb128, "camellia_192_cfb128"},
    {cipher_t::camellia_256_cfb128, "camellia_256_cfb128"},
    {cipher_t::camellia_128_ctr,    "camellia_128_ctr"},
    {cipher_t::camellia_192_ctr,    "camellia_192_ctr"},
    {cipher_t::camellia_256_ctr,    "camellia_256_ctr"},
    {cipher_t::camellia_128_gcm,    "camellia_128_gcm"},
    {cipher_t::camellia_192_gcm,    "camellia_192_gcm"},
    {cipher_t::camellia_256_gcm,    "camellia_256_gcm"},
    {cipher_t::des_ecb,             "des_ecb"},
    {cipher_t::des_cbc,             "des_cbc"},
    {cipher_t::des_ede_ecb,         "des_ede_ecb"},
    {cipher_t::des_ede_cbc,         "des_ede_cbc"},
    {cipher_t::des_ede3_ecb,        "des_ede3_ecb"},
    {cipher_t::des_ede3_cbc,        "des_ede3_cbc"},
    {cipher_t::blowfish_ecb,        "blowfish_ecb"},
    {cipher_t::blowfish_cbc,        "blowfish_cbc"},
    {cipher_t::blowfish_cfb64,      "blowfish_cfb64"},
    {cipher_t::blowfish_ctr,        "blowfish_ctr"},
    {cipher_t::arc4_128,            "arc4_128"},
    {cipher_t::aes_128_ccm,         "aes_128_ccm"},
    {cipher_t::aes_192_ccm,         "aes_192_ccm"},
    {cipher_t::aes_256_ccm,         "aes_256_ccm"},
    {cipher_t::camellia_128_ccm,    "camellia_128_ccm"},
    {cipher_t::camellia_192_ccm,    "camellia_192_ccm"},
    {cipher_t::camellia_256_ccm,    "camellia_256_ccm"},
    {cipher_t::aria_128_ecb,        "aria_128_ecb"},
    {cipher_t::aria_192_ecb,        "aria_192_ecb"},
    {cipher_t::aria_256_ecb,        "aria_256_ecb"},
    {cipher_t::aria_128_cbc,        "aria_128_cbc"},
    {cipher_t::aria_192_cbc,        "aria_192_cbc"},
    {cipher_t::aria_256_cbc,        "aria_256_cbc"},
    {cipher_t::aria_128_cfb128,     "aria_128_cfb128"},
    {cipher_t::aria_192_cfb128,     "aria_192_cfb128"},
    {cipher_t::aria_256_cfb128,     "aria_256_cfb128"},
    {cipher_t::aria_128_ctr,        "aria_128_ctr"},
    {cipher_t::aria_192_ctr,        "aria_192_ctr"},
    {cipher_t::aria_256_ctr,        "aria_256_ctr"},
    {cipher_t::aria_128_gcm,        "aria_128_gcm"},
    {cipher_t::aria_192_gcm,        "aria_192_gcm"},
    {cipher_t::aria_256_gcm,        "aria_256_gcm"},
    {cipher_t::aria_128_ccm,        "aria_128_ccm"},
    {cipher_t::aria_192_ccm,        "aria_192_ccm"},
    {cipher_t::aria_256_ccm,        "aria_256_ccm"},
    {cipher_t::aes_128_ofb,         "aes_128_ofb"},
    {cipher_t::aes_192_ofb,         "aes_192_ofb"},
    {cipher_t::aes_256_ofb,         "aes_256_ofb"},
    {cipher_t::aes_128_xts,         "aes_128_xts"},
    {cipher_t::aes_256_xts,         "aes_256_xts"},
    {cipher_t::chacha20,            "chacha20"},
    {cipher_t::chacha20_poly1305,   "chacha20_poly1305"},
    {cipher_t::unknown,             "unknown"},
};

const details::enum_name<pk_t> gPks[] = {
    {pk_t::rsa,        "rsa"},
    {pk_t::eckey,      "ec"},
    {pk_t::eckey_dh,   "ec_dh"},
    {pk_t::ecdsa,      "ecdsa"},
    {pk_t::rsa_alt,    "rsa_alt"},
    {pk_t::rsassa_pss, "rsassa_pss"},
    {pk_t::unknown,    "unknown"},
};

const details::enum_name<curve_t> gCurves[] = {
    {curve_t::secp192r1,  "secp192r1"},
    {curve_t::secp224r1,  "secp224r1"},
    {curve_t::secp256r1,  "secp256r1"},
    {curve_t::secp384r1,  "secp384r1"},
    {curve_t::secp521r1,  "secp521r1"},
    {curve_t::secp192k1,  "secp192k1"},
    {curve_t::secp224k1,  "secp224k1"},
    {curve_t::secp256k1,  "secp256k1"},
    {curve_t::bp256r1,    "bp256r1"},
    {curve_t::bp384r1,    "bp384r1"},
    {curve_t::bp512r1,    "bp512r1"},
    {curve_t::curve25519, "curve25519"},
    {curve_t::unknown,    "unknown"},
};

//-----------------------------------------------------------------------------

const details::enum_pair<hash_t, mbedtls_md_type_t> gHashPairs[] = {
    {hash_t::md2,       MBEDTLS_MD_MD2},
    {hash_t::md4,       MBEDTLS_MD_MD4},
    {hash_t::md5,       MBEDTLS_MD_MD5},
    {hash_t::sha1,      MBEDTLS_MD_SHA1},
    {hash_t::sha224,    MBEDTLS_MD_SHA224},
    {hash_t::sha256,    MBEDTLS_MD_SHA256},
    {hash_t::sha384,    MBEDTLS_MD_SHA384},
    {hash_t::sha512,    MBEDTLS_MD_SHA512},
    {hash_t::ripemd160, MBEDTLS_MD_RIPEMD160},
    {hash_t::unknown,   MBEDTLS_MD_NONE},
};

const details::enum_pair<padding_t, mbedtls_cipher_padding_t> gPaddingPairs[] = {
    {padding_t::none,          MBEDTLS_PADDING_NONE},
    {padding_t::pkcs7,         MBEDTLS_PADDING_PKCS7},
    {padding_t::one_and_zeros, MBEDTLS_PADDING_ONE_AND_ZEROS},
    {padding_t::zeros_and_len, MBEDTLS_PADDING_ZEROS_AND_LEN},
    {padding_t::zeros,         MBEDTLS_PADDING_ZEROS},
    {padding_t::unknown,       MBEDTLS_PADDING_NONE},
};

const details::enum_pair<cipher_bm, mbedtls_cipher_mode_t> gBlockModePairs[] = {
    {cipher_bm::ecb,        MBEDTLS_MODE_ECB},
    {cipher_bm::cbc,        MBEDTLS_MODE_CBC},
    {cipher_bm::cfb,        MBEDTLS_MODE_CFB},
    {cipher_bm::ofb,        MBEDTLS_MODE_OFB},
    {cipher_bm::ctr,        MBEDTLS_MODE_CTR},
    {cipher_bm::gcm,        MBEDTLS_MODE_GCM},
    {cipher_bm::ccm,        MBEDTLS_MODE_CCM},
    {cipher_bm::xts,        MBEDTLS_MODE_XTS},
    {cipher_bm::stream,     MBEDTLS_MODE_STREAM},
    {cipher_bm::chachapoly, MBEDTLS_MODE_CHACHAPOLY},
    {cipher_bm::unknown,    MBEDTLS_MODE_NONE},
};

const details::enum_pair<cipher_t, mbedtls_cipher_type_t> gCipherPairs[] = {
    {cipher_t::null,                MBEDTLS_CIPHER_NULL},
    {cipher_t::aes_128_ecb,         MBEDTLS_CIPHER_AES_128_ECB},
    {cipher_t::aes_192_ecb,         MBEDTLS_CIPHER_AES_192_ECB},
    {cipher_t::aes_256_ecb,         MBEDTLS_CIPHER_AES_256_ECB},
    {cipher_t::aes_128_cbc,         MBEDTLS_CIPHER_AES_128_CBC},
    {cipher_t::aes_192_cbc,         MBEDTLS_CIPHER_AES_192_CBC},
    {cipher_t::aes_256_cbc,         MBEDTLS_CIPHER_AES_256_CBC},
    {cipher_t::aes_128_cfb128,      MBEDTLS_CIPHER_AES_128_CFB128},
    {cipher_t::aes_192_cfb128,      MBEDTLS_CIPHER_AES_192_CFB128},
    {cipher_t::aes_256_cfb128,      MBEDTLS_CIPHER_AES_256_CFB128},
    {cipher_t::aes_128_ctr,         MBEDTLS_CIPHER_AES_128_CTR},
    {cipher_t::aes_192_ctr,         MBEDTLS_CIPHER_AES_192_CTR},
    {cipher_t::aes_256_ctr,         MBEDTLS_CIPHER_AES_256_CTR},
    {cipher_t::aes_128_gcm,         MBEDTLS_CIPHER_AES_128_GCM},
    {cipher_t::aes_192_gcm,         MBEDTLS_CIPHER_AES_192_GCM},
    {cipher_t::aes_256_gcm,         MBEDTLS_CIPHER_AES_256_GCM},
    {cipher_t::camellia_128_ecb,    MBEDTLS_CIPHER_CAMELLIA_128_ECB},
    {cipher_t::camellia_192_ecb,    MBEDTLS_CIPHER_CAMELLIA_192_ECB},
    {cipher_t::camellia_256_ecb,    MBEDTLS_CIPHER_CAMELLIA_256_ECB},
    {cipher_t::camellia_128_cbc,    MBEDTLS_CIPHER_CAMELLIA_128_CBC},
    {cipher_t::camellia_192_cbc,    MBEDTLS_CIPHER_CAMELLIA_192_CBC},
    {cipher_t::camellia_256_cbc,    MBEDTLS_CIPHER_CAMELLIA_256_CBC},
    {cipher_t::camellia_128_cfb128, MBEDTLS_CIPHER_CAMELLIA_128_CFB128},
    {cipher_t::camellia_192_cfb128, MBEDTLS_CIPHER_CAMELLIA_192_CFB128},
    {cipher_t::camellia_256_cfb128, MBEDTLS_CIPHER_CAMELLIA_256_CFB128},
    {cipher_t::camellia_128_ctr,    MBEDTLS_CIPHER_CAMELLIA_128_CTR},
    {cipher_t::camellia_192_ctr,    MBEDTLS_CIPHER_CAMELLIA_192_CTR},
    {cipher_t::camellia_256_ctr,    MBEDTLS_CIPHER_CAMELLIA_256_CTR},
    {cipher_t::camellia_128_gcm,    MBEDTLS_CIPHER_CAMELLIA_128_GCM},
    {cipher_t::camellia_192_gcm,    MBEDTLS_CIPHER_CAMELLIA_192_GCM},
    {cipher_t::camellia_256_gcm,    MBEDTLS_CIPHER_CAMELLIA_256_GCM},
    {cipher_t::des_ecb,             MBEDTLS_CIPHER_DES_ECB},
    {cipher_t::des_cbc,             MBEDTLS_CIPHER_DES_CBC},
    {cipher_t::des_ede_ecb,         MBEDTLS_CIPHER_DES_EDE_ECB},
    {cipher_t::des_ede_cbc,         MBEDTLS_CIPHER_DES_EDE_CBC},
    {cipher_t::des_ede3_ecb,        MBEDTLS_CIPHER_DES_EDE3_ECB},
    {cipher_t::des_ede3_cbc,        MBEDTLS_CIPHER_DES_EDE3_CBC},
    {cipher_t::blowfish_ecb,        MBEDTLS_CIPHER_BLOWFISH_ECB},
    {cipher_t::blowfish_cbc,        MBEDTLS_CIPHER_BLOWFISH_CBC},
    {cipher_t::blowfish_cfb64,      MBEDTLS_CIPHER_BLOWFISH_CFB64},
    {cipher_t::blowfish_ctr,        MBEDTLS_CIPHER_BLOWFISH_CTR},
    {cipher_t::arc4_128,            MBEDTLS_CIPHER_ARC4_128},
    {cipher_t::aes_128_ccm,         MBEDTLS_CIPHER_AES_128_CCM},
    {cipher_t::aes_192_ccm,         MBEDTLS_CIPHER_AES_192_CCM},
    {cipher_t::aes_256_ccm,         MBEDTLS_CIPHER_AES_256_CCM},
    {cipher_t::camellia_128_ccm,    MBEDTLS_CIPHER_CAMELLIA_128_CCM},
    {cipher_t::camellia_192_ccm,    MBEDTLS_CIPHER_CAMELLIA_192_CCM},
    {cipher_t::camellia_256_ccm,    MBEDTLS_CIPHER_CAMELLIA_256_CCM},
    {cipher_t::aria_128_ecb,        MBEDTLS_CIPHER_ARIA_128_ECB},
    {cipher_t::aria_192_ecb,        MBEDTLS_CIPHER_ARIA_192_ECB},
    {cipher_t::aria_256_ecb,        MBEDTLS_CIPHER_ARIA_256_ECB},
    {cipher_t::aria_128_cbc,        MBEDTLS_CIPHER_ARIA_128_CBC},
    {cipher_t::aria_192_cbc,        MBEDTLS_CIPHER_ARIA_192_CBC},
    {cipher_t::aria_256_cbc,        MBEDTLS_CIPHER_ARIA_256_CBC},
    {cipher_t::aria_128_cfb128,     MBEDTLS_CIPHER_ARIA_128_CFB128},
    {cipher_t::aria_192_cfb128,     MBEDTLS_CIPHER_ARIA_192_CFB128},
    {cipher_t::aria_256_cfb128,     MBEDTLS_CIPHER_ARIA_256_CFB128},
    {cipher_t::aria_128_ctr,        MBEDTLS_CIPHER_ARIA_128_CTR},
    {cipher_t::aria_192_ctr,        MBEDTLS_CIPHER_ARIA_192_CTR},
    {cipher_t::aria_256_ctr,        MBEDTLS_CIPHER_ARIA_256_CTR},
    {cipher_t::aria_128_gcm,        MBEDTLS_CIPHER_ARIA_128_GCM},
    {cipher_t::aria_192_gcm,        MBEDTLS_CIPHER_ARIA_192_GCM},
    {cipher_t::aria_256_gcm,        MBEDTLS_CIPHER_ARIA_256_GCM},
    {cipher_t::aria_128_ccm,        MBEDTLS_CIPHER_ARIA_128_CCM},
    {cipher_t::aria_192_ccm,        MBEDTLS_CIPHER_ARIA_192_CCM},
    {cipher_t::aria_256_ccm,        MBEDTLS_CIPHER_ARIA_256_CCM},
    {cipher_t::aes_128_ofb,         MBEDTLS_CIPHER_AES_128_OFB},
    {cipher_t::aes_192_ofb,         MBEDTLS_CIPHER_AES_192_OFB},
    {cipher_t::aes_256_ofb,         MBEDTLS_CIPHER_AES_256_OFB},
    {cipher_t::aes_128_xts,         MBEDTLS_CIPHER_AES_128_XTS},
    {cipher_t::aes_256_xts,         MBEDTLS_CIPHER_AES_256_XTS},
    {cipher_t::chacha20,            MBEDTLS_CIPHER_CHACHA20},
    {cipher_t::chacha20_poly1305,   MBEDTLS_CIPHER_CHACHA20_POLY1305},
    {cipher_t::unknown,             MBEDTLS_CIPHER_NONE},
};

const details::enum_pair<pk_t, mbedtls_pk_type_t> gPkPairs[] = {
    {pk_t::rsa,        MBEDTLS_PK_RSA},
    {pk_t::eckey,      MBEDTLS_PK_ECKEY},
    {pk_t::eckey_dh,   MBEDTLS_PK_ECKEY_DH},
    {pk_t::ecdsa,      MBEDTLS_PK_ECDSA},
    {pk_t::rsa_alt,    MBEDTLS_PK_RSA_ALT},
    {pk_t::rsassa_pss, MBEDTLS_PK_RSASSA_PSS},
    {pk_t::unknown,    MBEDTLS_PK_NONE},
};

const details::enum_pair<curve_t, mbedtls_ecp_group_id> gCurvePairs[] = {
    {curve_t::secp192r1,  MBEDTLS_ECP_DP_SECP192R1},
    {curve_t::secp224r1,  MBEDTLS_ECP_DP_SECP224R1},
    {curve_t::secp256r1,  MBEDTLS_ECP_DP_SECP256R1},
    {curve_t::secp384r1,  MBEDTLS_ECP_DP_SECP384R1},
    {curve_t::secp521r1,  MBEDTLS_ECP_DP_SECP521R1},
    {curve_t::secp192k1,  MBEDTLS_ECP_DP_SECP192K1},
    {curve_t::secp224k1,  MBEDTLS_ECP_DP_SECP224K1},
    {curve_t::secp256k1,  MBEDTLS_ECP_DP_SECP256K1},
    {curve_t::bp256r1,    MBEDTLS_ECP_DP_BP256R1},
    {curve_t::bp384r1,    MBEDTLS_ECP_DP_BP384R1},
    {curve_t::bp512r1,    MBEDTLS_ECP_DP_BP512R1},
    {curve_t::curve25519, MBEDTLS_ECP_DP_CURVE25519},
    {curve_t::unknown,    MBEDTLS_ECP_DP_NONE},
};

// clang-format on
//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

const char*
to_string(hash_t e) noexcept {
    return details::to_string(e, gHashes);
}

const char*
to_string(padding_t e) noexcept {
    return details::to_string(e, gPaddings);
}

const char*
to_string(cipher_bm e) noexcept {
    return details::to_string(e, gBlockModes);
}

const char*
to_string(cipher_t e) noexcept {
    return details::to_string(e, gCiphers);
}

const char*
to_string(pk_t e) noexcept {
    return details::to_string(e, gPks);
}

const char*
to_string(curve_t e) noexcept {
    return details::to_string(e, gCurves);
}

void
from_string(const char* name, hash_t& e) noexcept {
    e = details::from_string(name, gHashes);
}

void
from_string(const char* name, padding_t& e) noexcept {
    e = details::from_string(name, gPaddings);
}

void
from_string(const char* name, cipher_bm& e) noexcept {
    e = details::from_string(name, gBlockModes);
}

void
from_string(const char* name, cipher_t& e) noexcept {
    e = details::from_string(name, gCiphers);
}

void
from_string(const char* name, pk_t& e) noexcept {
    e = details::from_string(name, gPks);
}

void
from_string(const char* name, curve_t& e) noexcept {
    e = details::from_string(name, gCurves);
}

//-----------------------------------------------------------------------------

mbedtls_md_type_t
to_native(hash_t e) noexcept {
    return details::to_native(e, gHashPairs, MBEDTLS_MD_NONE);
}

mbedtls_cipher_padding_t
to_native(padding_t e) noexcept {
    return details::to_native(e, gPaddingPairs, MBEDTLS_PADDING_NONE);
}

mbedtls_cipher_mode_t
to_native(cipher_bm e) noexcept {
    return details::to_native(e, gBlockModePairs, MBEDTLS_MODE_NONE);
}

mbedtls_cipher_type_t
to_native(cipher_t e) noexcept {
    return details::to_native(e, gCipherPairs, MBEDTLS_CIPHER_NONE);
}

mbedtls_pk_type_t
to_native(pk_t e) noexcept {
    return details::to_native(e, gPkPairs, MBEDTLS_PK_NONE);
}

mbedtls_ecp_group_id
to_native(curve_t e) noexcept {
    return details::to_native(e, gCurvePairs, MBEDTLS_ECP_DP_NONE);
}

hash_t
from_native(mbedtls_md_type_t n) noexcept {
    return details::from_native(n, gHashPairs);
}

padding_t
from_native(mbedtls_cipher_padding_t n) noexcept {
    return details::from_native(n, gPaddingPairs);
}

cipher_bm
from_native(mbedtls_cipher_mode_t n) noexcept {
    return details::from_native(n, gBlockModePairs);
}

cipher_t
from_native(mbedtls_cipher_type_t n) noexcept {
    return details::from_native(n, gCipherPairs);
}

pk_t
from_native(mbedtls_pk_type_t n) noexcept {
    return details::from_native(n, gPkPairs);
}

curve_t
from_native(mbedtls_ecp_group_id n) noexcept {
    return details::from_native(n, gCurvePairs);
}

//-----------------------------------------------------------------------------

bool
supports(hash_t e) noexcept {
    return e == hash_t::unknown
               ? false
               : mbedtls_md_info_from_type(to_native(e)) != nullptr;
}

bool
supports(padding_t e) noexcept {
    if (e == padding_t::none)
        return true;
#if defined(MBEDTLS_CIPHER_PADDING_PKCS7)
    else if (e == padding_t::pkcs7)
        return true;
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS)
    else if (e == padding_t::one_and_zeros)
        return true;
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN)
    else if (e == padding_t::zeros_and_len)
        return true;
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS)
    else if (e == padding_t::zeros)
        return true;
#endif
    return false;
}

bool
supports(cipher_bm bm) noexcept {
    if (bm == cipher_bm::ecb)
        return true; // always supported
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    else if (bm == cipher_bm::cbc)
        return true;
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    else if (bm == cipher_bm::cfb)
        return true;
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    else if (bm == cipher_bm::ofb)
        return true;
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    else if (bm == cipher_bm::ctr)
        return true;
#endif
#if defined(MBEDTLS_GCM_C)
    else if (bm == cipher_bm::gcm)
        return true;
#endif
#if defined(MBEDTLS_CCM_C)
    else if (bm == cipher_bm::ccm)
        return true;
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    else if (bm == cipher_bm::xts)
        return true;
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    else if (bm == cipher_bm::stream)
        return true;
#endif
#if defined(MBEDTLS_CHACHAPOLY_C)
    else if (bm == cipher_bm::chachapoly)
        return true;
#endif
    return false;
}

bool
supports(cipher_t e) noexcept {
    return e == cipher_t::unknown
               ? false
               : mbedtls_cipher_info_from_type(to_native(e)) != nullptr;
}

bool
supports(pk_t e) noexcept {
    return e == pk_t::unknown
               ? false
               : mbedtls_pk_info_from_type(to_native(e)) != nullptr;
}

bool
supports(curve_t e) noexcept {
    if (e == curve_t::unknown)
        return false;
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
    else if (e == curve_t::secp192r1)
        return true;
#endif
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
    else if (e == curve_t::secp224r1)
        return true;
#endif
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
    else if (e == curve_t::secp256r1)
        return true;
#endif
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
    else if (e == curve_t::secp384r1)
        return true;
#endif
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
    else if (e == curve_t::secp521r1)
        return true;
#endif
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
    else if (e == curve_t::secp192k1)
        return true;
#endif
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
    else if (e == curve_t::secp224k1)
        return true;
#endif
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
    else if (e == curve_t::secp256k1)
        return true;
#endif
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
    else if (e == curve_t::bp256r1)
        return true;
#endif
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
    else if (e == curve_t::bp384r1)
        return true;
#endif
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
    else if (e == curve_t::bp512r1)
        return true;
#endif
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    else if (e == curve_t::curve25519)
        return true;
#endif
    return false;
}

bool
supports(features f) noexcept {
    if (f == features::aes_ni) {
#if defined(MBEDTLS_HAVE_X86_64) && defined(MBEDTLS_AESNI_C)
        return mbedtls_aesni_has_support(MBEDTLS_AESNI_AES) == 1;
#endif
    } else if (f == features::aead) {
#if defined(MBEDTLS_CIPHER_MODE_AEAD)
        return true;
#endif
    } else if (f == features::pk_keygen) {
#if defined(MBEDTLS_GENPRIME)
        return true;
#endif
    } else if (f == features::pk_ec) {
#if defined(MBEDTLS_ECP_C)
        return true;
#endif
    }
    return false;
}

//-----------------------------------------------------------------------------

std::vector<hash_t>
all_hashes() {
    return list_all(gHashes);
}

std::vector<padding_t>
all_paddings() {
    return list_all(gPaddings);
}

std::vector<cipher_bm>
all_block_modes() {
    return list_all(gBlockModes);
}

std::vector<cipher_t>
all_ciphers() {
    return list_all(gCiphers);
}

std::vector<pk_t>
all_pks() {
    return list_all(gPks);
}

std::vector<curve_t>
all_curves() {
    return list_all(gCurves);
}

std::vector<hash_t>
supported_hashes() {
    return list_supported(gHashes);
}

std::vector<padding_t>
supported_paddings() {
    return list_supported(gPaddings);
}

std::vector<cipher_bm>
supported_block_modes() {
    return list_supported(gBlockModes);
}

std::vector<cipher_t>
supported_ciphers() {
    return list_supported(gCiphers);
}

std::vector<pk_t>
supported_pks() {
    return list_supported(gPks);
}

std::vector<curve_t>
supported_curves() {
    return list_supported(gCurves);
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
