#include "mbedcrypto/types.hpp"
// #include "mbedcrypto/cipher.hpp"
// #include "mbedcrypto/pk.hpp"

#include "./enumerator.hxx"
// #include "./conversions.hpp"

//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
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
    {cipher_bm::ecb,     "ecb"},
    {cipher_bm::cbc,     "cbc"},
    {cipher_bm::cfb,     "cfb"},
    {cipher_bm::ctr,     "ctr"},
    {cipher_bm::gcm,     "gcm"},
    {cipher_bm::ccm,     "ccm"},
    {cipher_bm::stream,  "stream"},
    {cipher_bm::unknown, "unknown"},
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

#if 0 // yet to be refactored
bool
supports(features) {
    return false;
    switch (f) {
    case features::aes_ni:
        return cipher::supports_aes_ni();

    case features::aead:
        return cipher::supports_aead();

    case features::pk_export:
        return pk::supports_key_export();

    case features::rsa_keygen:
        return pk::supports_rsa_keygen();

    case features::ec_keygen:
        return pk::supports_ec_keygen();

    default:
        return false;
    }
}

bool
supports(hash_t e) {
    return mbedtls_md_info_from_type(to_native(e)) != nullptr;
}

bool
supports(padding_t e) {
#if defined(MBEDTLS_CIPHER_PADDING_PKCS7)
    if (e == padding_t::pkcs7)
        return true;
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS)
    if (e == padding_t::one_and_zeros)
        return true;
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN)
    if (e == padding_t::zeros_and_len)
        return true;
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS)
    if (e == padding_t::zeros)
        return true;
#endif
    if (e == padding_t::none)
        return true;

    return false;
}

bool
supports(cipher_bm bm) {
    switch (bm) {
    case cipher_bm::none:
    case cipher_bm::ecb:
        return true; // always supported

    case cipher_bm::cbc:
#if defined(MBEDTLS_CIPHER_MODE_CBC)
        return true;
#else
        return false;
#endif

    case cipher_bm::cfb:
#if defined(MBEDTLS_CIPHER_MODE_CFB)
        return true;
#else
        return false;
#endif

    case cipher_bm::ctr:
#if defined(MBEDTLS_CIPHER_MODE_CTR)
        return true;
#else
        return false;
#endif

    case cipher_bm::gcm:
#if defined(MBEDTLS_GCM_C)
        return true;
#else
        return false;
#endif

    case cipher_bm::ccm:
#if defined(MBEDTLS_CCM_C)
        return true;
#else
        return false;
#endif

    case cipher_bm::stream:
#if defined(MBEDTLS_ARC4_C)
        return true;
#else
        return false;
#endif

    default:
        break;
    }

    return false;
}

bool
supports(cipher_t e) {
    return mbedtls_cipher_info_from_type(to_native(e)) != nullptr;
}

bool
supports(pk_t e) {
    return mbedtls_pk_info_from_type(to_native(e)) != nullptr;
}

// other installed_xx() are implemented in conversion.cpp
std::vector<cipher_bm>
installed_block_modes() {
    std::vector<cipher_bm> my;
    for (auto bm : gBlockModes) {
        if (supports(bm.e))
            my.push_back(bm.e);
    }

    return my;
}

bool
supports(curve_t e) {
    switch (e) {
    case curve_t::none:
        return false;

    case curve_t::secp192r1:
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
        return true;
#else
        return false;
#endif

    case curve_t::secp224r1:
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
        return true;
#else
        return false;
#endif

    case curve_t::secp256r1:
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
        return true;
#else
        return false;
#endif

    case curve_t::secp384r1:
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
        return true;
#else
        return false;
#endif

    case curve_t::secp521r1:
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
        return true;
#else
        return false;
#endif

    case curve_t::secp192k1:
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
        return true;
#else
        return false;
#endif

    case curve_t::secp224k1:
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
        return true;
#else
        return false;
#endif

    case curve_t::secp256k1:
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
        return true;
#else
        return false;
#endif

    case curve_t::bp256r1:
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
        return true;
#else
        return false;
#endif

    case curve_t::bp384r1:
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
        return true;
#else
        return false;
#endif

    case curve_t::bp512r1:
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
        return true;
#else
        return false;
#endif

    case curve_t::curve25519:
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
        return true;
#else
        return false;
#endif

    default:
        return false;
        break;
    }
}

//-----------------------------------------------------------------------------

bool
supports_hash(const char* name) {
    auto e = hash_from_string(name);
    return (e == hash_t::none) ? false : supports(e);
}

bool
supports_padding(const char* name) {
    // padding_t::none is an acceptable padding
    return supports(padding_from_string(name));
}

bool
supports_block_mode(const char* name) {
    auto bm = block_mode_from_string(name);
    return (bm == cipher_bm::none) ? false : supports(bm);
}

bool
supports_cipher(const char* name) {
    auto e = cipher_from_string(name);
    return (e == cipher_t::none) ? false : supports(e);
}

bool
supports_pk(const char* name) {
    auto e = pk_from_string(name);
    return (e == pk_t::none) ? false : supports(e);
}

bool
supports_curve(const char* name) {
    auto e = curve_from_string(name);
    return (e == curve_t::none) ? false : supports(e);
}

//-----------------------------------------------------------------------------

hash_t
hash_from_string(const char* name) {
    auto t = mbedtls_md_get_type(
        mbedtls_md_info_from_string(to_upper(name).c_str()));
    return from_native(t);
}

padding_t
padding_from_string(const char* name) {
    return from_string<padding_t>(name, gPaddings);
}

cipher_bm
block_mode_from_string(const char* name) {
    return from_string<cipher_bm>(name, gBlockModes);
}

cipher_t
cipher_from_string(const char* name) {
    const auto* p = mbedtls_cipher_info_from_string(to_upper(name).c_str());
    if (p == nullptr)
        return cipher_t::none;
    return from_native(p->type);
}

pk_t
pk_from_string(const char* name) {
    return from_string<pk_t>(name, gPks);
}

curve_t
curve_from_string(const char* name) {
    return from_string<curve_t>(name, gCurves);
}

#endif
//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
