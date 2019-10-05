#include <catch2/catch.hpp>

#include "mbedcrypto/errors.hpp"
#include <mbedtls/md.h>
#include <mbedtls/cipher.h>
//-----------------------------------------------------------------------------

TEST_CASE("mbedtls errors", "[errors]") {
    using namespace mbedcrypto;

    SECTION("md error") {
        const int  Err = MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
        const auto ec  = mbedtls::make_error_code(Err);
        REQUIRE(ec.value() == Err);
        REQUIRE_FALSE(ec.message().empty());
    }

    SECTION("cipher error") {
        const int  Err = MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED;
        const auto ec  = mbedtls::make_error_code(Err);
        REQUIRE(ec.value() == Err);
        REQUIRE_FALSE(ec.message().empty());
    }
}

TEST_CASE("mbedcrypto errors", "[errors]") {
    using namespace mbedcrypto;

    struct every_thing_t {
        error_t     err;
        const char* msg;
    } all[] = {
        {error_t::success,       "success"},
        {error_t::type,          "invalid or unknown type"},
        {error_t::usage,         "bad api call or invalid argument"},
        {error_t::not_supported, "not supported by this build"},
        {error_t::bad_hash,      "invalid or unsupported hash type"},
        {error_t::bad_cipher,    "invalid or unsupported cipher type"},
        {error_t::aead,          "requires CCM or GCM modules, check build options"},
        {error_t::gcm,           "requires CGM module, check build options"},
        {error_t::pk,            "invalid or unsupported PK type"},
        {error_t::pk_export,     "requires PE_EXPORT module, check build options"},
        {error_t::rsa_keygen,    "requires RSA_KEYGEN, check build options"},
        {error_t::ecp,           "invalid or unsupported EC (elliptic curve) type"},
        {error_t::unknown,       "unknown error"},
    };

    for (const auto& a : all) {
        const auto ec = make_error_code(a.err);
        REQUIRE(ec.value()   == static_cast<int>(a.err));
        REQUIRE(ec.message() == a.msg);
    }

}
