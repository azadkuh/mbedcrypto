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
    using mcerr_t = mbedcrypto::error_t;

    struct every_thing_t {
        mcerr_t     err;
        const char* msg;
    } all[] = {
        {mcerr_t::success,         "success"},
        {mcerr_t::type,            "invalid or unknown type"},
        {mcerr_t::usage,           "bad api call or invalid argument"},
        {mcerr_t::not_supported,   "not supported by this algorithm or build"},
        {mcerr_t::empty_input,     "input buffer has invalid size or data"},
        {mcerr_t::bad_input,       "invalid input type, size or data"},
        {mcerr_t::small_output,    "output buffer is empty or too small"},
        {mcerr_t::bad_hash,        "invalid or unsupported hash type"},
        {mcerr_t::bad_cipher,      "invalid or unsupported cipher type"},
        {mcerr_t::cipher_args,     "incompatible or bad cipher input arguments"},
        {mcerr_t::cipher_auth,     "failed to authenticate cipher (aead)"},
        {mcerr_t::pk,              "invalid or unsupported PK type"},
        {mcerr_t::pk_export,       "requires PE_EXPORT module, check build options"},
        {mcerr_t::rsa_keygen,      "requires RSA_KEYGEN, check build options"},
        {mcerr_t::ecp,             "invalid or unsupported EC (elliptic curve) type"},
        {mcerr_t::unknown,         "unknown error"},
    };

    for (const auto& a : all) {
        const auto ec = make_error_code(a.err);
        REQUIRE(ec.value()   == static_cast<int>(a.err));
        REQUIRE(ec.message() == a.msg);
    }

    {
        // manually build with strange error code
        std::error_code ec{-666, mbedcrypto::error_category()};
        REQUIRE(ec.value()   == -666);
        REQUIRE(ec.message() == "unknown error");
    }
}
