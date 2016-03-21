#include <catch.hpp>

#include "mbedtls/pk.h"
#include "mbedcrypto/pki.hpp"
#include "mbedcrypto/random.hpp"
#include "mbedcrypto/tcodec.hpp"
#include "src/conversions.hpp"

#include "generator.hpp"
#include <iostream>
#include <fstream>
///////////////////////////////////////////////////////////////////////////////
namespace {
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("pk type checks", "[pki][types]") {
    using namespace mbedcrypto;
    SECTION("creation tests") {
        pki pk1;
        REQUIRE_FALSE(pk1.can_do(pk_t::rsa));

        pki pk2(pk_t::rsa);
        REQUIRE(pk2.can_do(pk_t::rsa));
        REQUIRE_FALSE(pk2.can_do(pk_t::rsa_alt));
        REQUIRE_FALSE(pk2.can_do(pk_t::ecdsa));

        pki pk3;
        REQUIRE_NOTHROW(pk3.parse_key(test::sample_private_key()));
        REQUIRE(pk3.can_do(pk_t::rsa));
        REQUIRE_FALSE(pk3.can_do(pk_t::rsa_alt));
        REQUIRE(pk3.bitlen() == 2048);

        // reuse of pk3
        REQUIRE_NOTHROW(pk3.parse_public_key(test::sample_public_key()));
        REQUIRE(pk3.can_do(pk_t::rsa));
        REQUIRE_FALSE(pk3.can_do(pk_t::rsa_alt));
        REQUIRE(pk3.bitlen() == 2048);

        REQUIRE_NOTHROW(pk3.parse_key(
                    test::sample_private_key_password(),
                    "mbedcrypto1234" // password
                    ));
        REQUIRE(pk3.can_do(pk_t::rsa));
        REQUIRE(pk3.bitlen() == 2048);
    }
}


///////////////////////////////////////////////////////////////////////////////
