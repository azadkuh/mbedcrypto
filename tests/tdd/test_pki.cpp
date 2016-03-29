#include <catch.hpp>

#include "mbedtls/pk.h"
#include "mbedcrypto/pki.hpp"
#include "mbedcrypto/random.hpp"
#include "mbedcrypto/hash.hpp"
#include "src/conversions.hpp"

#include "generator.hpp"
#include <cstring>
#include <iostream>
#include <fstream>
///////////////////////////////////////////////////////////////////////////////
namespace {
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////
bool
icompare(const char* a, const char* b) {
    return std::strncmp(a, b, strlen(b)) == 0;
}
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
        REQUIRE(icompare(pk2.name(), "RSA"));
        REQUIRE_FALSE(pk2.can_do(pk_t::rsa_alt));
        REQUIRE_FALSE(pk2.can_do(pk_t::ecdsa));

        pki pk3;
        REQUIRE_NOTHROW(pk3.parse_key(test::sample_private_key()));
        REQUIRE(icompare(pk3.name(), "RSA"));
        REQUIRE(pk3.can_do(pk_t::rsa));
        REQUIRE_FALSE(pk3.can_do(pk_t::rsa_alt));
        REQUIRE(pk3.bitlen() == 2048);

        // reuse of pk3
        REQUIRE_NOTHROW(pk3.parse_public_key(test::sample_public_key()));
        REQUIRE(icompare(pk3.name(), "RSA"));
        REQUIRE(pk3.can_do(pk_t::rsa));
        REQUIRE_FALSE(pk3.can_do(pk_t::rsa_alt));
        REQUIRE(pk3.bitlen() == 2048);

        REQUIRE_NOTHROW(pk3.parse_key(
                    test::sample_private_key_password(),
                    "mbedcrypto1234" // password
                    ));
        REQUIRE(icompare(pk3.name(), "RSA"));
        REQUIRE(pk3.can_do(pk_t::rsa));
        REQUIRE(pk3.bitlen() == 2048);
    }
}

TEST_CASE("pki cryptography", "[pki]") {
    using namespace mbedcrypto;

    SECTION("sign and verify") {
        // message is 455 bytes long > 2048 bits
        auto message = test::long_text();

        pki pks;
        pks.parse_key(test::sample_private_key());
        // invalid message size
        REQUIRE_THROWS( pks.sign(message) );

        auto signature = pks.sign(message, hash_t::sha1);
        REQUIRE( (signature == test::long_text_signature()) );
        // by self, a public key is rea
        REQUIRE( pks.verify(signature, message, hash_t::sha1) );

        pki pkv;
        pkv.parse_public_key(test::sample_public_key());
        REQUIRE( pkv.verify(signature, message, hash_t::sha1) );
    }

    SECTION("encrypt and decrypt") {
        const std::string message(test::long_text());
        const auto hvalue = hash::make(hash_t::sha256, message);

        pki pke;
        pke.parse_public_key(test::sample_public_key());

        REQUIRE_THROWS( pke.encrypt(message) );
        auto encv = pke.encrypt(message, hash_t::sha256);

        pki pkd;
        pkd.parse_key(test::sample_private_key());
        REQUIRE_THROWS( pkd.decrypt(message) );
        auto decv = pkd.decrypt(encv);
        REQUIRE( decv == hvalue );
    }
}

///////////////////////////////////////////////////////////////////////////////
