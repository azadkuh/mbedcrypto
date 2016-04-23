#include <catch.hpp>

#include "mbedcrypto_mbedtls_config.h"
#include "mbedtls/pk.h"
#include "mbedcrypto/pki.hpp"
#include "mbedcrypto/random.hpp"
#include "mbedcrypto/hash.hpp"
#include "src/conversions.hpp"

#include "generator.hpp"
#include <cstring>
#include <iostream>
///////////////////////////////////////////////////////////////////////////////
namespace {
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////
bool
icompare(const char* a, const char* b) {
    return std::strncmp(a, b, strlen(b)) == 0;
}

template<class F, class... Args>
void run_safe(F&& f, Args&&... args) {
    try {
        f(std::forward<Args&&>(args)...);

    } catch ( mbedcrypto::exception& cerr ) {
        std::cerr << cerr.to_string() << std::endl;
        throw;
    }
}
///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("pk type checks", "[pki][types]") {
    using namespace mbedcrypto;
    SECTION("rsa creation tests") {
        pki pk1;
        REQUIRE_FALSE(pk1.can_do(pk_t::rsa));

        pki pk2(pk_t::rsa);
        REQUIRE(pk2.can_do(pk_t::rsa));
        REQUIRE(icompare(pk2.name(), "RSA"));
        REQUIRE_FALSE(pk2.can_do(pk_t::rsa_alt));
        REQUIRE_FALSE(pk2.can_do(pk_t::ecdsa));

        pki pk3;
        REQUIRE_NOTHROW(pk3.parse_key(test::rsa_private_key()));
        REQUIRE(icompare(pk3.name(), "RSA"));
        REQUIRE(pk3.can_do(pk_t::rsa));
        REQUIRE_FALSE(pk3.can_do(pk_t::rsa_alt));
        REQUIRE(pk3.bitlen() == 2048);

        pki pk4;
        REQUIRE_NOTHROW(pk4.parse_public_key(test::rsa_public_key()));
        REQUIRE(icompare(pk4.name(), "RSA"));
        REQUIRE(pk4.can_do(pk_t::rsa));
        REQUIRE_FALSE(pk4.can_do(pk_t::rsa_alt));
        REQUIRE(pk4.bitlen() == 2048);

        // check key pair
        REQUIRE_THROWS( pki::check_pair(pk1, pk3) ); // pk1 is uninitialized
        REQUIRE( pki::check_pair(pk4, pk3) == true );

        // reuse of pk3
        REQUIRE_NOTHROW(pk3.parse_key(
                    test::rsa_private_key_password(),
                    "mbedcrypto1234" // password
                    ));
        REQUIRE(icompare(pk3.name(), "RSA"));
        REQUIRE(pk3.can_do(pk_t::rsa));
        REQUIRE(pk3.bitlen() == 2048);

        // pk3 is still the same key (with or without password)
        REQUIRE( pki::check_pair(pk4, pk3) == true );

    }

#if defined(MBEDTLS_ECP_C)
    SECTION("ec creation tests") {
        pki pk1;
        REQUIRE_FALSE(pk1.can_do(pk_t::eckey));

        pk1.reset_as(pk_t::eckey);
        REQUIRE( icompare(pk1.name(), "EC") );
        REQUIRE( pk1.can_do(pk_t::eckey) );
        REQUIRE( pk1.can_do(pk_t::eckey_dh) );
        REQUIRE( pk1.can_do(pk_t::ecdsa) );

        pk1.reset_as(pk_t::eckey_dh);
        REQUIRE( icompare(pk1.name(), "EC_DH") );
        REQUIRE( pk1.can_do(pk_t::eckey_dh) );
        REQUIRE( pk1.can_do(pk_t::eckey) );
        REQUIRE_FALSE( pk1.can_do(pk_t::ecdsa) );


    }
#endif // MBEDTLS_ECP_C

#if defined(MBEDTLS_ECDSA_C)
    SECTION("ecdsa creation tests") {
        pki pk1;
        REQUIRE_FALSE(pk1.can_do(pk_t::eckey));

        pk1.reset_as(pk_t::ecdsa);
        REQUIRE( icompare(pk1.name(), "ECDSA") );
        REQUIRE( pk1.can_do(pk_t::ecdsa) );
        REQUIRE_FALSE( pk1.can_do(pk_t::eckey) );
        REQUIRE_FALSE( pk1.can_do(pk_t::eckey_dh) );
    }

#endif // MBEDTLS_ECDSA_C
}

///////////////////////////////////////////////////////////////////////////////

TEST_CASE("pki cryptography", "[pki]") {
    using namespace mbedcrypto;

    SECTION("sign and verify") {
        // message is 455 bytes long > 2048 bits
        auto message = test::long_text();

        pki pks;
        pks.parse_key(test::rsa_private_key());
        // invalid message size
        REQUIRE_THROWS( pks.sign(message) );

        auto signature = pks.sign(message, hash_t::sha1);
        REQUIRE( (signature == test::long_text_signature()) );
        // by self, a public key is rea
        REQUIRE( pks.verify(signature, message, hash_t::sha1) );

        pki pkv;
        pkv.parse_public_key(test::rsa_public_key());
        REQUIRE( pkv.verify(signature, message, hash_t::sha1) );
    }

    SECTION("encrypt and decrypt") {
        const std::string message(test::long_text());
        const auto hvalue = hash::make(hash_t::sha256, message);

        pki pke;
        pke.parse_public_key(test::rsa_public_key());

        REQUIRE_THROWS( pke.encrypt(message) );
        auto encv = pke.encrypt(message, hash_t::sha256);

        pki pkd;
        pkd.parse_key(test::rsa_private_key());
        REQUIRE_THROWS( pkd.decrypt(message) );
        auto decv = pkd.decrypt(encv);
        REQUIRE( decv == hvalue );
    }
}

///////////////////////////////////////////////////////////////////////////////

TEST_CASE("key gen", "[pki]") {
    using namespace mbedcrypto;

#if defined(MBEDTLS_GENPRIME)
    SECTION("rsa key generation") {
        pki pk1;
        // pk1 is not defined as rsa
        REQUIRE_THROWS( pk1.rsa_generate_key(1024) );

        pki pk2(pk_t::rsa);
        REQUIRE_NOTHROW( pk2.rsa_generate_key(1024) );
        REQUIRE_NOTHROW( pk2.rsa_generate_key(2048, 3) );
    }
#endif

#if defined(MBEDTLS_ECP_C)
    SECTION("ec key generation") {
    }
#endif // MBEDTLS_ECP_C
}

///////////////////////////////////////////////////////////////////////////////

#if defined(MBEDTLS_PEM_WRITE_C)
TEST_CASE("key export tests", "[pki]") {
    using namespace mbedcrypto;

    const auto message = test::long_text();

#if defined(MBEDTLS_GENPRIME)
    SECTION("rsa") {
        pki pk_g(pk_t::rsa);
        pk_g.rsa_generate_key(2048);
        const auto signature = pk_g.sign(message, hash_t::sha256);

        // test pem public
        pki pk_pub;
        pk_pub.parse_public_key(pk_g.export_public_key(pki::pem_format));
        REQUIRE( pk_pub.verify(signature, message, hash_t::sha256) );
        REQUIRE( pki::check_pair(pk_pub, pk_g) == true );

        // test pem private
        pki pk_pri;
        pk_pri.parse_key(pk_g.export_key(pki::pem_format));
        REQUIRE(( signature == pk_pri.sign(message, hash_t::sha256) ));
        REQUIRE( pki::check_pair(pk_pub, pk_pri) == true );

        // test der public
        pk_pub.parse_public_key(pk_g.export_public_key(pki::der_format));
        REQUIRE( pk_pub.verify(signature, message, hash_t::sha256) );
        REQUIRE( pki::check_pair(pk_pub, pk_g) == true );

        // test der private
        pk_pri.parse_key(pk_g.export_key(pki::der_format));
        REQUIRE(( signature == pk_pri.sign(message, hash_t::sha256) ));
        REQUIRE( pki::check_pair(pk_pub, pk_pri) == true );

        // recreate key
        REQUIRE_NOTHROW( pk_pri.rsa_generate_key(1024, 3) );
        REQUIRE( pki::check_pair(pk_pub, pk_pri) == false );
    }
#endif // MBEDTLS_GENPRIME

#if defined(MBEDTLS_ECP_C)
    SECTION("ec") {
        pki pk1;
        REQUIRE_THROWS( pk1.ec_generate_key(curve_t::secp256k1) );

        pki pk2(pk_t::eckey);
        REQUIRE_THROWS( pk2.ec_generate_key(curve_t::none) );

        const std::initializer_list<curve_t> Items = {
            curve_t::secp192r1,
            curve_t::secp224r1,
            curve_t::secp256r1,
            curve_t::secp384r1,
            curve_t::secp521r1,
            curve_t::secp192k1,
            curve_t::secp224k1,
            curve_t::secp256k1,
            curve_t::bp256r1,
            curve_t::bp384r1,
            curve_t::bp512r1,
            //curve_t::curve25519,
        };

        auto key_test = [](pki& pkg, curve_t ctype) {
            pkg.ec_generate_key(ctype);
            auto pkey   = pkg.export_key(pki::pem_format);
            auto pubkey = pkg.export_public_key(pki::pem_format);

            pki pri;
            pri.parse_key(pkey);
            REQUIRE( pri.type() == pkg.type() );
            REQUIRE( (pubkey == pri.export_public_key(pki::pem_format)) );

            pki pub;
            pub.parse_public_key(pubkey);
        };

        for ( auto i : Items ) {
            REQUIRE_NOTHROW( run_safe(key_test, pk2, i) );
        }
    }

#endif // MBEDTLS_ECP_C
}
#endif // MBEDTLS_GENPRIME && MBEDTLS_PEM_WRITE_C
///////////////////////////////////////////////////////////////////////////////

