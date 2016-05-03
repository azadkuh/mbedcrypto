#include <catch.hpp>

#include "mbedcrypto_mbedtls_config.h"
#include "mbedtls/pk.h"
#include "mbedcrypto/pki.hpp"
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

// const char*
// bstring(bool b) {
//      eturn b ? "true" : "false";
// }

// std::ostream&
// operator<<(std::ostream& s, const pk::action_flags& f) {
     //s << "encrypt: " << bstring(f.encrypt) << " , "
       //<< "decrypt: " << bstring(f.decrypt) << " , "
       //<< "sign: " << bstring(f.sign) << " , "
       //<< "verify: " << bstring(f.verify);
     //return  s;
// }

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("pk type checks", "[pki][types]") {
    using namespace mbedcrypto;
    SECTION("rsa creation tests") {
        pki pk1;
        REQUIRE_FALSE(pk1.can_do(pk_t::rsa));
        REQUIRE_FALSE(pk1.has_private_key());
        auto af = pk1.what_can_do();
        // empty instance, all members must be false
        REQUIRE_FALSE( (af.encrypt || af.decrypt || af.sign || af.verify) );

        pki pk2(pk_t::rsa);
        REQUIRE(pk2.can_do(pk_t::rsa));
        REQUIRE(icompare(pk2.name(), "RSA"));
        REQUIRE_FALSE(pk2.has_private_key());
        REQUIRE_FALSE(pk2.can_do(pk_t::rsa_alt));
        REQUIRE_FALSE(pk2.can_do(pk_t::ecdsa));
        af = pk2.what_can_do();
        // no key, all members must be false
        REQUIRE_FALSE( (af.encrypt || af.decrypt || af.sign || af.verify) );


        pki pk3;
        REQUIRE_NOTHROW(pk3.import_key(test::rsa_private_key()));
        REQUIRE(icompare(pk3.name(), "RSA"));
        REQUIRE(pk3.can_do(pk_t::rsa));
        REQUIRE_FALSE(pk3.can_do(pk_t::rsa_alt));
        REQUIRE(pk3.has_private_key());
        REQUIRE(pk3.key_bitlen() == 2048);
        af = pk3.what_can_do();
        // private key, can do all of the tasks
        REQUIRE( (af.encrypt && af.decrypt && af.sign && af.verify) );

        pki pk4;
        REQUIRE_NOTHROW(pk4.import_public_key(test::rsa_public_key()));
        REQUIRE(icompare(pk4.name(), "RSA"));
        REQUIRE(pk4.can_do(pk_t::rsa));
        REQUIRE_FALSE(pk4.can_do(pk_t::rsa_alt));
        REQUIRE_FALSE(pk4.has_private_key());
        REQUIRE(pk4.key_bitlen() == 2048);
        af = pk4.what_can_do();
        // public key can both encrypt or verify
        REQUIRE( (af.encrypt  &&  af.verify) );
        // public key can not decrypt nor sign
        REQUIRE_FALSE( (af.decrypt  |  af.sign) );

        // check key pair
        REQUIRE_THROWS( pki::check_pair(pk1, pk3) ); // pk1 is uninitialized
        REQUIRE( pki::check_pair(pk4, pk3) == true );

        // reuse of pk3
        REQUIRE_NOTHROW(pk3.import_key(
                    test::rsa_private_key_password(),
                    "mbedcrypto1234" // password
                    ));
        REQUIRE(icompare(pk3.name(), "RSA"));
        REQUIRE(pk3.can_do(pk_t::rsa));
        REQUIRE(pk3.has_private_key());
        REQUIRE(pk3.key_bitlen() == 2048);

        // pk3 is still the same key (with or without password)
        REQUIRE( pki::check_pair(pk4, pk3) == true );

    }

#if defined(MBEDTLS_ECP_C)
    SECTION("ec creation tests") {
        pki pk1;
        REQUIRE_FALSE(pk1.can_do(pk_t::eckey));

        pk1.reset_as(pk_t::eckey);
        REQUIRE_FALSE(pk1.has_private_key());
        REQUIRE( icompare(pk1.name(), "EC") );
        REQUIRE( pk1.can_do(pk_t::eckey) );
        REQUIRE( pk1.can_do(pk_t::eckey_dh) );
        #if defined(MBEDTLS_ECDSA_C)
        REQUIRE( pk1.can_do(pk_t::ecdsa) );
        #else // MBEDTLS_ECDSA_C
        REQUIRE_FALSE( pk1.can_do(pk_t::ecdsa) );
        #endif // MBEDTLS_ECDSA_C
        auto af = pk1.what_can_do();
        // pk1 has no key. all capabilities must be false
        REQUIRE_FALSE( (af.encrypt || af.decrypt || af.sign || af.verify) );

        pk1.reset_as(pk_t::eckey_dh);
        REQUIRE( icompare(pk1.name(), "EC_DH") );
        REQUIRE_FALSE(pk1.has_private_key());
        REQUIRE( pk1.can_do(pk_t::eckey_dh) );
        REQUIRE( pk1.can_do(pk_t::eckey) );
        REQUIRE_FALSE( pk1.can_do(pk_t::ecdsa) );
        // pk1 has no key. all capabilities must be false
        REQUIRE_FALSE( (af.encrypt || af.decrypt || af.sign || af.verify) );


    }
#endif // MBEDTLS_ECP_C

#if defined(MBEDTLS_ECDSA_C)
    SECTION("ecdsa creation tests") {
        pki pk1;
        REQUIRE_FALSE(pk1.can_do(pk_t::eckey));

        pk1.reset_as(pk_t::ecdsa);
        REQUIRE( icompare(pk1.name(), "ECDSA") );
        REQUIRE_FALSE(pk1.has_private_key());
        REQUIRE( pk1.can_do(pk_t::ecdsa) );
        REQUIRE_FALSE( pk1.can_do(pk_t::eckey) );
        REQUIRE_FALSE( pk1.can_do(pk_t::eckey_dh) );
        auto af = pk1.what_can_do();
        // pk1 has no key. all capabilities must be false
        REQUIRE_FALSE( (af.encrypt || af.decrypt || af.sign || af.verify) );
    }
#endif // MBEDTLS_ECDSA_C
}

///////////////////////////////////////////////////////////////////////////////

TEST_CASE("rsa pki cryptography", "[pki]") {
    using namespace mbedcrypto;

    SECTION("sign and verify") {
        // message is 455 bytes long > 2048 bits
        auto message = test::long_text();

        pki pks;
        pks.import_key(test::rsa_private_key());
        // invalid message size
        REQUIRE_THROWS( pks.sign(message) );

        auto signature = pks.sign(message, hash_t::sha1);
        REQUIRE( (signature == test::long_text_signature()) );
        // by self, a public key is rea
        REQUIRE( pks.verify(signature, message, hash_t::sha1) );

        pki pkv;
        pkv.import_public_key(test::rsa_public_key());
        REQUIRE( pkv.verify(signature, message, hash_t::sha1) );
    }

    SECTION("encrypt and decrypt") {
        const std::string message(test::long_text());
        const auto hvalue = hash::make(hash_t::sha256, message);

        pki pke;
        pke.import_public_key(test::rsa_public_key());

        REQUIRE_THROWS( pke.encrypt(message) );
        auto encv = pke.encrypt(message, hash_t::sha256);

        pki pkd;
        pkd.import_key(test::rsa_private_key());
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
        REQUIRE_FALSE( pk1.has_private_key() );

        pki pk2(pk_t::rsa);
        REQUIRE_NOTHROW( pk2.rsa_generate_key(1024) );
        REQUIRE( pk2.has_private_key() );
        REQUIRE_NOTHROW( pk2.rsa_generate_key(2048, 3) );
        REQUIRE( pk2.has_private_key() );
    }
#endif

#if defined(MBEDTLS_ECP_C)  &&  defined(MBEDTLS_PEM_WRITE_C)
    SECTION("ec key generation") {
        pki pk;
        // pk1 is not defined as ec family
        REQUIRE_THROWS( pk.ec_generate_key(curve_t::secp521r1) );

        auto test_proc = [](pk_t ptype, curve_t ctype,
                const pk::action_flags& afpri,
                const pk::action_flags& afpub) {

            pki pri(ptype);
            REQUIRE_NOTHROW( pri.ec_generate_key(ctype) );
            REQUIRE( (pri.what_can_do() == afpri) );

            auto pub_data = pri.export_public_key(pk::pem_format);
            pki pub;
            REQUIRE_NOTHROW( pub.import_public_key(pub_data) );
            REQUIRE( (pub.what_can_do() == afpub) );
        };

        test_proc(pk_t::eckey, curve_t::secp256k1,
            #if defined(MBEDTLS_ECDSA_C)
                pk::action_flags{false, false, true, true},
                pk::action_flags{false, false, false, true}
            #else
                pk::action_flags{false, false, false, true},
                pk::action_flags{false, false, false, false}
            #endif
                );

    }
#endif // MBEDTLS_ECP_C && MBEDTLS_PEM_WRITE_C
}

///////////////////////////////////////////////////////////////////////////////

#if defined(MBEDTLS_PEM_WRITE_C)
TEST_CASE("key export tests", "[pki]") {
    using namespace mbedcrypto;

#if defined(MBEDTLS_GENPRIME)
    SECTION("rsa") {
        const auto message = test::long_text();

        pki pk_g(pk_t::rsa);
        pk_g.rsa_generate_key(2048);
        const auto signature = pk_g.sign(message, hash_t::sha256);

        // test pem public
        pki pk_pub;
        pk_pub.import_public_key(pk_g.export_public_key(pk::pem_format));
        REQUIRE( pk_pub.verify(signature, message, hash_t::sha256) );
        REQUIRE( pki::check_pair(pk_pub, pk_g) == true );

        // test pem private
        pki pk_pri;
        pk_pri.import_key(pk_g.export_key(pk::pem_format));
        REQUIRE(( signature == pk_pri.sign(message, hash_t::sha256) ));
        REQUIRE( pki::check_pair(pk_pub, pk_pri) == true );

        // test der public
        pk_pub.import_public_key(pk_g.export_public_key(pk::der_format));
        REQUIRE( pk_pub.verify(signature, message, hash_t::sha256) );
        REQUIRE( pki::check_pair(pk_pub, pk_g) == true );

        // test der private
        pk_pri.import_key(pk_g.export_key(pk::der_format));
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

        auto key_test = [](curve_t ctype) {
            pki gen(pk_t::eckey);
            gen.ec_generate_key(ctype);
            auto pkey   = gen.export_key(pk::pem_format);
            auto pubkey = gen.export_public_key(pk::pem_format);

            pki pri;
            pri.import_key(pkey);
            REQUIRE( pri.type() == gen.type() );
            REQUIRE( (pubkey == pri.export_public_key(pk::pem_format)) );

            pki pub;
            pub.import_public_key(pubkey);
            REQUIRE( pub.type() == gen.type() );

            REQUIRE( pki::check_pair(pub, pri) );
        };

        for ( auto i : Items ) {
            REQUIRE_NOTHROW( key_test(i) );
        }
    }

#endif // MBEDTLS_ECP_C
}
#endif // MBEDTLS_GENPRIME && MBEDTLS_PEM_WRITE_C
///////////////////////////////////////////////////////////////////////////////

