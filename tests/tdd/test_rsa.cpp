#include <catch.hpp>

#include "mbedcrypto/rsa.hpp"
#include "mbedcrypto/hash.hpp"
#include "generator.hpp"

#include <iostream>
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("rsa type checks", "[types][pk]") {
   using namespace mbedcrypto;

    SECTION("creation") {
        rsa my_empty;
        REQUIRE( test::icompare(my_empty.name(), "RSA") );
        REQUIRE( my_empty.can_do(pk_t::rsa) );
        REQUIRE( !my_empty.can_do(pk_t::rsa_alt) );
        REQUIRE( !my_empty.can_do(pk_t::ecdsa) );
        REQUIRE( !my_empty.has_private_key() );
        auto af = my_empty.what_can_do();
        // empty instance, all members must be false
        REQUIRE_FALSE( (af.encrypt || af.decrypt || af.sign || af.verify) );

        rsa my_pri;
        REQUIRE_NOTHROW( my_pri.import_key(test::rsa_private_key()) );
        REQUIRE( test::icompare(my_pri.name(), "RSA") );
        REQUIRE( my_pri.has_private_key() );
        REQUIRE( my_pri.can_do(pk_t::rsa) );
        REQUIRE( !my_pri.can_do(pk_t::rsa_alt) );
        REQUIRE( my_pri.key_bitlen() == 2048 );
        af = my_pri.what_can_do();
        // private key, can do all of the tasks
        REQUIRE( (af.encrypt && af.decrypt && af.sign && af.verify) );

        rsa my_key;
        REQUIRE_NOTHROW( my_key.import_public_key(test::rsa_public_key()) );
        REQUIRE( test::icompare(my_key.name(), "RSA") );
        REQUIRE( !my_key.has_private_key() );
        REQUIRE( my_key.can_do(pk_t::rsa) );
        REQUIRE( !my_key.can_do(pk_t::rsa_alt) );
        REQUIRE( my_key.key_bitlen() == 2048 );
        af = my_key.what_can_do();
        // public key can both encrypt or verify
        REQUIRE( (af.encrypt  &&  af.verify) );
        // public key can not decrypt nor sign
        REQUIRE_FALSE( (af.decrypt  |  af.sign) );

        // check key pair
        REQUIRE( !check_pair(my_empty, my_key) ); // my_empty is uninitialized
        REQUIRE( !check_pair(my_key, my_empty) ); // my_empty is uninitialized
        REQUIRE( check_pair(my_key, my_pri) == true );

        // reuse of my_key
        REQUIRE_NOTHROW(my_key.import_key(
                    test::rsa_private_key_password(),
                    "mbedcrypto1234" // password
                    ));
        REQUIRE( test::icompare(my_key.name(), "RSA") );
        REQUIRE( my_key.has_private_key() );
        REQUIRE( my_key.can_do(pk_t::rsa) );
        REQUIRE( my_key.key_bitlen() == 2048 );

        // my_key is still the same key (with or without password)
        REQUIRE( check_pair(my_pri, my_key) == true );
    }

}

TEST_CASE("rsa cryptography", "[pk]") {
    using namespace mbedcrypto;

    SECTION("cryptography max size") {
        rsa my_pri;
        my_pri.import_key(test::rsa_private_key());
        REQUIRE( my_pri.max_crypt_size() == my_pri.key_length() - 11 );

        rsa my_pub;
        my_pub.import_public_key(test::rsa_public_key());
        REQUIRE( my_pub.max_crypt_size() == my_pub.key_length() - 11 );
    }

    SECTION("sign and verify") {
        // message is 455 bytes long > 2048 bits
        auto message = test::long_text();

        rsa my_pri;
        my_pri.import_key(test::rsa_private_key());
        // invalid message size
        REQUIRE_THROWS( my_pri.sign(message) );

        auto signature = my_pri.sign(message, hash_t::sha1);
        REQUIRE( (signature == test::long_text_signature()) );
        // verify by itself, a private key contains the public
        REQUIRE( my_pri.verify(signature, message, hash_t::sha1) );

        rsa my_pub;
        my_pub.import_public_key(test::rsa_public_key());
        REQUIRE( my_pub.verify(signature, message, hash_t::sha1) );
    }

    SECTION("encrypt and decrypt") {
        const std::string message(test::long_text());
        const auto hvalue = hash::make(hash_t::sha256, message);

        rsa my_pub;
        my_pub.import_public_key(test::rsa_public_key());

        // message size is invalid
        REQUIRE_THROWS( my_pub.encrypt(message) );
        auto encv = my_pub.encrypt(message, hash_t::sha256);

        rsa my_pri;
        my_pri.import_key(test::rsa_private_key());
        REQUIRE_THROWS( my_pri.decrypt(message) );
        auto decv = my_pri.decrypt(encv);
        REQUIRE( decv == hvalue );
    }
}

TEST_CASE("rsa key tests", "[pk]") {
    using namespace mbedcrypto;

    if ( supports(features::rsa_keygen) ) {
        rsa my_pri;
        // my_pri is not defined as rsa
        REQUIRE_NOTHROW( my_pri.generate_key(1024) );
        REQUIRE( my_pri.has_private_key() );
        REQUIRE( my_pri.type() == pk_t::rsa );

        // reuse
        REQUIRE_NOTHROW( my_pri.generate_key(1024) );
        REQUIRE( my_pri.has_private_key() );
        REQUIRE_NOTHROW( my_pri.generate_key(2048, 3) );
        REQUIRE( my_pri.has_private_key() );
    }

    if ( supports(features::pk_export) ) {
        const auto message = test::long_text();

        rsa my_gen;
        my_gen.import_key(test::rsa_private_key());
        const auto signature = my_gen.sign(message, hash_t::sha256);

        // test pem public
        rsa my_pub;
        my_pub.import_public_key(my_gen.export_public_key(pk::pem_format));
        REQUIRE( my_pub.verify(signature, message, hash_t::sha256) );
        REQUIRE( check_pair(my_pub, my_gen) == true );

        // test pem private
        rsa my_pri;
        my_pri.import_key(my_gen.export_key(pk::pem_format));
        REQUIRE(( signature == my_pri.sign(message, hash_t::sha256) ));
        REQUIRE( check_pair(my_pub, my_pri) == true );

        // test der public
        my_pub.import_public_key(my_gen.export_public_key(pk::der_format));
        REQUIRE( my_pub.verify(signature, message, hash_t::sha256) );
        REQUIRE( check_pair(my_pub, my_gen) == true );

        // test der private
        my_pri.import_key(my_gen.export_key(pk::der_format));
        REQUIRE(( signature == my_pri.sign(message, hash_t::sha256) ));
        REQUIRE( check_pair(my_pub, my_pri) == true );
    }
}
