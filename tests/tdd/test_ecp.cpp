#include <catch.hpp>

#include "mbedcrypto/ecp.hpp"
#include "generator.hpp"

#include <iostream>
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("ec type checks", "[types][pk]") {
    using namespace mbedcrypto;

    if ( supports(pk_t::eckey)  ||  supports(pk_t::eckey_dh) ) {
        ecp my_key; // default as eckey
        REQUIRE( my_key.can_do(pk_t::eckey)) ;
        REQUIRE( !my_key.has_private_key() ); // no key is provided
        REQUIRE( test::icompare(my_key.name(), "EC") );
        REQUIRE( my_key.can_do(pk_t::eckey) );
        REQUIRE( my_key.can_do(pk_t::eckey_dh) );
        if ( supports(pk_t::ecdsa) ) {
            REQUIRE( my_key.can_do(pk_t::ecdsa) );
        } else {
            REQUIRE( !my_key.can_do(pk_t::ecdsa) );
        }

        auto af = my_key.what_can_do();
        // my_key has no key. all capabilities must be false
        REQUIRE_FALSE( (af.encrypt || af.decrypt || af.sign || af.verify) );

        my_key.reset_as(pk_t::eckey_dh);
        REQUIRE( test::icompare(my_key.name(), "EC_DH") );
        REQUIRE( !my_key.has_private_key() );
        REQUIRE( my_key.can_do(pk_t::eckey_dh) );
        REQUIRE( my_key.can_do(pk_t::eckey) );
        REQUIRE( !my_key.can_do(pk_t::ecdsa) ); // in any circumstances
        // my_key has no key. all capabilities must be false
        REQUIRE_FALSE( (af.encrypt || af.decrypt || af.sign || af.verify) );
    }

    if ( supports(pk_t::ecdsa) ) {
        ecp my_key(pk_t::ecdsa);
        REQUIRE( test::icompare(my_key.name(), "ECDSA") );
        REQUIRE( !my_key.has_private_key() );
        REQUIRE( my_key.can_do(pk_t::ecdsa) );
        REQUIRE( !my_key.can_do(pk_t::eckey) );
        REQUIRE( !my_key.can_do(pk_t::eckey_dh) );
        auto af = my_key.what_can_do();
        // my_key has no key. all capabilities must be false
        REQUIRE_FALSE( (af.encrypt || af.decrypt || af.sign || af.verify) );
    }
}


