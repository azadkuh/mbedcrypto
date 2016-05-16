#include <catch.hpp>

#include "pk_common.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace {
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////

void
mpi_checker(const char*, const mpi& mpi) {
    REQUIRE( mpi == true );
    REQUIRE( mpi.size() > 0 );
    REQUIRE( mpi.bitlen() <= (mpi.size() << 3) );

    auto bin = mpi.dump();
    REQUIRE( bin.size() == mpi.size() );

    auto str = mpi.to_string(16);
    REQUIRE( str.size() == (mpi.size() << 1) );

    REQUIRE( from_hex(str) == bin );

    // dumper(name, mpi);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("ec type checks", "[types][pk]") {
    using namespace mbedcrypto;

    if ( supports(pk_t::eckey)  ||  supports(pk_t::eckey_dh) ) {
        ecp my_key; // default as eckey
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

        REQUIRE_THROWS( my_key.reset_as(pk_t::none) );
        REQUIRE_THROWS( my_key.reset_as(pk_t::rsa) );
        REQUIRE_THROWS( my_key.reset_as(pk_t::rsa_alt) );
        REQUIRE_THROWS( my_key.reset_as(pk_t::rsassa_pss) );
        REQUIRE_NOTHROW( my_key.reset_as(pk_t::eckey) );
        REQUIRE_NOTHROW( my_key.reset_as(pk_t::eckey_dh) );
        if ( supports(pk_t::ecdsa) ) {
            REQUIRE_NOTHROW( my_key.reset_as(pk_t::ecdsa) );
        } else {
            REQUIRE_THROWS( my_key.reset_as(pk_t::ecdsa) );
        }

        my_key.reset_as(pk_t::eckey_dh);
        REQUIRE( test::icompare(my_key.name(), "EC_DH") );
        REQUIRE( !my_key.has_private_key() );
        REQUIRE( my_key.can_do(pk_t::eckey_dh) );
        REQUIRE( my_key.can_do(pk_t::eckey) );
        REQUIRE( !my_key.can_do(pk_t::ecdsa) ); // in any circumstances
        // my_key has no key. all capabilities must be false
        REQUIRE_FALSE( (af.encrypt || af.decrypt || af.sign || af.verify) );

        // rsa key is not loadable into ecp
        REQUIRE_THROWS( my_key.import_key(test::rsa_private_key()) );
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

TEST_CASE("ec key tests", "[pk]") {
    using namespace mbedcrypto;

    if ( supports(features::pk_export)  &&  supports(pk_t::eckey) ) {
        ecp gen;
        REQUIRE_THROWS( gen.generate_key(curve_t::none) );
        // test rsa conversion
        {
            REQUIRE_NOTHROW( gen.generate_key(curve_t::secp192r1) );
            auto pri_data = gen.export_key(pk::pem_format);
            auto pub_data = gen.export_public_key(pk::pem_format);

            rsa rkey;
            REQUIRE_THROWS( rkey.import_key(pri_data) );
            REQUIRE_THROWS( rkey.import_public_key(pub_data) );
        }

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
            //curve_t::curve25519, // reported bug in mbedtls!
        };

        auto key_test = [&gen](curve_t ctype, const auto& afs) {
            gen.generate_key(ctype);
            auto pri_data = gen.export_key(pk::pem_format);
            auto pub_data = gen.export_public_key(pk::pem_format);

            ecp pri;
            pri.import_key(pri_data);
            REQUIRE( pri.type() == gen.type() );
            REQUIRE( (pub_data == pri.export_public_key(pk::pem_format)) );
            ecp::key_info ki;
            pri >> ki;
            mpi_checker("Qx: ", ki.Qx);
            mpi_checker("Qy: ", ki.Qy);
            mpi_checker("Qz: ", ki.Qz);
            mpi_checker("D: ",  ki.D);

            ecp pub;
            pub.import_public_key(pub_data);
            REQUIRE( pub.type() == gen.type() );
            pub >> ki;
            mpi_checker("Qx: ", ki.Qx);
            mpi_checker("Qy: ", ki.Qy);
            mpi_checker("Qz: ", ki.Qz);
            REQUIRE( ki.D == false );

            REQUIRE( check_pair(pub, pri) );

            REQUIRE( (pri.what_can_do() == std::get<0>(afs)) );
            REQUIRE( (pub.what_can_do() == std::get<1>(afs)) );
        };

        auto eckey_afs = []() {
            if ( supports(pk_t::ecdsa) ) {
                return std::make_tuple(
                        pk::action_flags{false, false, true, true},
                        pk::action_flags{false, false, false, true}
                        );
            } else {
                return std::make_tuple(
                        pk::action_flags{false, false, false, false},
                        pk::action_flags{false, false, false, false}
                        );
            }
        };

        for ( auto i : Items ) {
            REQUIRE_NOTHROW( key_test(i, eckey_afs()) );
        }
    }
}
