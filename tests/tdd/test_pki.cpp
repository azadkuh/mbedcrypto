#include <catch.hpp>

#include "mbedcrypto_mbedtls_config.h"
#include "mbedtls/pk.h"
#include "mbedcrypto/pki.hpp"
#include "mbedcrypto/hash.hpp"
#include "src/conversions.hpp"

#include "generator.hpp"
#include <iostream>
///////////////////////////////////////////////////////////////////////////////
namespace {
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////

// std::ostream&
// operator<<(std::ostream& s, const pk::action_flags& f) {
//     auto bs = [](bool b) {
//         return b ? "true" : "false";
//     };

//     s << "encrypt: " << bs(f.encrypt) << " , "
//       << "decrypt: " << bs(f.decrypt) << " , "
//       << "sign: "    << bs(f.sign)    << " , "
//       << "verify: "  << bs(f.verify);
//     return  s;
// }

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

TEST_CASE("key gen", "[pki]") {
    using namespace mbedcrypto;

#if defined(MBEDTLS_ECP_C)  &&  defined(MBEDTLS_PEM_WRITE_C)
    SECTION("ec key generation") {
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
    }
#endif // MBEDTLS_GENPRIME

#if defined(MBEDTLS_ECP_C)
    SECTION("ec") {
        pki pk1;
        REQUIRE_NOTHROW( pk1.ec_generate_key(curve_t::secp256k1) );

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
            pki gen;
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

