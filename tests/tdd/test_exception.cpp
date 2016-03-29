#include <catch.hpp>
#include <cstring>
#include "mbedcrypto/types.hpp"
#include "mbedtls/md.h"

///////////////////////////////////////////////////////////////////////////////

TEST_CASE("mbedcrypto error / exception checkings", "[types][exception]") {
    using namespace mbedcrypto;

    SECTION("error codes") {
        exception ex1(MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE, "not implemented");
        REQUIRE( ex1.code() != 0 );
        REQUIRE( std::strlen(ex1.what()) > 0 );
        REQUIRE( ex1.error_string().size() > 0 );

        exception ex2("error without error code");
        REQUIRE( ex2.code() == 0 );
        REQUIRE( ex2.error_string().size() == 0 );
        REQUIRE( ex2.to_string() == ex2.what() );

        exception ex3(MBEDTLS_ERR_MD_BAD_INPUT_DATA);
        REQUIRE( ex3.code() != 0 );
        REQUIRE( std::strlen(ex3.what()) == 0 );
        REQUIRE( ex3.error_string().size() > 0 );
        REQUIRE( ex3.to_string().size() > 0 );

    }
}

