#include "mbedcrypto/types.hpp"
#include "mbedtls/md.h"
#include <catch2/catch.hpp>

///////////////////////////////////////////////////////////////////////////////

TEST_CASE("mbedcrypto error / exception checkings", "[types][exception]") {
    using namespace mbedcrypto;

    SECTION("error codes") {
        exception ex1(MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE, "not implemented");
        REQUIRE(ex1.code() == MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE);
        REQUIRE(std::strlen(ex1.what()) > 0);
        REQUIRE(ex1.error_string().size() > 0);

        exception ex2("error without error code");
        REQUIRE(ex2.code() == 0);
        REQUIRE(ex2.error_string().size() == 0);

        exception ex3(MBEDTLS_ERR_MD_BAD_INPUT_DATA);
        REQUIRE(ex3.code() != 0);
        REQUIRE(ex3.error_string().size() > 0);
        REQUIRE(ex3.error_string() == ex3.what()); // only error code
    }

    SECTION("throws") {
        try {
            mbedtls_md_context_t md;
            mbedtls_md_init(&md); // initialize items to nullptr
            // uninitialize (no md type): mbedcrypto_c_call must throw:
            mbedcrypto_c_call(mbedtls_md_starts, &md);
            REQUIRE_FALSE("above line must throw");

        } catch (exception&) {
            REQUIRE("fine");
        }
    }
}
