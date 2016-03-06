#include <catch.hpp>
#include <iostream>

#include "src/mbedtls_config.h"
#include "generator.hpp"
#include "mbedcrypto/hash.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace {
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

TEST_CASE("hash tests", "[hash]") {
    using namespace mbedcrypto;

    SECTION("size and single shot digest") {
        #if defined(MBEDTLS_MD2_C)
        REQUIRE( hash_size(hash_t::md2) == 16 );
        #endif

        #if defined(MBEDTLS_MD4_C)
        REQUIRE( hash_size(hash_t::md4) == 16 );
        #endif // MBEDTLS_MD4_C

        #if defined(MBEDTLS_MD5_C)
        REQUIRE( hash_size(hash_t::md5) == 16 );
        #endif // MBEDTLS_MD5_C

        #if defined(MBEDTLS_SHA1_C)
        REQUIRE( hash_size(hash_t::sha1) == 20 );
        #endif // MBEDTLS_SHA1_C

        #if defined(MBEDTLS_SHA256_C)
        REQUIRE( hash_size(hash_t::sha224) == 28 );
        REQUIRE( hash_size(hash_t::sha256) == 32 );
        #endif // MBEDTLS_SHA256_C

        #if defined(MBEDTLS_SHA512_C)
        REQUIRE( hash_size(hash_t::sha384) == 48 );
        REQUIRE( hash_size(hash_t::sha512) == 64 );
        #endif // MBEDTLS_SHA512_C

        #if defined(MBEDTLS_RIPEMD160_C)
        REQUIRE( hash_size(hash_t::ripemd160) == 20 );
        #endif // MBEDTLS_RIPEMD160_C

    }
}

