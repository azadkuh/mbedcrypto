#include <catch.hpp>
#include <iostream>

#include "src/mbedtls_config.h"
#include "generator.hpp"
#include "mbedcrypto/hash.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace {
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////
const char* long_md2() {
    return "4b2ffc802c256a38fd6ccb575cccc27c";
}

const char* long_md4() {
    return "8db2ba4980fa7d57725e42782ab47b42";
}

const char* long_md5() {
    return "db89bb5ceab87f9c0fcc2ab36c189c2c";
}

const char* long_sha1() {
    return "cd36b370758a259b34845084a6cc38473cb95e27";
}

const char* long_sha224() {
    return "b2d9d497bcc3e5be0ca67f08c86087a51322ae48b220ed9241cad7a5";
}

const char* long_sha256() {
    return "2d8c2f6d978ca21712b5f6de36c9d31fa8e96a4fa5d8ff8b0188dfb9e7c171bb";
}

const char* long_sha384() {
    return "d3b5710e17da84216f1bf08079bbbbf45303baefc6ecd677910a1c33c86cb1642"
        "81f0f2dcab55bbadc5e8606bdbc16b6";
}

const char* long_sha512() {
    return "8ba760cac29cb2b2ce66858ead169174057aa1298ccd581514e6db6dee3285280"
        "ee6e3a54c9319071dc8165ff061d77783100d449c937ff1fb4cd1bb516a69b9";
}

const char* long_ripemd160() {
    return "c4e3cc08809d907e233a24c10056c9951a67ffe2";
}

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

TEST_CASE("hash tests", "[hash]") {
    using namespace mbedcrypto;

    SECTION("size and single shot digest") {
        const buffer_t src(test::long_text());

        #if defined(MBEDTLS_MD2_C)
        REQUIRE( hash_size(hash_t::md2) == 16 );
        REQUIRE( to_hex(make_hash(hash_t::md2, src)) == long_md2() );
        #endif

        #if defined(MBEDTLS_MD4_C)
        REQUIRE( hash_size(hash_t::md4) == 16 );
        REQUIRE( to_hex(make_hash(hash_t::md4, src)) == long_md4() );
        #endif // MBEDTLS_MD4_C

        #if defined(MBEDTLS_MD5_C)
        REQUIRE( hash_size(hash_t::md5) == 16 );
        REQUIRE( to_hex(make_hash(hash_t::md5, src)) == long_md5() );
        #endif // MBEDTLS_MD5_C

        #if defined(MBEDTLS_SHA1_C)
        REQUIRE( hash_size(hash_t::sha1) == 20 );
        REQUIRE( to_hex(make_hash(hash_t::sha1, src)) == long_sha1() );
        #endif // MBEDTLS_SHA1_C

        #if defined(MBEDTLS_SHA256_C)
        REQUIRE( hash_size(hash_t::sha224) == 28 );
        REQUIRE( hash_size(hash_t::sha256) == 32 );
        REQUIRE( to_hex(make_hash(hash_t::sha224, src)) == long_sha224() );
        REQUIRE( to_hex(make_hash(hash_t::sha256, src)) == long_sha256() );
        #endif // MBEDTLS_SHA256_C

        #if defined(MBEDTLS_SHA512_C)
        REQUIRE( hash_size(hash_t::sha384) == 48 );
        REQUIRE( hash_size(hash_t::sha512) == 64 );
        REQUIRE( to_hex(make_hash(hash_t::sha384, src)) == long_sha384() );
        REQUIRE( to_hex(make_hash(hash_t::sha512, src)) == long_sha512() );
        #endif // MBEDTLS_SHA512_C

        #if defined(MBEDTLS_RIPEMD160_C)
        REQUIRE( hash_size(hash_t::ripemd160) == 20 );
        REQUIRE( to_hex(make_hash(hash_t::ripemd160, src)) == long_ripemd160() );
        #endif // MBEDTLS_RIPEMD160_C

    }
}

