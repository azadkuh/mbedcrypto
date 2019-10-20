#include <catch2/catch.hpp>

#include "./helper.hpp"
#include "mbedcrypto/hash.hpp"
#include "mbedcrypto/text_codec.hpp"
#include "mbedcrypto_mbedtls_config.h"

#include <iostream>
//-----------------------------------------------------------------------------
namespace {
using namespace mbedcrypto;

struct tester
{
    const bin_view_t src{test::long_text()};
    hash             md;

    void run_hash(hash_t algo, size_t hsize, const char* hex) {
        REQUIRE(hsize == hash_size(algo));

        auto digest = make_hash<std::string>(src, algo);
        REQUIRE_FALSE(digest.second);
        REQUIRE(hsize == digest.first.size());

        auto hexed = to_hex<std::string>(digest.first);
        REQUIRE_FALSE(hexed.second);
        REQUIRE(hexed.first == hex);

        for (size_t i = 0; i < 2; ++i) {
            auto ec = md.start(algo);
            REQUIRE_FALSE(ec);
            // feed in many 13-bytes chunks
            test::chunker(src, 13, [this](const uint8_t* bin, size_t size) {
                md.update(bin_view_t{bin, size});
            });
            std::string output;
            ec = md.finish(output);
            REQUIRE_FALSE(ec);
            REQUIRE(output.size() == hsize);
            REQUIRE(output == digest.first);
        }
    }
};

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

TEST_CASE("hash tests", "[hash]") {
    tester t;

#if defined(MBEDTLS_MD2_C)
    t.run_hash(hash_t::md2, 16, "4b2ffc802c256a38fd6ccb575cccc27c");
#endif // MBEDTLS_MD2_C

#if defined(MBEDTLS_MD4_C)
    t.run_hash(hash_t::md4, 16, "8db2ba4980fa7d57725e42782ab47b42");
#endif // MBEDTLS_MD4_C

#if defined(MBEDTLS_MD5_C)
    t.run_hash(hash_t::md5, 16, "db89bb5ceab87f9c0fcc2ab36c189c2c");
#endif // MBEDTLS_MD5_C

#if defined(MBEDTLS_SHA1_C)
    t.run_hash(hash_t::sha1, 20, "cd36b370758a259b34845084a6cc38473cb95e27");
#endif // MBEDTLS_SHA1_C

#if defined(MBEDTLS_SHA256_C)
    t.run_hash(hash_t::sha224, 28,
        "b2d9d497bcc3e5be0ca67f08c86087a51322ae48b220ed9241cad7a5");
    t.run_hash(hash_t::sha256, 32,
        "2d8c2f6d978ca21712b5f6de36c9d31fa8e96a4fa5d8ff8b0188dfb9e7c171bb");
#endif // MBEDTLS_SHA256_C

#if defined(MBEDTLS_SHA512_C)
    t.run_hash(hash_t::sha384, 48,
        "d3b5710e17da84216f1bf08079bbbbf45303baefc6ecd677910a1c33c86cb1642"
        "81f0f2dcab55bbadc5e8606bdbc16b6");
    t.run_hash(hash_t::sha512, 64,
        "8ba760cac29cb2b2ce66858ead169174057aa1298ccd581514e6db6dee3285280"
        "ee6e3a54c9319071dc8165ff061d77783100d449c937ff1fb4cd1bb516a69b9");
#endif // MBEDTLS_SHA512_C

#if defined(MBEDTLS_RIPEMD160_C)
    t.run_hash(hasht_t::ripemd160, 20,
        "c4e3cc08809d907e233a24c10056c9951a67ffe2");
#endif // MBEDTLS_RIPEMD160_C
}
