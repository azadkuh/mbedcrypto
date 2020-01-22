#include <catch2/catch.hpp>

#include "./helper.hpp"
#include "mbedcrypto/hash.hpp"
#include "mbedcrypto/text_codec.hpp"
#include "mbedcrypto_mbedtls_config.h"

#include <iostream>
//-----------------------------------------------------------------------------
namespace {
using namespace mbedcrypto;
using mcerr_t = mbedcrypto::error_t;

struct tester
{
    const bin_view_t src{test::long_text()};
    const bin_view_t key{test::short_text()};
    hash             md;
    hmac             mac;

    void run(hash_t algo, size_t hsize, const char* hex_hash, const char* hex_hmac) {
        _test_hash(algo, hsize, hex_hash);
        _test_hmac(algo, hsize, hex_hmac);
    }

    void fail(hash_t algo) {
        REQUIRE(hash_size(algo) == 0);

        auto digest = make_hash<std::string>(src, algo);
        REQUIRE(digest.second == make_error_code(mcerr_t::not_supported));
        REQUIRE(digest.first.empty());

        auto ec = md.start(algo);
        REQUIRE(ec == make_error_code(mcerr_t::not_supported));

        digest = make_hmac<std::string>(src, key, algo);
        REQUIRE(digest.second == make_error_code(mcerr_t::not_supported));
        REQUIRE(digest.first.empty());

        ec = mac.start(key, algo);
        REQUIRE(ec == make_error_code(mcerr_t::not_supported));
    }

protected:
    void _test_hash(hash_t algo, size_t hsize, const char* hex) {
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
            ec = md.finish(auto_size_t{output});
            REQUIRE_FALSE(ec);
            REQUIRE(output.size() == hsize);
            REQUIRE(output == digest.first);
        }
    }

    void _test_hmac(hash_t algo, size_t hsize, const char* hex) {
        auto digest = make_hmac<std::string>(src, key, algo);
        REQUIRE_FALSE(digest.second);
        REQUIRE(hsize == digest.first.size());

        auto hexed = to_hex<std::string>(digest.first);
        REQUIRE_FALSE(hexed.second);
        REQUIRE(hexed.first == hex);

        for (size_t i = 0; i < 2; ++i) {
            auto ec = mac.start(key, algo);
            REQUIRE_FALSE(ec);
            // feed in many 13-bytes chunks
            test::chunker(src, 13, [this](const uint8_t* bin, size_t size) {
                mac.update(bin_view_t{bin, size});
            });
            std::string output;
            ec = mac.finish(auto_size_t{output});
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
    t.run(hash_t::md2, 16,
            "4b2ffc802c256a38fd6ccb575cccc27c",
            "2f4145529e20098f844838ed8fa25c00"
            );
#else
    t.fail(hash_t::md2);
#endif // MBEDTLS_MD2_C

#if defined(MBEDTLS_MD4_C)
    t.run(hash_t::md4, 16,
            "8db2ba4980fa7d57725e42782ab47b42",
            "8cf0fe3c2742db0c79887e2c7db38932"
            );
#else
    t.fail(hash_t::md4);
#endif // MBEDTLS_MD4_C

#if defined(MBEDTLS_MD5_C)
    t.run(hash_t::md5, 16,
            "db89bb5ceab87f9c0fcc2ab36c189c2c",
            "e6be7149bdf6c8ba909f73cf70f418bc"
            );
#else
    t.fail(hash_t::md5);
#endif // MBEDTLS_MD5_C

#if defined(MBEDTLS_SHA1_C)
    t.run(hash_t::sha1, 20,
            "cd36b370758a259b34845084a6cc38473cb95e27",
            "e555abe5b1e4778d2b9a287ad54b307b23a9ae7f"
            );
#else
#error sha1 is mandatory in every build
#endif // MBEDTLS_SHA1_C

#if defined(MBEDTLS_SHA256_C)
    t.run(hash_t::sha224, 28,
        "b2d9d497bcc3e5be0ca67f08c86087a51322ae48b220ed9241cad7a5",
        "5e8ec017b64206dc1255cccfa9ba0855a7fe049e56a738ed8c8dbeba"
        );
    t.run(hash_t::sha256, 32,
        "2d8c2f6d978ca21712b5f6de36c9d31fa8e96a4fa5d8ff8b0188dfb9e7c171bb",
        "85844cded885971e6c58087c814cdee1780caa6c2cea491dd05b5e345f4e17d8"
        );
#else
#error sha224/sha256 are mandatory in every build
#endif // MBEDTLS_SHA256_C

#if defined(MBEDTLS_SHA512_C)
    t.run(hash_t::sha384, 48,
        "d3b5710e17da84216f1bf08079bbbbf45303baefc6ecd677910a1c33c86cb1642"
        "81f0f2dcab55bbadc5e8606bdbc16b6",
        "c79079bdff18bab9d22cd7ef84a8a347491632e48543b2f6300400a7eb178246b"
        "f117703ad1ca8461d2f042b840edafd"
        );
    t.run(hash_t::sha512, 64,
        "8ba760cac29cb2b2ce66858ead169174057aa1298ccd581514e6db6dee3285280"
        "ee6e3a54c9319071dc8165ff061d77783100d449c937ff1fb4cd1bb516a69b9",
        "ad723f73a26e1002bc5b226457f88235a26226a4f5c755d048560f22bbd17b5d5"
        "a13920fff6d41ffecb5f6babcf29125bbed8e5caf0da7ff2d3f34f08715aba7"
        );
#else
#error sha384/sha512 are mandatory in every build
#endif // MBEDTLS_SHA512_C

#if defined(MBEDTLS_RIPEMD160_C)
    t.run(hash_t::ripemd160, 20,
        "c4e3cc08809d907e233a24c10056c9951a67ffe2",
        "d8a3cd3129090b0fff57f6ade2a33e2d67c4c0a2");
#else
    t.fail(hash_t::ripemd160);
#endif // MBEDTLS_RIPEMD160_C

    t.fail(hash_t::unknown);
}

TEST_CASE("pbkdf2-hmac tests", "[hash]") {
    std::vector<uint8_t> salt;
    auto ec = from_hex(auto_size_t{salt}, "aaef2d3f4d77ac66e9c5a6c3d8f921d1");
    REQUIRE_FALSE(ec);

    uint8_t buff[32] = {0};
    bin_edit_t out{buff, 32};
    ec = make_hmac_pbkdf2(out, hash_t::sha256, "p@$Sw0rD~1", salt, 50000);
    REQUIRE_FALSE(ec);

    std::string hexed;
    ec = to_hex(auto_size_t{hexed}, out);
    REQUIRE_FALSE(ec);
    REQUIRE(hexed == "52c5efa16e7022859051b1dec28bc65d9696a3005d0f97e506c42843bc3bdbc0");

    // by empty salt: not recommended
    ec = make_hmac_pbkdf2(out, hash_t::sha512, "a bad pass", bin_view_t{}, 32);
    REQUIRE_FALSE(ec);
    ec = to_hex(auto_size_t{hexed}, out);
    REQUIRE_FALSE(ec);
    REQUIRE(hexed == "e04edf3b8fd8efd5eea249c57fead6a939ee55c858e87f45f5a1aaec7b7a1c8e");

    // bad inputs
    {
        bin_edit_t empty;
        ec = make_hmac_pbkdf2(empty, hash_t::sha256, "some pass", bin_view_t{}, 32);
        REQUIRE(ec == make_error_code(mcerr_t::bad_input)); // empty output

        ec = make_hmac_pbkdf2(out, hash_t::unknown, "some pass", bin_view_t{}, 32);
        REQUIRE(ec == make_error_code(mcerr_t::bad_input)); // bad hash

        ec = make_hmac_pbkdf2(out, hash_t::sha256, bin_view_t{}, bin_view_t{}, 32);
        REQUIRE(ec == make_error_code(mcerr_t::bad_input)); // empty password

        ec = make_hmac_pbkdf2(out, hash_t::sha256, "some pass", bin_view_t{}, 0);
        REQUIRE(ec == make_error_code(mcerr_t::bad_input)); // bad iterations
    }
}

