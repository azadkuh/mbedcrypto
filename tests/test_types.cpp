#include <catch2/catch.hpp>

#include "../src/private/conversions.hpp"

#include <initializer_list>
#include <cstdio>
//-----------------------------------------------------------------------------
namespace {
//-----------------------------------------------------------------------------
using namespace mbedcrypto;

void
hasHash(hash_t h) {
    INFO("hash(" << to_string(h) << ")");
    REQUIRE(supports(h));
    const char* name = to_string(h);
    INFO("hash(" << to_string(h) << "): " << name);
    REQUIRE(supports_hash(name));
    auto v = from_string<hash_t>(name);
    REQUIRE(v == h);
}

template<typename List>
void
dump(const List& list) noexcept {
    const auto size = list.size();
    for (size_t i = 0; i < size; ++i) {
        std::printf("%s%s", to_string(list[i]), i == (size-1) ? "" : ", ");
    }
}

void
dump_algorithms(const char* tag, size_t curr, size_t all) noexcept {
    std::printf("\n  %-12s (%zu of %zu): ", tag, curr, all);
}

void
dump_feature(features f, const char* tag, const char* desc) noexcept {
    std::printf("  %-10s: %-4s (%s)\n", tag, supports(f) ? "yes" : "no", desc);
}

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

TEST_CASE("mbedcrypto size of types", "[types]") {
    // change in enum sizes should break these numbers
    REQUIRE(9  == all_hashes().size());
    REQUIRE(5  == all_paddings().size());
    REQUIRE(10 == all_block_modes().size());
    REQUIRE(73 == all_ciphers().size());
    REQUIRE(6  == all_pks().size());
    REQUIRE(13 == all_curves().size());
}

TEST_CASE("list supported algorithms", "[types]") {
    std::printf("this build supports:\nalgorithms:");
    {
        auto list = supported_hashes();
        REQUIRE(list.size() > 0);
        dump_algorithms("hashes", list.size(), all_hashes().size());
        dump(list);
    }
    {
        auto list = supported_paddings();
        REQUIRE(list.size() > 0);
        dump_algorithms("paddings", list.size(), all_paddings().size());
        dump(list);
    }
    {
        auto list = supported_block_modes();
        REQUIRE(list.size() > 0);
        dump_algorithms("block modes", list.size(), all_block_modes().size());
        dump(list);
    }
    {
        auto list = supported_ciphers();
        REQUIRE(list.size() > 0);
        dump_algorithms("ciphers", list.size(), all_ciphers().size());
        dump(list);
    }
    {
        auto list = supported_pks();
        REQUIRE(list.size() > 0);
        dump_algorithms("PKs", list.size(), all_pks().size());
        dump(list);
    }
    {
        auto list = supported_curves(); // may be empty
        dump_algorithms("EC curves", list.size(), all_curves().size());
        dump(list);
    }
    std::printf("\nfeatures:\n");
    dump_feature(features::aes_ni,    "aes-ni",    "hardware accelarated aes");
    dump_feature(features::aead,      "aead",      "authenticated encryption by additional data");
    dump_feature(features::pk_keygen, "pk-keygen", "private/public key generator");
    dump_feature(features::pk_ec,     "pk-ec",     "elliptic curve algorithms");
}

TEST_CASE("mbedcrypto types checkings", "[types]") {
    SECTION("hashes") {
        const std::initializer_list<hash_t> Items = {
            hash_t::md2,
            hash_t::md4,
            hash_t::md5,
            hash_t::sha1,
            hash_t::sha224,
            hash_t::sha256,
            hash_t::sha384,
            hash_t::sha512,
            hash_t::ripemd160,
            hash_t::unknown,
        };

        for (auto i : Items) {
            const char* name = to_string(i);
            REQUIRE(name != nullptr);
            auto v = from_string<hash_t>(name);
            INFO("hash(" << to_string(v) << "): " << name);
            REQUIRE(v == i);
        }

        REQUIRE_FALSE(supports(hash_t::unknown));

#if defined(MBEDTLS_MD2_C)
        hasHash(hash_t::md2);
#else
        REQUIRE_FALSE(supports(hash_t::md2));
#endif
#if defined(MBEDTLS_MD4_C)
        hasHash(hash_t::md4);
#else
        REQUIRE_FALSE(supports(hash_t::md4));
#endif
#if defined(MBEDTLS_MD5_C)
        hasHash(hash_t::md5);
#else
        REQUIRE_FALSE(supports(hash_t::md5));
#endif
#if defined(MBEDTLS_SHA1_C)
        hasHash(hash_t::sha1);
#else
        REQUIRE_FALSE(supports(hash_t::sha1));
#endif
#if defined(MBEDTLS_SHA256_C)
        hasHash(hash_t::sha224);
        hasHash(hash_t::sha256);
#else
        REQUIRE_FALSE(supports(hash_t::sha224));
        REQUIRE_FALSE(supports(hash_t::sha256));
#endif
#if defined(MBEDTLS_SHA512_C)
        hasHash(hash_t::sha384);
        hasHash(hash_t::sha512);
#else
        REQUIRE_FALSE(supports(hash_t::sha384));
        REQUIRE_FALSE(supports(hash_t::sha512));
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        hasHash(hash_t::ripemd160);
#else
        REQUIRE_FALSE(supports(hash_t::ripemd160));
#endif
    }

    SECTION("paddings") {
        const std::initializer_list<padding_t> Items = {
            padding_t::none,
            padding_t::pkcs7,
            padding_t::one_and_zeros,
            padding_t::zeros_and_len,
            padding_t::zeros,
            padding_t::unknown,
        };

        for (auto i : Items) {
            const char* name = to_string(i);
            REQUIRE(name != nullptr);
            auto v = from_string<padding_t>(name);
            REQUIRE(v == i);
        }
    }

    SECTION("block modes") {
        const std::initializer_list<cipher_bm> Items = {
            cipher_bm::ecb,
            cipher_bm::cbc,
            cipher_bm::cfb,
            cipher_bm::ofb,
            cipher_bm::ctr,
            cipher_bm::gcm,
            cipher_bm::ccm,
            cipher_bm::xts,
            cipher_bm::stream,
            cipher_bm::chachapoly,
            cipher_bm::unknown,
        };

        for (auto i : Items) {
            const char* name = to_string(i);
            REQUIRE(name != nullptr);
            auto v = from_string<cipher_bm>(name);
            REQUIRE(v == i);
        }
    }

    SECTION("ciphers") {
        const std::initializer_list<cipher_t> Items = {
            cipher_t::null,
            cipher_t::aes_128_ecb,
            cipher_t::aes_192_ecb,
            cipher_t::aes_256_ecb,
            cipher_t::aes_128_cbc,
            cipher_t::aes_192_cbc,
            cipher_t::aes_256_cbc,
            cipher_t::aes_128_cfb128,
            cipher_t::aes_192_cfb128,
            cipher_t::aes_256_cfb128,
            cipher_t::aes_128_ctr,
            cipher_t::aes_192_ctr,
            cipher_t::aes_256_ctr,
            cipher_t::aes_128_gcm,
            cipher_t::aes_192_gcm,
            cipher_t::aes_256_gcm,
            cipher_t::camellia_128_ecb,
            cipher_t::camellia_192_ecb,
            cipher_t::camellia_256_ecb,
            cipher_t::camellia_128_cbc,
            cipher_t::camellia_192_cbc,
            cipher_t::camellia_256_cbc,
            cipher_t::camellia_128_cfb128,
            cipher_t::camellia_192_cfb128,
            cipher_t::camellia_256_cfb128,
            cipher_t::camellia_128_ctr,
            cipher_t::camellia_192_ctr,
            cipher_t::camellia_256_ctr,
            cipher_t::camellia_128_gcm,
            cipher_t::camellia_192_gcm,
            cipher_t::camellia_256_gcm,
            cipher_t::des_ecb,
            cipher_t::des_cbc,
            cipher_t::des_ede_ecb,
            cipher_t::des_ede_cbc,
            cipher_t::des_ede3_ecb,
            cipher_t::des_ede3_cbc,
            cipher_t::blowfish_ecb,
            cipher_t::blowfish_cbc,
            cipher_t::blowfish_cfb64,
            cipher_t::blowfish_ctr,
            cipher_t::arc4_128,
            cipher_t::aes_128_ccm,
            cipher_t::aes_192_ccm,
            cipher_t::aes_256_ccm,
            cipher_t::camellia_128_ccm,
            cipher_t::camellia_192_ccm,
            cipher_t::camellia_256_ccm,
            cipher_t::aria_128_ecb,
            cipher_t::aria_192_ecb,
            cipher_t::aria_256_ecb,
            cipher_t::aria_128_cbc,
            cipher_t::aria_192_cbc,
            cipher_t::aria_256_cbc,
            cipher_t::aria_128_cfb128,
            cipher_t::aria_192_cfb128,
            cipher_t::aria_256_cfb128,
            cipher_t::aria_128_ctr,
            cipher_t::aria_192_ctr,
            cipher_t::aria_256_ctr,
            cipher_t::aria_128_gcm,
            cipher_t::aria_192_gcm,
            cipher_t::aria_256_gcm,
            cipher_t::aria_128_ccm,
            cipher_t::aria_192_ccm,
            cipher_t::aria_256_ccm,
            cipher_t::aes_128_ofb,
            cipher_t::aes_192_ofb,
            cipher_t::aes_256_ofb,
            cipher_t::aes_128_xts,
            cipher_t::aes_256_xts,
            cipher_t::chacha20,
            cipher_t::chacha20_poly1305,
            cipher_t::unknown,
        };

        for (auto i : Items) {
            const auto* name = to_string(i);
            REQUIRE(name != nullptr);
            auto v = from_string<cipher_t>(name);
            REQUIRE(v == i);
        }
    }

    SECTION("curve names") {
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
            curve_t::curve25519,
            curve_t::curve448,
            curve_t::unknown,
        };

        for (auto i : Items) {
            const auto* name = to_string(i);
            REQUIRE(name != nullptr);
            auto v = from_string<curve_t>(name);
            REQUIRE(v == i);
        }
    }

    SECTION("pk features") {
        auto check = supports(features::pk_keygen);
        REQUIRE(check == supports_rsa_keygen());
#if defined(MBEDTLS_GENPRIME)
        REQUIRE(check);
#else
        REQUIRE_FALSE(check);
#endif

        check = supports(features::pk_ec);
#if defined(MBEDTLS_ECP_C)
        REQUIRE(check);
#else
        REQUIRE_FALSE(check);
#endif

        check = supports(features::pk_ec) && supports(features::pk_keygen);
        REQUIRE(check == supports_ec_keygen());
#if defined(MBEDTLS_ECP_C) && defined(MBEDTLS_GENPRIME)
        REQUIRE(check);
#else
        REQUIRE_FALSE(check);
#endif
    }
}
