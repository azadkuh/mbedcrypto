#include <catch2/catch.hpp>

#include "src/conversions.hpp"

#include <initializer_list>
#include <iostream>
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

std::ostream&
operator<<(std::ostream& s, features f) {
    if (supports(f))
        s << "supports";
    else
        s << "does not support";

    return s;
}

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

TEST_CASE("mbedcrypto types checkings", "[types]") {
    SECTION("list installed algorithms") {
        auto hashes = installed_hashes();
        REQUIRE(hashes.size() > 0);
        std::cout << "\nsupports " << hashes.size() << " hash algorithms: ";
        for (auto h : hashes) {
            std::cout << to_string(h) << " , ";
        }

        auto paddings = installed_paddings();
        REQUIRE(paddings.size() > 0);
        std::cout << "\nsupports " << paddings.size()
                  << " padding algorithms: ";
        for (auto p : paddings) {
            std::cout << to_string(p) << " , ";
        }

        auto block_modes = installed_block_modes();
        REQUIRE(block_modes.size() > 0);
        std::cout << "\nsupports " << block_modes.size() << " block modes: ";
        for (auto bm : block_modes) {
            std::cout << to_string(bm) << " , ";
        }

        auto ciphers = installed_ciphers();
        REQUIRE(ciphers.size() > 0);
        std::cout << "\nsupports " << ciphers.size() << " cipher algorithms: ";
        for (auto c : ciphers) {
            std::cout << to_string(c) << " , ";
        }
        std::cout << "\n this system " << features::aes_ni
                  << " AESNI (hardware accelerated AES)";
        std::cout << "\n this build " << features::aead
                  << " AEAD (authenticated encryption with additional data)";

        auto pks = installed_pks();
        std::cout << "\nsupports " << pks.size()
                  << " pk (public key) algorithms: ";
        for (auto p : pks) {
            std::cout << to_string(p) << " , ";
        }
        std::cout << "\n this build " << features::pk_export
                  << " PK export (*.pem, *.der) facility";
        std::cout << "\n this build " << features::rsa_keygen
                  << " RSA key generation";
        std::cout << "\n this build " << features::ec_keygen
                  << " EC (elliptic curve) key generation";

        auto curves = installed_curves();
        std::cout << "\nsupports " << curves.size() << " elliptic curves: ";
        for (auto c : curves) {
            std::cout << to_string(c) << " , ";
        }

        std::cout << std::endl;
    }

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
            cipher_bm::ctr,
            cipher_bm::gcm,
            cipher_bm::ccm,
            cipher_bm::stream,
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
            cipher_t::unknown,
        };

        for (auto i : Items) {
            const auto* name = to_string(i);
            REQUIRE(name != nullptr);
            auto v = from_string<cipher_t>(name);
            REQUIRE(v == i);
        }
    }

    SECTION("pk features") {
#if 0 // not implemented yet
        auto check = pk::supports_key_export();
#if defined(MBEDTLS_PEM_WRITE_C)
        REQUIRE(check);
#else  // MBEDTLS_PEM_WRITE_C
        REQUIRE_FALSE(check);
#endif // MBEDTLS_PEM_WRITE_C

        check = supports(features::rsa_keygen);
#if defined(MBEDTLS_GENPRIME)
        REQUIRE(check);
#else
        REQUIRE_FALSE(check);
#endif // MBEDTLS_GENPRIME

        check = supports(features::ec_keygen);
#if defined(MBEDTLS_ECP_C)
        REQUIRE(check);
#else  // MBEDTLS_ECP_C
        REQUIRE_FALSE(check);
#endif // MBEDTLS_ECP_C
#endif
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
            curve_t::unknown,
        };

        for (auto i : Items) {
            const auto* name = to_string(i);
            REQUIRE(name != nullptr);
            auto v = from_string<curve_t>(name);
            REQUIRE(v == i);
        }
    }
}
