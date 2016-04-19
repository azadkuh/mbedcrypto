#include <catch.hpp>
#include <iostream>
#include <initializer_list>

#include "mbedcrypto_mbedtls_config.h"
#include "mbedcrypto/cipher.hpp"
#include "generator.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace {
using cchars = const char*;
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////
auto hasHash = [](hash_t h) {
    REQUIRE( supports(h) );
    cchars name = to_string(h);

    REQUIRE( supports_hash(name) );
    auto v = from_string<hash_t>(name);
    REQUIRE( v == h );
};

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("mbedcrypto types checkings", "[types]") {
    using namespace mbedcrypto;

    SECTION("list installed algorithms") {
        auto hashes = installed_hashes();
        REQUIRE( hashes.size() > 0 );
        std::cout << "\nsupports " << hashes.size() << " hash algorithms: ";
        for ( auto h : hashes ) {
            std::cout << to_string(h) << " , ";
        }

        auto paddings = installed_paddings();
        REQUIRE( paddings.size() > 0 );
        std::cout << "\nsupports " << paddings.size() << " padding algorithms: ";
        for ( auto p : paddings ) {
            std::cout << to_string(p) << " , ";
        }

        auto block_modes = installed_block_modes();
        REQUIRE( block_modes.size() > 0 );
        std::cout << "\nsupports " << block_modes.size() << " block modes: ";
        for ( auto bm : block_modes ) {
            std::cout << to_string(bm) << " , ";
        }

        auto ciphers = installed_ciphers();
        REQUIRE( ciphers.size() > 0 );
        std::cout << "\nsupports " << ciphers.size() << " cipher algorithms: ";
        for ( auto c : ciphers ) {
            std::cout << to_string(c) << " , ";
        }
        std::cout << "\nthis system "
            << (cipher::supports_aes_ni() ? "supports" : "does not support")
            << " AESNI (hardware accelerated AES)";
        std::cout << "\nthis system "
            << (cipher::supports_aead() ? "supports" : "does not support")
            << " AEAD (authenticated encryption with additional data)";

        auto pks = installed_pks();
        std::cout << "\nsupports " << pks.size() << " pk (public key) algorithms: ";
        for ( auto p : pks ) {
            std::cout << to_string(p) << " , ";
        }

        auto curves = installed_curves();
        std::cout << "\nsupports " << curves.size() << " elliptic curves: ";
        for ( auto c : curves ) {
            std::cout << to_string(c) << " , ";
        }

        std::cout << std::endl;
    }

    SECTION("hashes") {
        REQUIRE_FALSE( supports(hash_t::none) );

        #if defined(MBEDTLS_MD2_C)
        hasHash(hash_t::md2);
        #else
        REQUIRE_FALSE( supports(hash_t::md2) );
        #endif

        #if defined(MBEDTLS_MD4_C)
        hasHash(hash_t::md4);
        #else // MBEDTLS_MD4_C
        REQUIRE_FALSE( supports(hash_t::md4) );
        #endif // MBEDTLS_MD4_C

        #if defined(MBEDTLS_MD5_C)
        hasHash(hash_t::md5);
        #else // MBEDTLS_MD5_C
        REQUIRE_FALSE( supports(hash_t::md5) );
        #endif // MBEDTLS_MD5_C

        #if defined(MBEDTLS_SHA1_C)
        hasHash(hash_t::sha1);
        #else // MBEDTLS_SHA1_C
        REQUIRE_FALSE( supports(hash_t::sha1) );
        #endif // MBEDTLS_SHA1_C

        #if defined(MBEDTLS_SHA256_C)
        hasHash(hash_t::sha224);
        hasHash(hash_t::sha256);
        #else // MBEDTLS_SHA256_C
        REQUIRE_FALSE( supports(hash_t::sha224) );
        REQUIRE_FALSE( supports(hash_t::sha256) );
        #endif // MBEDTLS_SHA256_C

        #if defined(MBEDTLS_SHA512_C)
        hasHash(hash_t::sha384);
        hasHash(hash_t::sha512);
        #else // MBEDTLS_SHA512_C
        REQUIRE_FALSE( supports(hash_t::sha384) );
        REQUIRE_FALSE( supports(hash_t::sha512) );
        #endif // MBEDTLS_SHA512_C

        #if defined(MBEDTLS_RIPEMD160_C)
        hasHash(hash_t::ripemd160);
        #else // MBEDTLS_RIPEMD160_C
        REQUIRE_FALSE( supports(hash_t::ripemd160) );
        #endif // MBEDTLS_RIPEMD160_C

        std::cout << std::endl;

    }

    SECTION("ciphers") {
        const std::initializer_list<cipher_t> Items = {
            cipher_t::none,
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
        };

        for ( auto i : Items ) {
            cchars name = to_string(i);
            if ( name == nullptr )
                continue;

            auto v = from_string<cipher_t>(name);
            REQUIRE( v == i );
        }
    }

    SECTION("paddings") {
        const std::initializer_list<padding_t> Items = {
            padding_t::none,
            padding_t::pkcs7,
            padding_t::one_and_zeros,
            padding_t::zeros_and_len,
            padding_t::zeros,
        };

        for ( auto i : Items ) {
            cchars name = to_string(i);
            if ( name == nullptr )
                continue;

            auto v = from_string<padding_t>(name);
            REQUIRE( v == i );
        }
    }

    SECTION("block modes") {
        const std::initializer_list<cipher_bm> Items = {
            cipher_bm::none,
            cipher_bm::ecb,
            cipher_bm::cbc,
            cipher_bm::cfb,
            cipher_bm::ctr,
            cipher_bm::gcm,
            cipher_bm::ccm,
            cipher_bm::stream,
        };

        for ( auto i : Items) {
            cchars name = to_string(i);
            if ( name == nullptr )
                continue;

            auto v = from_string<cipher_bm>(name);
            REQUIRE( v == i );
        }
    }

    SECTION("curve names") {
        const std::initializer_list<curve_t> Items = {
            curve_t::none,
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
        };

        for ( auto i : Items ) {
            cchars name = to_string(i);
            if ( name == nullptr )
                continue;

            auto v = from_string<curve_t>(name);
            REQUIRE( v == i );
        }
    }

}

