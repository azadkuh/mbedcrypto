#include <catch2/catch.hpp>

#include "./helper.hpp"
#include "mbedcrypto/cipher.hpp"
#include "mbedcrypto/text_codec.hpp"
#include "src/conversions.hpp"

#include <fstream>
//-----------------------------------------------------------------------------
namespace {
using namespace mbedcrypto;
//-----------------------------------------------------------------------------

struct cipher_properties {
    cipher_t  type;
    size_t    block_size;
    size_t    iv_size;
    size_t    key_bits;
    cipher_bm bmode;
};

const cipher_properties Props[] = {
    // id                       block  iv key    block mode
    {cipher_t::null,                0,  0,  0,   cipher_bm::unknown},
    {cipher_t::aes_128_ecb,         16, 0,  128, cipher_bm::ecb},
    {cipher_t::aes_192_ecb,         16, 0,  192, cipher_bm::ecb},
    {cipher_t::aes_256_ecb,         16, 0,  256, cipher_bm::ecb},
    {cipher_t::aes_128_cbc,         16, 16, 128, cipher_bm::cbc},
    {cipher_t::aes_192_cbc,         16, 16, 192, cipher_bm::cbc},
    {cipher_t::aes_256_cbc,         16, 16, 256, cipher_bm::cbc},
    {cipher_t::aes_128_cfb128,      16, 16, 128, cipher_bm::cfb},
    {cipher_t::aes_192_cfb128,      16, 16, 192, cipher_bm::cfb},
    {cipher_t::aes_256_cfb128,      16, 16, 256, cipher_bm::cfb},
    {cipher_t::aes_128_ctr,         16, 16, 128, cipher_bm::ctr},
    {cipher_t::aes_192_ctr,         16, 16, 192, cipher_bm::ctr},
    {cipher_t::aes_256_ctr,         16, 16, 256, cipher_bm::ctr},
    {cipher_t::aes_128_gcm,         16, 12, 128, cipher_bm::gcm},
    {cipher_t::aes_192_gcm,         16, 12, 192, cipher_bm::gcm},
    {cipher_t::aes_256_gcm,         16, 12, 256, cipher_bm::gcm},
    {cipher_t::camellia_128_ecb,    16, 16, 128, cipher_bm::ecb},
    {cipher_t::camellia_192_ecb,    16, 16, 192, cipher_bm::ecb},
    {cipher_t::camellia_256_ecb,    16, 16, 256, cipher_bm::ecb},
    {cipher_t::camellia_128_cbc,    16, 16, 128, cipher_bm::cbc},
    {cipher_t::camellia_192_cbc,    16, 16, 192, cipher_bm::cbc},
    {cipher_t::camellia_256_cbc,    16, 16, 256, cipher_bm::cbc},
    {cipher_t::camellia_128_cfb128, 16, 16, 128, cipher_bm::cfb},
    {cipher_t::camellia_192_cfb128, 16, 16, 192, cipher_bm::cfb},
    {cipher_t::camellia_256_cfb128, 16, 16, 256, cipher_bm::cfb},
    {cipher_t::camellia_128_ctr,    16, 16, 128, cipher_bm::ctr},
    {cipher_t::camellia_192_ctr,    16, 16, 192, cipher_bm::ctr},
    {cipher_t::camellia_256_ctr,    16, 16, 256, cipher_bm::ctr},
    {cipher_t::camellia_128_gcm,    16, 12, 128, cipher_bm::gcm},
    {cipher_t::camellia_192_gcm,    16, 12, 192, cipher_bm::gcm},
    {cipher_t::camellia_256_gcm,    16, 12, 256, cipher_bm::gcm},
    {cipher_t::des_ecb,             8,  8,  64,  cipher_bm::ecb},
    {cipher_t::des_cbc,             8,  8,  64,  cipher_bm::cbc},
    {cipher_t::des_ede_ecb,         8,  8,  128, cipher_bm::ecb},
    {cipher_t::des_ede_cbc,         8,  8,  128, cipher_bm::cbc},
    {cipher_t::des_ede3_ecb,        8,  8,  192, cipher_bm::ecb},
    {cipher_t::des_ede3_cbc,        8,  8,  192, cipher_bm::cbc},
    {cipher_t::blowfish_ecb,        8,  8,  128, cipher_bm::ecb},
    {cipher_t::blowfish_cbc,        8,  8,  128, cipher_bm::cbc},
    {cipher_t::blowfish_cfb64,      8,  8,  128, cipher_bm::cfb},
    {cipher_t::blowfish_ctr,        8,  8,  128, cipher_bm::ctr},
    {cipher_t::arc4_128,            1,  0,  128, cipher_bm::stream},
    {cipher_t::aes_128_ccm,         16, 12, 128, cipher_bm::ccm},
    {cipher_t::aes_192_ccm,         16, 12, 192, cipher_bm::ccm},
    {cipher_t::aes_256_ccm,         16, 12, 256, cipher_bm::ccm},
    {cipher_t::camellia_128_ccm,    16, 12, 128, cipher_bm::ccm},
    {cipher_t::camellia_192_ccm,    16, 12, 192, cipher_bm::ccm},
    {cipher_t::camellia_256_ccm,    16, 12, 256, cipher_bm::ccm},
    {cipher_t::aria_128_ecb,        16, 16, 128, cipher_bm::ecb},
    {cipher_t::aria_192_ecb,        16, 16, 192, cipher_bm::ecb},
    {cipher_t::aria_256_ecb,        16, 16, 256, cipher_bm::ecb},
    {cipher_t::aria_128_cbc,        16, 16, 128, cipher_bm::cbc},
    {cipher_t::aria_192_cbc,        16, 16, 192, cipher_bm::cbc},
    {cipher_t::aria_256_cbc,        16, 16, 256, cipher_bm::cbc},
    {cipher_t::aria_128_cfb128,     16, 16, 128, cipher_bm::cfb},
    {cipher_t::aria_192_cfb128,     16, 16, 192, cipher_bm::cfb},
    {cipher_t::aria_256_cfb128,     16, 16, 256, cipher_bm::cfb},
    {cipher_t::aria_128_ctr,        16, 16, 128, cipher_bm::ctr},
    {cipher_t::aria_192_ctr,        16, 16, 192, cipher_bm::ctr},
    {cipher_t::aria_256_ctr,        16, 16, 256, cipher_bm::ctr},
    {cipher_t::aria_128_gcm,        16, 12, 128, cipher_bm::gcm},
    {cipher_t::aria_192_gcm,        16, 12, 192, cipher_bm::gcm},
    {cipher_t::aria_256_gcm,        16, 12, 256, cipher_bm::gcm},
    {cipher_t::aria_128_ccm,        16, 12, 128, cipher_bm::ccm},
    {cipher_t::aria_192_ccm,        16, 12, 192, cipher_bm::ccm},
    {cipher_t::aria_256_ccm,        16, 12, 256, cipher_bm::ccm},
    {cipher_t::aes_128_ofb,         16, 16, 128, cipher_bm::ofb},
    {cipher_t::aes_192_ofb,         16, 16, 192, cipher_bm::ofb},
    {cipher_t::aes_256_ofb,         16, 16, 256, cipher_bm::ofb},
    {cipher_t::aes_128_xts,         16, 16, 256, cipher_bm::xts},
    {cipher_t::aes_256_xts,         16, 16, 512, cipher_bm::xts},
    {cipher_t::chacha20,            1,  12, 256, cipher_bm::stream},
    {cipher_t::chacha20_poly1305,   1,  12, 256, cipher_bm::chachapoly},
};

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

TEST_CASE("cipher properties", "[cipher]") {
    for (const auto& p : Props) {
        const auto bsize = block_size(p.type);
        const auto isize = iv_size(p.type);
        const auto kbits = key_bitlen(p.type);
        const auto bmode = block_mode(p.type);
        if (supports(p.type)) {
            REQUIRE(bsize == p.block_size);
            REQUIRE(isize == p.iv_size);
            REQUIRE(kbits == p.key_bits);
            REQUIRE(bmode == p.bmode);
        } else {
            REQUIRE(bsize == 0);
            REQUIRE(isize == 0);
            REQUIRE(kbits == 0);
            REQUIRE(bmode == cipher_bm::unknown);
        }
    }
}

