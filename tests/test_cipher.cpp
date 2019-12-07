#include <catch2/catch.hpp>

#include "./helper.hpp"
#include "mbedcrypto/cipher.hpp"
#include "mbedcrypto/text_codec.hpp"
#include "../src/private/conversions.hpp"

#include <array>

#define VERBOSE_CIPHER 0
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

auto
padding_of(cipher_bm bm) noexcept {
    return bm != cipher_bm::cbc ? padding_t::none : padding_t::pkcs7;
}

bin_view_t
make_source(bin_view_t in, const cipher_properties& p) noexcept {
    auto copy{in};
    if (p.bmode == cipher_bm::ecb)
        copy.size -= (in.size % p.block_size); // must be N % block_size
    return copy;
}

//-----------------------------------------------------------------------------

struct streamer {
    auto result() const noexcept { return bin_view_t{buffer}; }

    void encrypt(bin_view_t source, const cipher::info_t& ci) {
        auto ec = s.start_encrypt(ci);
        REQUIRE_FALSE(ec);
        prepare(source.size, ci.type);
        run(source);
    }

    void decrypt(bin_view_t source, const cipher::info_t& ci) {
        auto ec = s.start_decrypt(ci);
        REQUIRE_FALSE(ec);
        prepare(source.size, ci.type);
        run(source);
    }

protected:
    size_t                  chunk_size = 0;
    cipher::stream          s;
    std::vector<uint8_t>    buffer;
    std::array<uint8_t, 64> temp; // for intermediate crypt

    void prepare(size_t input_size, cipher_t type) {
        buffer.resize(input_size + 64); // initial guess
        const auto bm = mbedcrypto::block_mode(type);
        if (bm == cipher_bm::ecb)
            chunk_size = mbedcrypto::block_size(type);
        else if (bm == cipher_bm::gcm)
            chunk_size = 3 * mbedcrypto::block_size(type); // N * block_size
        else
            chunk_size = 42; // custom input size fittable into temp
    }

    void run(bin_view_t source) {
        auto* pbuf = &buffer[0];
        test::chunker(source, chunk_size, [&](const auto* ptr, size_t len) {
            bin_edit_t out{temp};
            auto ec = s.update(out, bin_view_t{ptr, len});
            if (ec)
                std::printf("\nupdate %zu error(%0x): %s\n",
                        len, -ec.value(), ec.message().data());
            REQUIRE_FALSE(ec);
            std::memcpy(pbuf, out.data, out.size);
            pbuf += out.size;
        });

        bin_edit_t out{temp};
        auto ec = s.finish(out);
        REQUIRE_FALSE(ec);
        if (out.size > 0) {
            std::memcpy(pbuf, out.data, out.size);
            pbuf += out.size;
        }

        size_t processed = (pbuf - &buffer[0]);
        buffer.resize(processed);
    }
};

//-----------------------------------------------------------------------------

struct tester {
    explicit tester(const cipher_properties& p) noexcept : prop{p} {}

    void run() const {
        check_props();
        cypt();
        auth_crypt();
    }

protected:
    cipher_properties prop;

    void check_props() const {
        const auto bsize = block_size(prop.type);
        const auto isize = iv_size(prop.type);
        const auto kbits = key_bitlen(prop.type);
        const auto bmode = block_mode(prop.type);
        REQUIRE(bsize == prop.block_size);
        REQUIRE(isize == prop.iv_size);
        REQUIRE(kbits == prop.key_bits);
        REQUIRE(bmode == prop.bmode);
        cipher::info_t ci;
        ci.type = prop.type;
        ci.key  = test::long_binary();
        ci.iv   = test::long_binary();
        REQUIRE_FALSE(is_valid(ci)); // bad key/iv size
        ci.key.size = kbits >> 3; // in bytes
        ci.iv.size  = isize;      // in bytes
        REQUIRE(is_valid(ci));
    }

    void cypt() const {
        if (prop.bmode == cipher_bm::ccm) // CCM is only for AEAD
            return;
#if VERBOSE_CIPHER > 0
        std::printf("%-20s", to_string(prop.type));
#endif
        cipher::info_t ci;
        prepare(ci);
        if (prop.bmode == cipher_bm::chachapoly) {
            ci.ad = bin_view_t("some additional data is required");
        }

        const auto source = make_source(test::long_text(), prop);

        std::vector<uint8_t> enc;
        auto ec = cipher::encrypt(obuffer_t{enc}, source, ci);
        if (ec)
            std::printf("\ncrypt error(%0x): %s\n", -ec.value(), ec.message().data());
        REQUIRE_FALSE(ec);
        REQUIRE(enc.size() >= source.size);

        std::string dec;
        ec = cipher::decrypt(obuffer_t{dec}, enc, ci);
        REQUIRE_FALSE(ec);

#if VERBOSE_CIPHER > 0
        std::printf(" done. sizeof in:%3zu enc:%3zu dec:%3zu\n",
            source.size, enc.size(), dec.size());
#endif
        REQUIRE(dec == source);

        // streamin-api
        if (prop.bmode == cipher_bm::xts)
            return; // does not support
        streamer stm;
        stm.encrypt(source, ci);
        if (false) {
            test::write_to_file("output.enc", enc);
            test::write_to_file("output.stm", stm.result());
        }
        REQUIRE(stm.result() == enc);

        stm.decrypt(enc, ci);
        REQUIRE(stm.result() == source);
    }

    void auth_crypt() const {
        switch (prop.bmode) {
            case cipher_bm::ccm:
            case cipher_bm::gcm:
            case cipher_bm::chachapoly:
                break;
            default: return; // this block-mode does not support AEAD
        }

#if VERBOSE_CIPHER > 0
        std::printf("%-20s", to_string(prop.type));
#endif
        cipher::info_t ci;
        prepare(ci);
        ci.ad = bin_view_t("some additional data is required");

        const auto source = make_source(test::long_text(), prop);

        std::vector<uint8_t> enc;
        std::vector<uint8_t> tag;
        auto ec = cipher::auth_encrypt(obuffer_t{enc}, obuffer_t{tag}, source, ci);
        if (ec)
            std::printf("\nauth-crypt error(%0x): %s\n", -ec.value(), ec.message().data());
        REQUIRE_FALSE(ec);
        REQUIRE(enc.size() >= source.size);
        REQUIRE(tag.size() >= 16);

        std::string dec;
        ec = cipher::auth_decrypt(obuffer_t{dec}, tag, enc, ci);
        REQUIRE_FALSE(ec);
        REQUIRE(dec.size() == source.size);

#if VERBOSE_CIPHER > 0
        std::printf(" done. sizeof in:%3zu enc:%3zu dec:%3zu tag:%2zu (AEAD)\n",
            source.size, enc.size(), dec.size(), tag.size());
#endif
        REQUIRE(dec == source);
    }

private:
    void prepare(cipher::info_t& ci) const noexcept {
        ci.type    = prop.type;
        ci.padding = padding_of(prop.bmode);
        ci.key     = test::short_binary();
        ci.iv      = test::short_text();
        REQUIRE(ci.iv.size > prop.iv_size);
        // adjust to exact size
        ci.iv.size  = prop.iv_size;
        ci.key.size = prop.key_bits >> 3; // to byte
    }
};

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

TEST_CASE("cipher properties", "[cipher]") {
    SECTION("empty ciphers") {
        cipher::info_t ci;
        REQUIRE_FALSE(is_valid(ci));
        REQUIRE(block_size(ci.type) == 0);
        REQUIRE(iv_size(ci.type)    == 0);
        REQUIRE(key_bitlen(ci.type) == 0);
        REQUIRE(block_mode(ci.type) == cipher_bm::unknown);
    }

    SECTION("all supported ciphers") {
        for (const auto& p : Props) {
            if (supports(p.type)) {
                tester{p}.run();
            } else {
                REQUIRE(block_size(p.type) == 0);
                REQUIRE(iv_size(p.type)    == 0);
                REQUIRE(key_bitlen(p.type) == 0);
                REQUIRE(block_mode(p.type) == cipher_bm::unknown);
            }
        }
    }
}

