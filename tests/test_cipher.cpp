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

struct cipher_feats_t {
    cipher_t         type;
    cipher::traits_t traits;
};

const cipher_feats_t Features[] = {
    // id                          block key iv   block mode           padding  anyin  v_iv   v_key
    {cipher_t::null,                {0,  0,   0,  cipher_bm::unknown,    false, false, false, false}},
    {cipher_t::aes_128_ecb,         {16, 128, 0,  cipher_bm::ecb,        false, false, false, false}},
    {cipher_t::aes_192_ecb,         {16, 192, 0,  cipher_bm::ecb,        false, false, false, false}},
    {cipher_t::aes_256_ecb,         {16, 256, 0,  cipher_bm::ecb,        false, false, false, false}},
    {cipher_t::aes_128_cbc,         {16, 128, 16, cipher_bm::cbc,        true,  true,  false, false}},
    {cipher_t::aes_192_cbc,         {16, 192, 16, cipher_bm::cbc,        true,  true,  false, false}},
    {cipher_t::aes_256_cbc,         {16, 256, 16, cipher_bm::cbc,        true,  true,  false, false}},
    {cipher_t::aes_128_cfb128,      {16, 128, 16, cipher_bm::cfb,        false, true,  false, false}},
    {cipher_t::aes_192_cfb128,      {16, 192, 16, cipher_bm::cfb,        false, true,  false, false}},
    {cipher_t::aes_256_cfb128,      {16, 256, 16, cipher_bm::cfb,        false, true,  false, false}},
    {cipher_t::aes_128_ctr,         {16, 128, 16, cipher_bm::ctr,        false, true,  false, false}},
    {cipher_t::aes_192_ctr,         {16, 192, 16, cipher_bm::ctr,        false, true,  false, false}},
    {cipher_t::aes_256_ctr,         {16, 256, 16, cipher_bm::ctr,        false, true,  false, false}},
    {cipher_t::aes_128_gcm,         {16, 128, 12, cipher_bm::gcm,        false, true,  true,  false}},
    {cipher_t::aes_192_gcm,         {16, 192, 12, cipher_bm::gcm,        false, true,  true,  false}},
    {cipher_t::aes_256_gcm,         {16, 256, 12, cipher_bm::gcm,        false, true,  true,  false}},
    {cipher_t::camellia_128_ecb,    {16, 128, 16, cipher_bm::ecb,        false, false, false, false}},
    {cipher_t::camellia_192_ecb,    {16, 192, 16, cipher_bm::ecb,        false, false, false, false}},
    {cipher_t::camellia_256_ecb,    {16, 256, 16, cipher_bm::ecb,        false, false, false, false}},
    {cipher_t::camellia_128_cbc,    {16, 128, 16, cipher_bm::cbc,        true,  true,  false, false}},
    {cipher_t::camellia_192_cbc,    {16, 192, 16, cipher_bm::cbc,        true,  true,  false, false}},
    {cipher_t::camellia_256_cbc,    {16, 256, 16, cipher_bm::cbc,        true,  true,  false, false}},
    {cipher_t::camellia_128_cfb128, {16, 128, 16, cipher_bm::cfb,        false, true,  false, false}},
    {cipher_t::camellia_192_cfb128, {16, 192, 16, cipher_bm::cfb,        false, true,  false, false}},
    {cipher_t::camellia_256_cfb128, {16, 256, 16, cipher_bm::cfb,        false, true,  false, false}},
    {cipher_t::camellia_128_ctr,    {16, 128, 16, cipher_bm::ctr,        false, true,  false, false}},
    {cipher_t::camellia_192_ctr,    {16, 192, 16, cipher_bm::ctr,        false, true,  false, false}},
    {cipher_t::camellia_256_ctr,    {16, 256, 16, cipher_bm::ctr,        false, true,  false, false}},
    {cipher_t::camellia_128_gcm,    {16, 128, 12, cipher_bm::gcm,        false, true,  true,  false}},
    {cipher_t::camellia_192_gcm,    {16, 192, 12, cipher_bm::gcm,        false, true,  true,  false}},
    {cipher_t::camellia_256_gcm,    {16, 256, 12, cipher_bm::gcm,        false, true,  true,  false}},
    {cipher_t::des_ecb,             {8,  64,  8,  cipher_bm::ecb,        false, false, false, false}},
    {cipher_t::des_cbc,             {8,  64,  8,  cipher_bm::cbc,        true,  true,  false, false}},
    {cipher_t::des_ede_ecb,         {8,  128, 8,  cipher_bm::ecb,        false, false, false, false}},
    {cipher_t::des_ede_cbc,         {8,  128, 8,  cipher_bm::cbc,        true,  true,  false, false}},
    {cipher_t::des_ede3_ecb,        {8,  192, 8,  cipher_bm::ecb,        false, false, false, false}},
    {cipher_t::des_ede3_cbc,        {8,  192, 8,  cipher_bm::cbc,        true,  true,  false, false}},
    {cipher_t::blowfish_ecb,        {8,  128, 8,  cipher_bm::ecb,        false, false, false, true }},
    {cipher_t::blowfish_cbc,        {8,  128, 8,  cipher_bm::cbc,        true,  true,  false, true }},
    {cipher_t::blowfish_cfb64,      {8,  128, 8,  cipher_bm::cfb,        false, true,  false, true }},
    {cipher_t::blowfish_ctr,        {8,  128, 8,  cipher_bm::ctr,        false, true,  false, true }},
    {cipher_t::arc4_128,            {1,  128, 0,  cipher_bm::stream,     false, true,  false, false}},
    {cipher_t::aes_128_ccm,         {16, 128, 12, cipher_bm::ccm,        false, true,  true,  false}},
    {cipher_t::aes_192_ccm,         {16, 192, 12, cipher_bm::ccm,        false, true,  true,  false}},
    {cipher_t::aes_256_ccm,         {16, 256, 12, cipher_bm::ccm,        false, true,  true,  false}},
    {cipher_t::camellia_128_ccm,    {16, 128, 12, cipher_bm::ccm,        false, true,  true,  false}},
    {cipher_t::camellia_192_ccm,    {16, 192, 12, cipher_bm::ccm,        false, true,  true,  false}},
    {cipher_t::camellia_256_ccm,    {16, 256, 12, cipher_bm::ccm,        false, true,  true,  false}},
    {cipher_t::aria_128_ecb,        {16, 128, 16, cipher_bm::ecb,        false, false, false, false}},
    {cipher_t::aria_192_ecb,        {16, 192, 16, cipher_bm::ecb,        false, false, false, false}},
    {cipher_t::aria_256_ecb,        {16, 256, 16, cipher_bm::ecb,        false, false, false, false}},
    {cipher_t::aria_128_cbc,        {16, 128, 16, cipher_bm::cbc,        true,  true,  false, false}},
    {cipher_t::aria_192_cbc,        {16, 192, 16, cipher_bm::cbc,        true,  true,  false, false}},
    {cipher_t::aria_256_cbc,        {16, 256, 16, cipher_bm::cbc,        true,  true,  false, false}},
    {cipher_t::aria_128_cfb128,     {16, 128, 16, cipher_bm::cfb,        false, true,  false, false}},
    {cipher_t::aria_192_cfb128,     {16, 192, 16, cipher_bm::cfb,        false, true,  false, false}},
    {cipher_t::aria_256_cfb128,     {16, 256, 16, cipher_bm::cfb,        false, true,  false, false}},
    {cipher_t::aria_128_ctr,        {16, 128, 16, cipher_bm::ctr,        false, true,  false, false}},
    {cipher_t::aria_192_ctr,        {16, 192, 16, cipher_bm::ctr,        false, true,  false, false}},
    {cipher_t::aria_256_ctr,        {16, 256, 16, cipher_bm::ctr,        false, true,  false, false}},
    {cipher_t::aria_128_gcm,        {16, 128, 12, cipher_bm::gcm,        false, true,  true,  false}},
    {cipher_t::aria_192_gcm,        {16, 192, 12, cipher_bm::gcm,        false, true,  true,  false}},
    {cipher_t::aria_256_gcm,        {16, 256, 12, cipher_bm::gcm,        false, true,  true,  false}},
    {cipher_t::aria_128_ccm,        {16, 128, 12, cipher_bm::ccm,        false, true,  true,  false}},
    {cipher_t::aria_192_ccm,        {16, 192, 12, cipher_bm::ccm,        false, true,  true,  false}},
    {cipher_t::aria_256_ccm,        {16, 256, 12, cipher_bm::ccm,        false, true,  true,  false}},
    {cipher_t::aes_128_ofb,         {16, 128, 16, cipher_bm::ofb,        false, true,  false, false}},
    {cipher_t::aes_192_ofb,         {16, 192, 16, cipher_bm::ofb,        false, true,  false, false}},
    {cipher_t::aes_256_ofb,         {16, 256, 16, cipher_bm::ofb,        false, true,  false, false}},
    {cipher_t::aes_128_xts,         {16, 256, 16, cipher_bm::xts,        false, true,  false, false}},
    {cipher_t::aes_256_xts,         {16, 512, 16, cipher_bm::xts,        false, true,  false, false}},
    {cipher_t::chacha20,            {1,  256, 12, cipher_bm::stream,     false, true,  false, false}},
    {cipher_t::chacha20_poly1305,   {1,  256, 12, cipher_bm::chachapoly, false, true,  false, false}},
};

auto
padding_of(cipher_bm bm) noexcept {
    return bm != cipher_bm::cbc ? padding_t::none : padding_t::pkcs7;
}

bin_view_t
make_source(bin_view_t in, const cipher::traits_t& tr) noexcept {
    auto copy{in};
    if (tr.block_mode == cipher_bm::ecb)
        copy.size -= (in.size % tr.block_size); // must be N % block_size
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
        const auto tr = cipher::traits(type);
        if (tr.block_mode == cipher_bm::ecb)
            chunk_size = tr.block_size;
        else if (tr.block_mode == cipher_bm::gcm)
            chunk_size = 3 * tr.block_size; // N * block_size
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
    explicit tester(const cipher_feats_t& f) noexcept : feats{f} {}

    void run() const {
        check_props();
        crypt();
        auth_crypt();
    }

protected:
    cipher_feats_t feats;

    void check_props() const {
        const auto tr = cipher::traits(feats.type);
        REQUIRE(tr.block_size               == feats.traits.block_size);
        REQUIRE(tr.key_bitlen               == feats.traits.key_bitlen);
        REQUIRE(tr.iv_size                  == feats.traits.iv_size);
        REQUIRE(tr.block_mode               == feats.traits.block_mode);
        REQUIRE(tr.requires_padding         == feats.traits.requires_padding);
        REQUIRE(tr.accept_any_input_size    == feats.traits.accept_any_input_size);
        REQUIRE(tr.accept_variable_key_size == feats.traits.accept_variable_key_size);
        REQUIRE(tr.accept_variable_iv_size  == feats.traits.accept_variable_iv_size);
        cipher::info_t ci;
        ci.type = feats.type;
        ci.key  = test::long_binary();
        ci.iv   = test::long_binary();
        REQUIRE_FALSE(is_valid(ci)); // bad key/iv size
        ci.key.size = tr.key_bitlen >> 3; // in bytes
        ci.iv.size  = tr.iv_size;      // in bytes
        REQUIRE(is_valid(ci));
    }

    void crypt() const {
        if (feats.traits.block_mode == cipher_bm::ccm) // CCM is only for AEAD
            return;
#if VERBOSE_CIPHER > 0
        std::printf("%-20s", to_string(prop.type));
#endif
        cipher::info_t ci;
        prepare(ci);
        if (feats.traits.block_mode == cipher_bm::chachapoly) {
            ci.ad = bin_view_t("some additional data is required");
        }

        const auto source = make_source(test::long_text(), feats.traits);

        std::vector<uint8_t> enc;
        auto ec = cipher::encrypt(auto_size_t{enc}, source, ci);
        if (ec)
            std::printf("\ncrypt error(%0x): %s\n", -ec.value(), ec.message().data());
        REQUIRE_FALSE(ec);
        REQUIRE(enc.size() >= source.size);

        std::string dec;
        ec = cipher::decrypt(auto_size_t{dec}, enc, ci);
        REQUIRE_FALSE(ec);

#if VERBOSE_CIPHER > 0
        std::printf(" done. sizeof in:%3zu enc:%3zu dec:%3zu\n",
            source.size, enc.size(), dec.size());
#endif
        REQUIRE(dec == source);

        // streamin-api
        if (feats.traits.block_mode == cipher_bm::xts)
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
        switch (feats.traits.block_mode) {
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

        const auto source = make_source(test::long_text(), feats.traits);

        std::vector<uint8_t> enc;
        std::vector<uint8_t> tag;
        auto ec = cipher::auth_encrypt(auto_size_t{enc}, auto_size_t{tag}, source, ci);
        if (ec)
            std::printf("\nauth-crypt error(%0x): %s\n", -ec.value(), ec.message().data());
        REQUIRE_FALSE(ec);
        REQUIRE(enc.size() >= source.size);
        REQUIRE(tag.size() >= 16);

        std::string dec;
        ec = cipher::auth_decrypt(auto_size_t{dec}, tag, enc, ci);
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
        ci.type    = feats.type;
        ci.padding = padding_of(feats.traits.block_mode);
        ci.key     = test::short_binary();
        ci.iv      = test::short_text();
        REQUIRE(ci.iv.size > feats.traits.iv_size);
        // adjust to exact size
        ci.iv.size  = feats.traits.iv_size;
        ci.key.size = feats.traits.key_bitlen >> 3; // to byte
    }
};

void
test_variable_iv(cipher_t type) {
    if (!supports(type))
        return;
    const auto tr = cipher::traits(type);
    REQUIRE(tr.accept_variable_iv_size);
    cipher::info_t ci;
    ci.type     = type;
    ci.key      = test::short_binary();
    ci.iv       = test::short_text();
    ci.key.size = tr.key_bitlen >> 3;
    ci.iv.size  = tr.iv_size + 2; // extra 2bytes to the recommended size

    const bin_view_t plain{test::long_text()};

    std::string enc;
    auto        ec = cipher::encrypt(auto_size_t{enc}, plain, ci);
    REQUIRE_FALSE(ec);
    REQUIRE(enc.size() == plain.size);

    std::string dec;
    ec = cipher::decrypt(auto_size_t{dec}, enc, ci);
    REQUIRE_FALSE(ec);
    REQUIRE(plain == dec);
}

void
test_variable_key(cipher_t type) {
    if (!supports(type))
        return;
    const auto tr = cipher::traits(type);
    REQUIRE(tr.accept_variable_key_size);
    cipher::info_t ci;
    ci.type     = type;
    ci.padding  = padding_of(tr.block_mode);
    ci.key      = test::short_binary();
    ci.iv       = test::short_text();
    ci.key.size = (tr.key_bitlen >> 3) + 2; // extra 2bytes to the recommended size
    ci.iv.size  = tr.iv_size;

    const auto plain = make_source(test::long_text(), tr);

    std::string enc;
    auto        ec = cipher::encrypt(auto_size_t{enc}, plain, ci);
    REQUIRE_FALSE(ec);

    std::string dec;
    ec = cipher::decrypt(auto_size_t{dec}, enc, ci);
    REQUIRE_FALSE(ec);
    REQUIRE(plain == dec);
}

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

TEST_CASE("cipher properties", "[cipher]") {
    SECTION("empty traits") {
        cipher::traits_t tr{};
        REQUIRE_FALSE(is_valid(tr));
        tr.block_size = 16;
        REQUIRE_FALSE(is_valid(tr));
        tr.key_bitlen = 128;
        REQUIRE_FALSE(is_valid(tr));
        tr.block_mode = cipher_bm::ecb;
        REQUIRE(is_valid(tr)); // ecb can come with iv_size=0
        tr.block_mode = cipher_bm::gcm;
        REQUIRE_FALSE(is_valid(tr)); // requires iv
        tr.iv_size = 16;
        REQUIRE(is_valid(tr));
    }

    SECTION("empty ciphers") {
        cipher::info_t ci;
        REQUIRE_FALSE(is_valid(ci));
        auto tr = cipher::traits(ci.type);
        REQUIRE(tr.block_size == 0);
        REQUIRE(tr.key_bitlen == 0);
        REQUIRE(tr.iv_size    == 0);
        REQUIRE(tr.block_mode == cipher_bm::unknown);
    }

    SECTION("all supported ciphers") {
        for (const auto& f : Features) {
            if (supports(f.type)) {
                tester{f}.run();
            } else {
                const auto& tr = cipher::traits(f.type);
                REQUIRE(tr.block_size == 0);
                REQUIRE(tr.key_bitlen == 0);
                REQUIRE(tr.iv_size    == 0);
                REQUIRE(tr.block_mode == cipher_bm::unknown);
            }
        }
    }
}

TEST_CASE("special cipher tests", "[cipher]") {
    test_variable_iv(cipher_t::aes_128_gcm);
    test_variable_iv(cipher_t::aria_128_gcm);
    test_variable_iv(cipher_t::camellia_128_gcm);
    // INFO: at the moment mbedtls can not support variable IV for ccm block modes!
    // test_variable_iv(cipher_t::aes_128_ccm);
    // test_variable_iv(cipher_t::aria_128_ccm);
    // test_variable_iv(cipher_t::camellia_128_ccm);

    test_variable_key(cipher_t::blowfish_cbc);
    test_variable_key(cipher_t::blowfish_cfb64);
    test_variable_key(cipher_t::blowfish_ctr);
}

