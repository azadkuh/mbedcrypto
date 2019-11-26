#include <catch2/catch.hpp>

#include "./helper.hpp"
#include "mbedcrypto/text_codec.hpp"
#include "mbedcrypto/pk.hpp"

//-----------------------------------------------------------------------------
namespace {
using namespace mbedcrypto;
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

TEST_CASE("api tests", "[pk]") {
    auto  ptr = pk::make_context();
    auto& ctx = *ptr;
    SECTION("empty checks") {
        REQUIRE_FALSE(pk::is_valid(ctx));
        REQUIRE(pk::type_of(ctx)                  == pk_t::unknown);
        REQUIRE(pk::key_bitlen(ctx)               == 0);
        REQUIRE(pk::key_size(ctx)                 == 0);
        REQUIRE(pk::max_crypt_size(ctx)           == 0);
        REQUIRE(pk::has_private_key(ctx)          == false);
        REQUIRE(pk::can_do(ctx, pk_t::rsa)        == false);
        REQUIRE(pk::can_do(ctx, pk_t::rsa_alt)    == false);
        REQUIRE(pk::can_do(ctx, pk_t::rsassa_pss) == false);
        REQUIRE(pk::can_do(ctx, pk_t::ec)         == false);
        REQUIRE(pk::can_do(ctx, pk_t::ecdh)       == false);
        REQUIRE(pk::can_do(ctx, pk_t::ecdsa)      == false);
        REQUIRE(pk::what_can_do(ctx)              == pk::capability{});
        auto other = pk::make_context();
        REQUIRE(pk::is_pri_pub_pair(ctx, *other)  == false); // both are invalid
    }

    SECTION("setup rsa") {
        auto ec = pk::setup(ctx, pk_t::rsa); // rsa is always enabled
        REQUIRE_FALSE(ec);
        REQUIRE(pk::type_of(ctx) == pk_t::rsa);

        ec = pk::setup(ctx, pk_t::unknown);
        REQUIRE(ec == make_error_code(error_t::not_supported));
        REQUIRE(pk::type_of(ctx) == pk_t::unknown);

        ec = pk::setup(ctx, pk_t::rsa_alt);
        REQUIRE(ec == make_error_code(error_t::not_supported));
        REQUIRE(pk::type_of(ctx) == pk_t::unknown);

        ec = pk::setup(ctx, pk_t::rsassa_pss);
        REQUIRE(ec == make_error_code(error_t::not_supported));
        REQUIRE(pk::type_of(ctx) == pk_t::unknown);
    }

    SECTION("setup ec") {
        if (supports(features::pk_ec)) {
            auto ec = pk::setup(ctx, pk_t::ec);
            REQUIRE_FALSE(ec);
            REQUIRE(pk::type_of(ctx) == pk_t::ec);

            ec = pk::setup(ctx, pk_t::ecdh);
            REQUIRE_FALSE(ec);
            REQUIRE(pk::type_of(ctx) == pk_t::ecdh);

            ec = pk::setup(ctx, pk_t::ecdsa);
            REQUIRE_FALSE(ec);
            REQUIRE(pk::type_of(ctx) == pk_t::ecdsa);
        } else {
            auto ec = pk::setup(ctx, pk_t::ec);
            REQUIRE(ec == make_error_code(error_t::not_supported));
            REQUIRE(pk::type_of(ctx) == pk_t::unknown);

            ec = pk::setup(ctx, pk_t::ecdh);
            REQUIRE(ec == make_error_code(error_t::not_supported));
            REQUIRE(pk::type_of(ctx) == pk_t::unknown);

            ec = pk::setup(ctx, pk_t::ecdsa);
            REQUIRE(ec == make_error_code(error_t::not_supported));
            REQUIRE(pk::type_of(ctx) == pk_t::unknown);
        }
    }

    SECTION("make rsa key") {
        constexpr size_t keybits = 1024;
        auto ec = make_rsa_key(ctx, keybits);
        if (pk::supports_rsa_keygen()) {
            REQUIRE_FALSE(ec);
            REQUIRE(pk::type_of(ctx)                  == pk_t::rsa);
            REQUIRE(pk::key_bitlen(ctx)               == keybits);
            REQUIRE(pk::key_size(ctx)                 == 128); // 1024 / 8
            REQUIRE(pk::max_crypt_size(ctx)           == (128 - 11));
            REQUIRE(pk::has_private_key(ctx)          == true);
            REQUIRE(pk::can_do(ctx, pk_t::rsa)        == true);
            REQUIRE(pk::can_do(ctx, pk_t::rsa_alt)    == false);
            REQUIRE(pk::can_do(ctx, pk_t::rsassa_pss) == true);
            REQUIRE(pk::can_do(ctx, pk_t::ec)         == false);
            REQUIRE(pk::can_do(ctx, pk_t::ecdh)       == false);
            REQUIRE(pk::can_do(ctx, pk_t::ecdsa)      == false);
            auto cap = pk::what_can_do(ctx);
            REQUIRE(cap.encrypt == true);
            REQUIRE(cap.decrypt == true);
            REQUIRE(cap.sign    == true);
            REQUIRE(cap.verify  == true);

            std::string pub_data;
            ec = pk::export_pub_key(pub_data, ctx, pk::key_io_t::der);
            REQUIRE_FALSE(ec);
            REQUIRE_FALSE(pub_data.empty());

            auto pub = pk::make_context();
            ec = pk::import_pub_key(*pub, pub_data);
            REQUIRE_FALSE(ec);
            REQUIRE(pk::is_valid(*pub));
            REQUIRE(is_pri_pub_pair(ctx, *pub));

            REQUIRE(pk::type_of(*pub)                  == pk_t::rsa);
            REQUIRE(pk::key_bitlen(*pub)               == keybits);
            REQUIRE(pk::key_size(*pub)                 == 128); // 1024 / 8
            REQUIRE(pk::max_crypt_size(*pub)           == (128 - 11));
            REQUIRE(pk::has_private_key(*pub)          == false);
            REQUIRE(pk::can_do(*pub, pk_t::rsa)        == true);
            REQUIRE(pk::can_do(*pub, pk_t::rsa_alt)    == false);
            REQUIRE(pk::can_do(*pub, pk_t::rsassa_pss) == true);
            REQUIRE(pk::can_do(*pub, pk_t::ec)         == false);
            REQUIRE(pk::can_do(*pub, pk_t::ecdh)       == false);
            REQUIRE(pk::can_do(*pub, pk_t::ecdsa)      == false);
            cap = pk::what_can_do(*pub);
            REQUIRE(cap.encrypt == true);
            REQUIRE(cap.decrypt == false);
            REQUIRE(cap.sign    == false);
            REQUIRE(cap.verify  == true);
        } else {
            REQUIRE(ec == make_error_code(error_t::not_supported));
        }
    }
}

TEST_CASE("public-key capabilities", "[pk]") {
    pk::capability c;
    REQUIRE((c.encrypt == false &&
             c.decrypt == false &&
             c.sign    == false &&
             c.verify  == false));
}

