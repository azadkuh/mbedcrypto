#include <catch2/catch.hpp>

#include "./helper.hpp"
#include "../src/private/pk_context.hpp"
#include "mbedcrypto/text_codec.hpp"

//-----------------------------------------------------------------------------
namespace {
using namespace mbedcrypto;
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

TEST_CASE("private api tests", "[pk]") {
    pk::context ctx;
    SECTION("empty checks") {
        REQUIRE_FALSE(pk::is_valid(ctx));
        REQUIRE_NOTHROW(pk::reset(ctx)); // empty context are resetable
        REQUIRE_NOTHROW(pk::reset(ctx));
        REQUIRE(pk::type_of(ctx)                  == pk_t::unknown);
        REQUIRE(pk::key_bitlen(ctx)               == 0);
        REQUIRE(pk::key_size(ctx)                 == 0);
        REQUIRE(pk::max_crypt_size(ctx)           == 0);
        REQUIRE(pk::has_private_key(ctx)          == false);
        REQUIRE(pk::can_do(ctx, pk_t::rsa)        == false);
        REQUIRE(pk::can_do(ctx, pk_t::eckey)      == false);
        REQUIRE(pk::can_do(ctx, pk_t::eckey_dh)   == false);
        REQUIRE(pk::can_do(ctx, pk_t::ecdsa)      == false);
        REQUIRE(pk::can_do(ctx, pk_t::rsa_alt)    == false);
        REQUIRE(pk::can_do(ctx, pk_t::rsassa_pss) == false);
        REQUIRE(pk::what_can_do(ctx)              == pk::capability{});
        pk::context other;
        REQUIRE(pk::check_pair(ctx, other) == false); // both are invalid
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
        #if defined(MBEDCRYPTO_EC)
        auto ec = pk::setup(ctx, pk_t::eckey);
        REQUIRE_FALSE(ec);
        REQUIRE(pk::type_of(ctx) == pk_t::eckey);

        ec = pk::setup(ctx, pk_t::eckey_dh);
        REQUIRE_FALSE(ec);
        REQUIRE(pk::type_of(ctx) == pk_t::eckey_dh);

        ec = pk::setup(ctx, pk_t::ecdsa);
        REQUIRE_FALSE(ec);
        REQUIRE(pk::type_of(ctx) == pk_t::ecdsa);
        #else
        auto ec = pk::setup(ctx, pk_t::eckey);
        REQUIRE(ec == make_error_code(error_t::not_supported));
        REQUIRE(pk::type_of(ctx) == pk_t::unknown);

        ec = pk::setup(ctx, pk_t::eckey_dh);
        REQUIRE(ec == make_error_code(error_t::not_supported));
        REQUIRE(pk::type_of(ctx) == pk_t::unknown);

        ec = pk::setup(ctx, pk_t::ecdsa);
        REQUIRE(ec == make_error_code(error_t::not_supported));
        REQUIRE(pk::type_of(ctx) == pk_t::unknown);
        #endif
    }
}

TEST_CASE("public-key capabilities", "[pk]") {
    pk::capability c;
    REQUIRE((c.encrypt == false &&
             c.decrypt == false &&
             c.sign    == false &&
             c.verify  == false));
}

