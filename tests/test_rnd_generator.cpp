#include <catch2/catch.hpp>
#include <array>

#include "mbedcrypto/rnd_generator.hpp"
#include "mbedcrypto/text_codec.hpp"

//-----------------------------------------------------------------------------

TEST_CASE("random generator tests", "[random]") {
    using namespace mbedcrypto;

    rnd_generator rnd{"some custom text or binary data"};

    {
        std::array<uint8_t, 24> memory;
        bin_edit_t out{memory};
        auto ec  = rnd.make(out);
        REQUIRE_FALSE(ec);
        REQUIRE(out.size == 24);
    }
    {
        std::string out;
        auto        ec = rnd.make(obuffer_t{out}, 16);
        REQUIRE_FALSE(ec);
        REQUIRE(out.size() == 16);
    }

    {
        auto ec = rnd.reseed();
        REQUIRE_FALSE(ec);
        ec = rnd.reseed("with some data");
        REQUIRE_FALSE(ec);
    }

    {
        auto ec = rnd.update("with some data");
        REQUIRE_FALSE(ec);
        ec = rnd.update(bin_view_t{});
        REQUIRE_FALSE(ec);
    }

    {
        auto p = make_random_bytes<std::vector<uint8_t>>(16);
        REQUIRE_FALSE(p.second);
        REQUIRE(p.first.size() == 16);
    }
}
