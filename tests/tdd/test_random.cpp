#include <catch.hpp>
#include <iostream>

#include "mbedcrypto/random.hpp"
#include "mbedcrypto/tcodec.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace {
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

TEST_CASE("random generator tests", "[random]") {
    using namespace mbedcrypto;

    mbedcrypto::random rnd("some custom text or binary data");

    auto buf = rnd.make(128);
    REQUIRE( buf.size() == 128 );

    REQUIRE_NOTHROW( rnd.reseed() );
    REQUIRE_NOTHROW( rnd.reseed("with some data") );
    REQUIRE( rnd.reseed(nullptr, 0) == 0 );

    REQUIRE_NOTHROW( rnd.update("with some data") );
    REQUIRE_NOTHROW( rnd.update(std::string())    );

    rnd.entropy_length(64);
    rnd.reseed_interval(200);
    rnd.prediction_resistance(true);

    mbedcrypto::random rnd2;
    buf = rnd2.make(93);
    REQUIRE( buf.size() == 93 );

    // big buffer must be possible
    REQUIRE_NOTHROW( rnd.make(32004) );
}
