#include <catch2/catch.hpp>
#include <array>

#include "mbedcrypto/mpi.hpp"
#include "../src/private/mpi_impl.hpp"

//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
//-----------------------------------------------------------------------------

mpi_impl
make_mpi(int64_t i, size_t shift) {
    mpi_impl big;
    int ret = mbedtls_mpi_lset(&big.ctx_, i);
    REQUIRE(ret == 0);
    ret = mbedtls_mpi_shift_l(&big.ctx_, shift);
    REQUIRE(ret == 0);
    return big;
}

//-----------------------------------------------------------------------------
} // namespace anon
} // namespace mbedcrypto
//-----------------------------------------------------------------------------

TEST_CASE("mpi tests", "[mpi]") {
    using namespace mbedcrypto;

    SECTION("empty") {
        mpi empty;
        REQUIRE_FALSE(empty);
        REQUIRE(empty.size()   == 0);
        REQUIRE(empty.bitlen() == 0);

        mpi other;
        REQUIRE(empty.compare(other) == 0);
    }

    // tests private api of mpi interface
    SECTION("value") {
        auto big = make_mpi(42, 400); // 42 * 2^400
        SECTION("properties") {
            REQUIRE(big.bitlen() == 406); // 2^406
            REQUIRE(big.size()   == 51);  // requires 51 bytes
            // std::printf("bit len is: %zu size is: %zu\n", big.bitlen(), big.size());
        }
        SECTION("compare") {
            auto small = make_mpi(1024, 12);
            REQUIRE(small.compare(big) < 0);
            auto other = make_mpi(42, 400);
            REQUIRE(other.compare(big) == 0);
        }
        SECTION("string dump") {
            std::string out;
            auto ec = big.to_string(obuffer_t{out}, 10);
            REQUIRE_FALSE(ec);
            REQUIRE_FALSE(out.empty());

            mpi_impl r;
            REQUIRE(r.bitlen() == 0); // empty
            ec = r.from_string(out.data(), 10);
            REQUIRE_FALSE(ec);
            REQUIRE(r.compare(big) == 0); // are equal

            r.reset();
            REQUIRE(r.bitlen() == 0); // empty
            ec = r.from_string(out.data(), 16); // mismatched radix
            REQUIRE_FALSE(ec);
            REQUIRE(r.compare(big) != 0); // are not equal
        }
        SECTION("binary dump") {
            std::vector<uint8_t> out;
            auto ec = big.to_binary(obuffer_t{out});
            REQUIRE_FALSE(ec);
            REQUIRE(out.size() == 51); // big is a 51 bytes integer

            mpi_impl r;
            ec = r.from_binary(out);
            REQUIRE_FALSE(ec);
            REQUIRE(r.compare(big) == 0);
        }
    }
}
