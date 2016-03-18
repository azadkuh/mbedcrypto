#include <catch.hpp>

#include "mbedtls/cipher.h"
#include "mbedcrypto/cipher.hpp"
#include "mbedcrypto/random.hpp"
#include "mbedcrypto/tcodec.hpp"
#include "src/conversions.hpp"

#include "generator.hpp"
#include <iostream>
///////////////////////////////////////////////////////////////////////////////
namespace {
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////
class finder
{
    const char* pstr = nullptr;

public:
    explicit finder(const char* name) : pstr(name) {}
    finder()  = delete;
    ~finder() = default;

    bool contains(const char* part) const {
        if ( part == nullptr  ||  pstr == nullptr )
            throw std::logic_error("invalid arguments");

        return strstr(pstr, part) != nullptr;
    }

}; // finder
///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("test block mode", "[cipher][types]") {
    using namespace mbedcrypto;

    SECTION("block modes") {
        const auto ciphers = installed_ciphers();
        for ( const auto t : ciphers ) {
            if ( !supports(t) )
                continue;

            finder f(to_string(t));
            if ( f.contains("ECB") ) {
                REQUIRE( cipher::block_mode(t) == cipher_bm::ecb );

            } else if ( f.contains("CBC") ) {
                REQUIRE( cipher::block_mode(t) == cipher_bm::cbc );

            } else if ( f.contains("CFB") ) {
                REQUIRE( cipher::block_mode(t) == cipher_bm::cfb );

            } else if ( f.contains("CTR") ) {
                REQUIRE( cipher::block_mode(t) == cipher_bm::ctr );

            } else if ( f.contains("GCM") ) {
                REQUIRE( cipher::block_mode(t) == cipher_bm::gcm );

            } else if ( f.contains("CCM") ) {
                REQUIRE( cipher::block_mode(t) == cipher_bm::ccm );

            } else if ( t == cipher_t::arc4_128 ) {
                REQUIRE( cipher::block_mode(t) == cipher_bm::stream );
            }
        }
    }

}


///////////////////////////////////////////////////////////////////////////////
