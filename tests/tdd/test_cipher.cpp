#include <catch.hpp>

#include "mbedtls/cipher.h"
#include "mbedcrypto/cipher.hpp"
#include "mbedcrypto/random.hpp"
#include "mbedcrypto/tcodec.hpp"
#include "src/conversions.hpp"

#include "generator.hpp"
#include <cstring>
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

padding_t
padding_of(cipher_bm bm) {
    switch ( bm ) {
        case cipher_bm::cbc:
            return padding_t::pkcs7;

        case cipher_bm::ecb:
        case cipher_bm::cfb:
        case cipher_bm::ctr:
        case cipher_bm::stream:
        case cipher_bm::gcm:
            return padding_t::none;

        default:
            return padding_t::none;
    }
}

size_t
chunk_size_of(cipher_t ct) {
    switch ( cipher::block_mode(ct) ) {
        case cipher_bm::ecb:
            return cipher::block_size(ct);

        case cipher_bm::cbc:
        case cipher_bm::cfb:
        case cipher_bm::ctr:
        case cipher_bm::stream:
        case cipher_bm::gcm:
        case cipher_bm::ccm:
            return 160; // custom value, could be any value > 0

        default:
            throw std::logic_error(std::string("invalid cipher type: ")
                    + to_string(ct));
            return 0;
    }
}

buffer_t
make_input(cipher_bm bm, size_t bs, mbedcrypto::random& drbg) {
    switch ( bm ) {
        case cipher_bm::ecb:
            return drbg.make(100 * bs);

        case cipher_bm::cbc:
        case cipher_bm::cfb:
        case cipher_bm::ctr:
        case cipher_bm::stream:
        case cipher_bm::gcm:
            return drbg.make(3241);

        default: // not supported types
            return buffer_t();
    }
}

buffer_t
chunker(size_t chunk_size, const buffer_t& input, cipher& cip) {
    cip.start();

    size_t isize = input.size();
    size_t osize = isize + cip.block_size() + 32;
    buffer_t output(osize, '\0');

    size_t i_index = 0;
    size_t o_index = 0;

    // blocks
    size_t chunks = isize / chunk_size;
    for ( size_t i = 0;    i < chunks;    ++i ) {
        o_index += cip.update(chunk_size, input, i_index, output, o_index);
        i_index += chunk_size;
    }

    // last block
    size_t residue = isize % chunk_size;
    if ( residue )
        o_index += cip.update(residue, input, i_index, output, o_index);

    // finalize
    o_index += cip.finish(output, o_index);

    output.resize(o_index);
    return output;
}

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

TEST_CASE("test ciphers against mbedtls", "[cipher]") {
    using namespace mbedcrypto;

    mbedcrypto::random drbg;

    const auto types = installed_ciphers();
    for ( auto ct : types ) {
        try {
            auto block_mode    = cipher::block_mode(ct);
            auto block_size    = cipher::block_size(ct);
            auto key_len       = cipher::key_bitlen(ct) / 8; // bits to bytes
            auto iv_len        = cipher::iv_size(ct);
            size_t chunk_size  = chunk_size_of(ct);

            const auto iv      = drbg.make(iv_len);
            const auto key     = drbg.make(key_len);
            const auto padding = padding_of(block_mode);
            const auto input   = make_input(block_mode, block_size, drbg);

            if ( input.empty() ) {
                std::cerr << "not supported yet: " << to_string(ct) << std::endl;
                continue;
            }

            // single shot calls
            auto enc1 = cipher::encrypt(
                    ct, padding,
                    iv, key,
                    input
                    );
            auto dec1 = cipher::decrypt(
                    ct, padding,
                    iv, key,
                    enc1
                    );
            INFO( to_string(ct) );
            REQUIRE( (dec1 == input) );

            // cipher object
            cipher cipenc(ct);
            cipenc
                .padding(padding)
                .iv(iv)
                .key(key, cipher::encrypt_mode);
            // by single update
            cipenc.start();
            auto enc2 = cipenc.update(input);
            enc2.append(cipenc.finish());
            REQUIRE( (enc2 == enc1) );

            // by many chunked updates
            auto enc3 = chunker(chunk_size, input, cipenc);
            // in arc4 the encrypted data may be different (no iv in arc4)
            if ( block_mode != cipher_bm::stream   &&   block_mode != cipher_bm::gcm )
                REQUIRE( (enc3 == enc1) );

            cipher cipdec(ct);
            cipdec
                .padding(padding)
                .iv(iv)
                .key(key, cipher::decrypt_mode);
            // by single update
            cipdec.start();
            auto dec2 = cipdec.update(enc2);
            dec2.append(cipdec.finish());
            REQUIRE( (dec2 == input) );

            // by many chunked updates
            auto dec3 = chunker(chunk_size, enc3, cipdec);
            REQUIRE( (dec3 == input) );

        } catch ( mbedcrypto::exception& cerr ) {
            std::cerr << "error(" << to_string(ct) << ") :"
                << cerr.to_string() << std::endl;
            REQUIRE_FALSE( "exception failure" );
        }

    }
}


///////////////////////////////////////////////////////////////////////////////
