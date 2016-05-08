#include <catch.hpp>

#include "mbedtls/cipher.h"
#include "mbedcrypto/cipher.hpp"
#include "mbedcrypto/rnd_generator.hpp"
#include "mbedcrypto/tcodec.hpp"
#include "src/conversions.hpp"

#include "generator.hpp"
#include <cstring>
#include <iostream>
///////////////////////////////////////////////////////////////////////////////
namespace {
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////
class sub_finder
{
    const char* pstr = nullptr;

public:
    explicit sub_finder(const char* name) : pstr(name) {}
    sub_finder()  = delete;
    ~sub_finder() = default;

    bool contains(const char* part) const {
        if ( part == nullptr  ||  pstr == nullptr )
            throw std::logic_error("invalid arguments");

        return strstr(pstr, part) != nullptr;
    }

}; // sub_finder

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
        case cipher_bm::ccm:
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
make_input(cipher_bm bm, size_t bs, rnd_generator& drbg) {
    switch ( bm ) {
        case cipher_bm::ecb:
            return drbg.make(100 * bs);

        case cipher_bm::cbc:
        case cipher_bm::cfb:
        case cipher_bm::ctr:
        case cipher_bm::stream:
        case cipher_bm::gcm:
        case cipher_bm::ccm:
            return drbg.make(3241);

        default: // not supported types
            return buffer_t();
    }
}

buffer_t
chunker_impl(size_t chunk_size, const buffer_t& input, cipher& cip) {
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

const char*
AdditionalData() {
    return "some additional data!\n"
        "may be transferred in plain text if you like.";
}
///////////////////////////////////////////////////////////////////////////////

struct cipher_tester {
    cipher_t  ctype        = cipher_t::none;
    padding_t padding_mode = padding_t::none;
    cipher_bm block_mode   = cipher_bm::none;
    size_t    block_size   = 0;
    size_t    key_size     = 0;
    size_t    iv_size      = 0;
    size_t    chunk_size   = 0;

    buffer_t  iv;
    buffer_t  key;
    buffer_t  input;

    cipher    cipenc;
    cipher    cipdec;

public:
    explicit cipher_tester(cipher_t ct)
        : ctype(ct), cipenc(ct), cipdec(ct) {}

    bool setup(rnd_generator& drbg) {
        // properties
        block_mode   = cipher::block_mode(ctype);
        block_size   = cipher::block_size(ctype);
        key_size     = cipher::key_bitlen(ctype) / 8; // bits to bytes
        iv_size      = cipher::iv_size(ctype);
        chunk_size   = chunk_size_of(ctype);
        padding_mode = padding_of(block_mode);

        // input parameters
        iv           = drbg.make(iv_size);
        key          = drbg.make(key_size);
        input        = make_input(block_mode, block_size, drbg);

        if ( input.empty() ) // not supported yet
            return false;

        // children
        cipenc
            .padding(padding_mode)
            .iv(iv)
            .key(key, cipher::encrypt_mode);

        cipdec
            .padding(padding_mode)
            .iv(iv)
            .key(key, cipher::decrypt_mode);

        return true;
    }

    void one_shot() {
        auto encr = cipher::encrypt(
                ctype, padding_mode,
                iv, key,
                input
                );

        auto decr = cipher::decrypt(
                ctype, padding_mode,
                iv, key,
                encr
                );

        INFO( to_string(ctype) );
        REQUIRE( (decr == input) );
    }

    void by_object() {
        cipenc.start();
        auto encr = cipenc.update(input);
        encr.append(cipenc.finish());

        cipdec.start();
        auto decr = cipdec.update(encr);
        decr.append(cipdec.finish());

        REQUIRE( (decr == input) );
    }

    void by_object_chunked() {
        auto encr = chunker_impl(chunk_size, input, cipenc);

        auto decr = chunker_impl(chunk_size, encr, cipdec);

        REQUIRE( (decr == input) );
    }

    void aead_one_shot() {
        auto encr = cipher::encrypt_aead(
                ctype,
                iv, key,
                AdditionalData(),
                input
                );

        auto decr = cipher::decrypt_aead(
                ctype,
                iv, key,
                AdditionalData(),
                encr
                );

        INFO( to_string(ctype) );
        REQUIRE( std::get<0>(decr) ); // result status
        REQUIRE( (std::get<1>(decr) == input) );
    }

    void gcm_check() {
        cipenc.start();
        cipenc.gcm_additional_data(AdditionalData());
        auto encr = cipenc.update(input);
        encr.append(cipenc.finish());

        auto tag = cipenc.gcm_encryption_tag(16);
        REQUIRE( tag.size() == 16 );

        cipdec.start();
        cipdec.gcm_additional_data(AdditionalData());
        auto decr = cipdec.update(encr);
        decr.append(cipdec.finish());

        REQUIRE( (decr == input) );
        REQUIRE( cipdec.gcm_check_decryption_tag(tag) );
    }

}; // struct cipher_tester

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

            sub_finder f(to_string(t));
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

    rnd_generator drbg;

    const auto types = installed_ciphers();
    for ( auto ctype : types ) {
        try {
            cipher_tester tester(ctype);
            if ( !tester.setup(drbg) ) {
                std::cerr << "not supported yet: " << to_string(ctype) << std::endl;
                continue;
            }

            // ccm only works in aead mode
            if ( tester.block_mode != cipher_bm::ccm ) {
                // single shot calls
                tester.one_shot();

                // cipher object
                // single start()/update()/finish()
                tester.by_object();

                // by many chunked updates
                tester.by_object_chunked();
            }

            // aead tests
            if ( tester.block_mode == cipher_bm::gcm
                    ||  tester.block_mode == cipher_bm::ccm ) {
                tester.aead_one_shot();
            }

            // gcm special checks
            if ( tester.block_mode == cipher_bm::gcm ) {
                tester.gcm_check();
            }


        } catch ( mbedcrypto::exception& cerr ) {
            std::cerr << "error(" << to_string(ctype) << ") :"
                << cerr.what() << std::endl;
            REQUIRE_FALSE( "exception failure" );
        }

    }
}


///////////////////////////////////////////////////////////////////////////////
