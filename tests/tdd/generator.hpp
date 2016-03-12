/** @file generator.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.06
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef TESTS_GENERATOR_HPP
#define TESTS_GENERATOR_HPP

#include "mbedcrypto/types.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace test {
///////////////////////////////////////////////////////////////////////////////

// following functions return some sample data for various test units.

const char* short_text();
const char* long_text();

buffer_t short_binary();
buffer_t long_binary();

///////////////////////////////////////////////////////////////////////////////

/// utility function for reading a buffer in chunks
/// used by test units to test start()/update().../finish() sequences.
template<class BufferT, class Func, class... Args> void
chunker(size_t chunk_size, const BufferT& src, Func&& func, Args&&... args) {

    const auto* data = reinterpret_cast<const unsigned char*>(src.data());

    for ( size_t i = 0;    (i+chunk_size) <= src.size();    i += chunk_size ) {
        func(data + i, chunk_size, std::forward<Args&&>(args)...);
    }

    size_t residue = src.size() % chunk_size;
    if ( residue )
        func(data + src.size() - residue, residue, std::forward<Args&&>(args)...);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace test
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // TESTS_GENERATOR_HPP