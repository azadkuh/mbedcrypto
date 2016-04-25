/** @file configs.hpp
 *
 * @copyright (C) 2016
 * @date 2016.03.07
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_CONFIGS_HPP
#define MBEDCRYPTO_CONFIGS_HPP

#include <string>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {

/// std::string is able to hold both TEXT and Binary data.
/// as encryption is frequently being used with both text strings and binaries,
///  std::string is more convenient than std::vector<unsigned char> or
///  std::basic_string<unsigned char>.
/// although std::vector<unsigned char> is a better options for binary contents.
using buffer_t = std::string;

// synonyms
using cuchars = const unsigned char*;
using uchars  = unsigned char*;

// helper function used internally
inline auto
to_const_ptr(const buffer_t& b) {
    return reinterpret_cast<cuchars>(b.data());
}

inline auto
to_ptr(buffer_t& b) {
    return reinterpret_cast<uchars>(&b.front());
}


///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_CONFIGS_HPP
