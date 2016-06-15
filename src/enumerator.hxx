/** @file enumerator.hxx
 *
 * @copyright (C) 2016
 * @date 2016.04.09
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef ENUMERATOR_HXX
#define ENUMERATOR_HXX

#include "mbedcrypto/exception.hpp"

#include <algorithm>
#include <cctype>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

template <typename Enum, typename Native> struct enum_map {
    Enum   e;
    Native n;
};

template <typename Enum, class Array>
auto
to_native(Enum e, const Array& items) {
    for (const auto& i : items) {
        if (i.e == e)
            return i.n;
    }

    throw exceptions::type_error{};
}

template <typename Native, class Array>
auto
from_native(Native n, const Array& items) {
    for (const auto& i : items) {
        if (i.n == n)
            return i.e;
    }

    throw exceptions::type_error{};
}

///////////////////////////////////////////////////////////////////////////////

template <typename Enum> struct name_map {
    Enum        e;
    const char* n;
};

inline std::string
to_upper(const char* p) {
    std::string s(p);
    std::transform(s.cbegin(), s.cend(), s.begin(), [](char c) {
        return std::toupper(c);
    });
    return s;
}

template <typename Enum, class Array>
auto
to_string(Enum e, const Array& items) {
    for (const auto& i : items) {
        if (i.e == e)
            return i.n;
    }

    throw exceptions::type_error{};
}

template <typename Enum, class Array>
Enum
from_string(const char* name, const Array& items) {
    auto uname = to_upper(name);
    for (const auto& i : items) {
        if (uname == i.n)
            return i.e;
    }

    return Enum::none;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // ENUMERATOR_HXX
