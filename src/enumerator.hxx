/** @file enumerator.hxx
 *
 * @copyright (C) 2016
 * @date 2016.04.09
 * @author amir zamani <azadkuh@live.com>
 */

#ifndef MBEDCRYPTO_ENUMERATOR_HXX
#define MBEDCRYPTO_ENUMERATOR_HXX

#include <cstring>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace details {
//-----------------------------------------------------------------------------

inline char
to_lower_ascii(char ch) noexcept {
    constexpr char Shift = 'a' - 'A';
    return (ch >= 'A' && ch <= 'Z') ? ch + Shift : ch;
};

//-----------------------------------------------------------------------------

/// maps a mbedcrypto enum class to a native (mbedtls) enum
template <typename Enum, typename Native>
struct enum_pair {
    Enum   e;
    Native n;
};

template <
    class Array,
    typename Enum   = decltype(std::declval<Array>()[0].e),
    typename Native = decltype(std::declval<Array>()[0].n)>
inline Native
to_native(Enum e, const Array& items, Native bad) noexcept {
    for (const auto& i : items) {
        if (i.e == e)
            return i.n;
    }
    return bad;
}

template <
    class Array,
    typename Enum   = decltype(std::declval<Array>()[0].e),
    typename Native = decltype(std::declval<Array>()[0].n)>
inline Enum
from_native(Native n, const Array& items) noexcept {
    for (const auto& i : items) {
        if (i.n == n)
            return i.e;
    }
    return Enum::unknown;
}

//-----------------------------------------------------------------------------

/// maps a mbedcrypto enum class to it's name
template <typename Enum>
struct enum_name {
    Enum        e;
    const char* n;
};

template <class Array, typename Enum = typename Array::Enum>
inline const char*
to_string(Enum e, const Array& items) noexcept {
    for (const auto& i : items) {
        if (i.e == e)
            return i.n;
    }
    return nullptr;
}

template <class Array, typename Enum = decltype(std::declval<Array>()[0].e)>
inline Enum
from_string(const char* name, const Array& items) noexcept {
    auto icmp = [](const char* lhs, const char* rhs) -> bool {
        const auto lz = std::strlen(lhs);
        const auto rz = std::strlen(rhs);
        if (lz == 0 || rz == 0 || lz != rz)
            return false;
        return std::equal(lhs, lhs + lz - 1, rhs, [](char a, char b) {
            return to_lower_ascii(a) == to_lower_ascii(b);
        });
    };
    for (const auto& i : items) {
        if (icmp(i.n, name))
            return i.e;
    }
    return Enum::unknown;
}

//-----------------------------------------------------------------------------
} // namespace details
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_ENUMERATOR_HXX
