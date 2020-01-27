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
    return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch + Shift) : ch;
}

inline bool
icompare(const char* a, size_t alen, const char* b, size_t blen) noexcept {
    if (alen != blen)
        return false;
    return std::equal(a, a + alen, b, [](char x, char y) {
        return to_lower_ascii(x) == to_lower_ascii(y);
    });
}

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
    if (name != nullptr) {
        for (const auto& i : items) {
            if (icompare(i.n, std::strlen(i.n), name, std::strlen(name)))
                return i.e;
        }
    }
    return Enum::unknown;
}

//-----------------------------------------------------------------------------
} // namespace details
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_ENUMERATOR_HXX
