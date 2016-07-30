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

#include <memory>
#include <string>

#if defined(QT_CORE_LIB)
#include <QByteArray>
#endif // QT_CORE_LIB
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

#if defined(QT_CORE_LIB)
inline auto
to_const_ptr(const QByteArray& b) {
    return reinterpret_cast<cuchars>(b.data());
}

inline auto
to_ptr(QByteArray& b) {
    return reinterpret_cast<uchars>(b.data());
}

inline QByteArray
QByteArrayShallow(const buffer_t& src) {
    return QByteArray::fromRawData(src.data(), src.size());
}

inline QByteArray
QByteArrayShallow(cuchars src, size_t size) {
    return QByteArray::fromRawData(reinterpret_cast<const char*>(src), size);
}
#endif // QT_CORE_LIB

///////////////////////////////////////////////////////////////////////////////
/// a class similar to c++17 std::string_view
class buffer_view_t
{
    cuchars  data_ = nullptr;
    size_t   size_ = 0;

public:
    constexpr buffer_view_t(cuchars data, size_t length) noexcept
        : data_(data), size_(length) {}

    // T could be std::string, QByteArray or even an std::vector<uchar>
    template <class T>
    constexpr buffer_view_t(const T& src)
        : data_(to_const_ptr(src)), size_(src.length()) {}

    constexpr cuchars data() const noexcept {
        return data_;
    }

    constexpr size_t size() const noexcept {
        return size_;
    }

    constexpr size_t length() const noexcept {
        return size_;
    }

    constexpr bool empty() const noexcept {
        return size_ == 0;
    }

    // conversion
    template<class T>
    T to() const;


    // copyalbe, moveable
    ~buffer_view_t() = default;
    buffer_view_t()  = delete;
    buffer_view_t(const buffer_view_t&) = default;
    buffer_view_t(buffer_view_t&&)      = default;
    buffer_view_t& operator=(const buffer_view_t&) = default;
    buffer_view_t& operator=(buffer_view_t&&)      = default;
}; // buffer_view_t

template <>
inline buffer_t
buffer_view_t::to<buffer_t>() const {
    return buffer_t(reinterpret_cast<const char*>(data_), size_);
}

#if defined(QT_CORE_LIB)
template <>
inline QByteArray
buffer_view_t::to<QByteArray>() const {
    return QByteArray(reinterpret_cast<const char*>(data_), size_);
}
#endif // QT_CORE_LIB
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDCRYPTO_CONFIGS_HPP
