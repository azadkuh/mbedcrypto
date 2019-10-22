/** @file binutils.hpp
 *
 * @copyright (C) 2019
 * @date 2019.10.05
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_BINUTILS_HPP
#define MBEDCRYPTO_BINUTILS_HPP

#include "mbedcrypto/meta.hxx"
#include <string>

#if defined(QT_CORE_LIB)
#   include <QByteArray>
#endif

//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

/// std::string is able to hold both TEXT and Binary data.
/// as encryption is frequently being used with both text strings and binaries,
/// std::string is more convenient than std::vector<unsigned char> or
/// std::basic_string<unsigned char>.
/// although std::vector<unsigned char> is a better options for binary contents.
using buffer_t = std::string;

//-----------------------------------------------------------------------------

/** an editor (mutable) interface for binary (or text) data.
 * can accept most resizable containers as: std::string, std::vector,
 * QByteArray, ...
 */
struct bin_edit_t final
{
    uint8_t* data = nullptr;
    size_t   size = 0;

    void resize(size_t sz) { pimpl->resize(*this, sz); }

public: // iterator
    using iterator       = uint8_t*;
    using const_iterator = const uint8_t*;
    iterator       begin()  noexcept       { return data;        }
    iterator       end()    noexcept       { return data + size; }
    const_iterator cbegin() const noexcept { return data;        }
    const_iterator cend()   const noexcept { return data + size; }

public:
    template <typename T,                                  // T
        typename S = decltype(std::declval<T>().size()),   // has size()
        typename O = decltype(std::declval<T>()[42]),      // has operator[size_t/int]()
        typename = decltype(std::declval<T>().resize(42)), // has resize(size_t/int)
        typename = std::enable_if_t<                       // also:
            std::is_reference<O>::value                    // operator[] returns a reference
            && !std::is_const<O>::value                    // operator[] is a mutable reference
            && sizeof(std::remove_reference_t<O>) == 1     // operator[] returns a single-byte reference
            && std::is_integral<S>::value                  // size() returns an integral
    >>
    bin_edit_t(T& ref) : pimpl{/*placement*/new(stack) model<T>{*this, ref}} {}

    ~bin_edit_t() { pimpl->~concept_t(); }
    bin_edit_t() noexcept             = delete;
    bin_edit_t(const bin_edit_t&)     = delete;
    bin_edit_t(bin_edit_t&&) noexcept = delete;

protected:
    struct concept_t {
        virtual ~concept_t() = default;
        virtual void resize(bin_edit_t&, size_t) = 0;
    };

    template <typename T> struct model final : concept_t {
        T& container;
        explicit model(bin_edit_t& self, T& t) : container{t} {
            assign(self);
        }
        void resize(bin_edit_t& self, size_t sz) override {
            container.resize(sz);
            assign(self);
        }
        void assign(bin_edit_t& self) {
            self.data = reinterpret_cast<uint8_t*>(&container[0]);
            self.size = container.size();
        }
    };

    constexpr static size_t Size = 2 * sizeof(void*);
    char       stack[Size] = {};
    concept_t* pimpl       = nullptr;
}; // struct bin_edit_t

//-----------------------------------------------------------------------------

/** a view (immutable) interface for binary (or text) data.
 * can accept raw buffers and different containers (std::string, std::vector,
 * QByteArray, std::span, std::string_view, std::array, ...).
 */
struct bin_view_t {
    const uint8_t* data = nullptr;
    size_t         size = 0;

    bin_view_t() noexcept = default;

    /// accepts char, unsigned char, ... or any other single-byte type
    template <
        typename T,      // T should be single-byte as char or uint8_t
        typename Size,   // Size should be integral as size_t or int
        typename = std::enable_if_t<sizeof(T) == 1 && std::is_integral<Size>::value>
        >
    bin_view_t(const T* buffer, Size length) noexcept
        : data{reinterpret_cast<const uint8_t*>(buffer)},
          size{static_cast<size_t>(length)} {}

    /// accepts null-terminated strings
    bin_view_t(const char* text_src)
        : data{reinterpret_cast<const uint8_t*>(text_src)},
          size{std::strlen(text_src)} {}

    /// accepts any container with data() and size() member functions.
    template <typename Container>
    using is_supported_t = std::enable_if_t<
        std::is_constructible<
            bin_view_t,
            decltype(std::declval<Container>().data()),
            decltype(std::declval<Container>().size())
        >::value
    >;

    template <typename Container, typename = is_supported_t<Container>>
    bin_view_t(const Container& c) noexcept : bin_view_t{c.data(), c.size()} {}

    bin_view_t(const bin_edit_t& be) noexcept : bin_view_t{be.data, be.size} {}

public: // iterators
    using iterator       = const uint8_t*;
    using const_iterator = const uint8_t*;
    iterator       begin()  noexcept       { return data;        }
    iterator       end()    noexcept       { return data + size; }
    const_iterator cbegin() const noexcept { return data;        }
    const_iterator cend()   const noexcept { return data + size; }
}; // struct bin_view_t

//-----------------------------------------------------------------------------

constexpr inline bool
is_empty(const bin_view_t& bv) noexcept {
    return bv.size == 0 || bv.data == nullptr;
}

inline bool
operator==(bin_view_t a, bin_view_t b) {
    return a.size == b.size && std::memcmp(a.data, b.data, a.size) == 0;
}

template <typename Container>
inline bool
operator==(const Container& a, bin_view_t b) {
    return bin_view_t{a} == b;
}

template <typename Container>
inline bool
operator==(bin_view_t a, const Container& b) {
    return a == bin_view_t{b};
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_BINUTILS_HPP
