/** @file binutils.hpp
 *
 * @copyright (C) 2019
 * @date 2019.10.05
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_BINUTILS_HPP
#define MBEDCRYPTO_BINUTILS_HPP

#include <string>

#if defined(QT_CORE_LIB)
#   include <QByteArray>
#endif

//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

/** resizes a container, @sa obuffer_t::resize().
 * write an overload for any container you want to use as output if it has
 * different signature than T::resize(size_t)
 */
template <typename T, typename = decltype(std::declval<T&>().resize(42))>
inline void
resize(T& ref, size_t sz) {
    ref.resize(sz);
}

#if defined(QT_CORE_LIB)
template <>
inline void
resize(QByteArray& ref, size_t sz) {
    ref.resize(static_cast<int>(sz));
}
#endif

//-----------------------------------------------------------------------------

/** an editable (mutable) interface for binary (or text) data.
 * can accept raw buffers and different containers (std::string, std::vector,
 * QByteArray, std::span, std::string_view, std::array, ...).
 */
struct bin_edit_t
{
    uint8_t* data = nullptr;
    size_t   size = 0;

    bin_edit_t() noexcept = default;

    template <
        typename Elem,
        typename Size,
        typename = std::enable_if_t<
            sizeof(Elem) == 1                   // Elem has to be single-byte
            && !std::is_const<Elem>::value      // Elem should be mutable
            && std::is_integral<Size>::value    // Size should be integral
        >
    >
    bin_edit_t(Elem* buffer, Size length) noexcept
        : data{reinterpret_cast<uint8_t*>(buffer)},
          size{static_cast<size_t>(length)} {}

    template <typename Container,
         typename S = decltype(std::declval<const Container&>().size()),
         typename P = decltype(&std::declval<Container&>()[42]),
         typename = std::enable_if_t<
             std::is_pointer<P>::value &&
             std::is_constructible<bin_edit_t, P, S>::value
         >
    >
    bin_edit_t(Container& c) noexcept : bin_edit_t{&c[0], c.size()} {}

public: // iterators
    using iterator       = uint8_t*;
    using const_iterator = const uint8_t*;
    iterator       begin()  noexcept       { return data;        }
    iterator       end()    noexcept       { return data + size; }
    const_iterator cbegin() const noexcept { return data;        }
    const_iterator cend()   const noexcept { return data + size; }
}; // struct bin_edit_t

//-----------------------------------------------------------------------------

/** a view (immutable) interface for binary (or text) data.
 * accepts raw buffers and different containers (std::string, std::vector,
 * QByteArray, std::span, std::string_view, std::array, ...).
 */
struct bin_view_t {
    const uint8_t* data = nullptr;
    size_t         size = 0;

    bin_view_t() noexcept = default;

    /// accepts char, unsigned char, ... or any other single-byte type
    template <
        typename Elem, // Elem should be single-byte as char or uint8_t
        typename Size, // Size should be integral as size_t or int
        typename = std::enable_if_t<
            sizeof(Elem) == 1 && std::is_integral<Size>::value
        >
    >
    bin_view_t(const Elem* buffer, Size length) noexcept
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
            decltype(std::declval<const Container&>().data()),
            decltype(std::declval<const Container&>().size())
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

/** an mutable wrapper interface for binary (or text) containers.
 * accepts most resizable containers such as: std::string, std::vector<uint8_t>,
 * QByteArray, QVector<uint8_t>, ...
 */
struct obuffer_t final : bin_edit_t
{
    void resize(size_t sz) { pimpl->resize(*this, sz); }

    template <
        typename Container,
        typename = decltype(mbedcrypto::resize(std::declval<Container&>(), 42)),
        typename = std::enable_if_t<std::is_constructible<bin_edit_t, Container&>::value>
    >
    explicit obuffer_t(Container& ref)
        : pimpl{/*placement*/ new (stack) model<Container>{*this, ref}} {}

    ~obuffer_t() { pimpl->~concept_t(); }
    obuffer_t() noexcept            = delete;
    obuffer_t(const obuffer_t&)     = delete;
    obuffer_t(obuffer_t&&) noexcept = delete;

protected: // type-erased and generic holder to a resizable container reference.
    struct concept_t {
        virtual ~concept_t() = default;
        virtual void resize(bin_edit_t&, size_t) = 0;
    };

    template <typename Container> struct model final : concept_t {
        Container& container;
        explicit model(bin_edit_t& self, Container& t) : container{t} {
            assign(self);
        }
        void resize(bin_edit_t& self, size_t sz) override {
            mbedcrypto::resize(container, sz);
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
}; // struct obuffer_t

//-----------------------------------------------------------------------------

constexpr inline bool
is_empty(const bin_view_t& bv) noexcept {
    return bv.size == 0 || bv.data == nullptr;
}

constexpr inline bool
is_empty(const bin_edit_t& be) noexcept {
    return be.size == 0 || be.data == nullptr;
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
