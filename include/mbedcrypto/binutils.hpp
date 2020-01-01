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
struct bin_view_t;
struct bin_edit_t;
struct auto_size_t;
//-----------------------------------------------------------------------------

/** a view (immutable) interface for binary (or text) data.
 * accepts raw buffers and different *contiguous* containers (std::string,
 * std::vector, QByteArray, std::span, std::string_view, std::array, ...).
 */
struct bin_view_t {
    const uint8_t* data = nullptr;
    size_t         size = 0;

    constexpr bin_view_t() noexcept = default;

    /// accepts char, unsigned char, ... or any other single-byte type
    template <
        typename Elem, // Elem should be single-byte as char or uint8_t
        typename Size, // Size should be integral as size_t or int
        typename = std::enable_if_t<
            sizeof(Elem) == 1 && std::is_integral<Size>::value
        >
    >
    constexpr bin_view_t(const Elem* buffer, Size length) noexcept
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

    constexpr bin_view_t(const bin_edit_t& be) noexcept;

public: // iterators
    using iterator       = const uint8_t*;
    using const_iterator = const uint8_t*;
    constexpr iterator       begin()  noexcept       { return data;        }
    constexpr iterator       end()    noexcept       { return data + size; }
    constexpr const_iterator cbegin() const noexcept { return data;        }
    constexpr const_iterator cend()   const noexcept { return data + size; }
}; // struct bin_view_t

//-----------------------------------------------------------------------------

/** a writer (mutable) interface for binary (or text) data.
 * accepts raw buffer and different *contiguous* containers (std::string,
 * std::vector, QByteArray, std::span, std::string_view, std::array, ...).
 *
 * @warning only writes in-place and never does (re)allocation, resizing or any
 * other memory management.
 */
struct bin_edit_t
{
    uint8_t* data = nullptr;
    size_t   size = 0;

    constexpr bin_edit_t() noexcept = default;

    template <
        typename Elem,
        typename Size,
        typename = std::enable_if_t<
            sizeof(Elem) == 1                   // Elem has to be single-byte
            && !std::is_const<Elem>::value      // Elem should be mutable
            && std::is_integral<Size>::value    // Size should be integral
        >
    >
    constexpr bin_edit_t(Elem* buffer, Size length) noexcept
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
    constexpr iterator       begin()  noexcept       { return data;        }
    constexpr iterator       end()    noexcept       { return data + size; }
    constexpr const_iterator cbegin() const noexcept { return data;        }
    constexpr const_iterator cend()   const noexcept { return data + size; }
}; // struct bin_edit_t

//-----------------------------------------------------------------------------

/** resizes a container, @sa auto_size_t::resize().
 * please write an overload for containers with different signature than:
 * Container::resize(size_t)
 * @sa resize(QByteArray&, size_t);
 */
template <
    typename Container,
    typename = decltype(std::declval<Container&>().resize(42))>
inline void
resize(Container& c, size_t new_size) {
    c.resize(new_size);
}

#if defined(QT_CORE_LIB)
template <>
inline void
resize(QByteArray& ba, size_t new_size) {
    ba.resize(static_cast<int>(new_size));
}
#endif

//-----------------------------------------------------------------------------


/** a resizing interface around a *contiguous* container.
 * accepts resizable containers such as: std::string, std::vector, QByteArray,
 * or any other container if mbedcrypto::resize<>(T&, size_t) is available for
 * it.
 *
 * usage:
 * @code
 * // given following function:
 * // std::error_code fn(auto_size_t&& out, bin_view_t in, ...);
 *
 * std::vector<uint8_t> output;
 * // or std::string    output;
 * // or QByteArray     output;
 * auto ec = fn(auto_size_t{output}, in, ...);
 *
 * // now output is automatically resized to optimum required size and also is
 * // filled with the proper data.
 * @endcode
 */
struct auto_size_t final : bin_edit_t
{
    template <
        typename Container,
        typename = decltype(mbedcrypto::resize(std::declval<Container&>(), 42)),
        typename = std::enable_if_t<std::is_constructible<bin_edit_t, Container&>::value>
    >
    explicit auto_size_t(Container& ref) // no heap allocation
        : pimpl_{/*placement*/ new (stack_) model_t<Container>{*this, ref}} {}

    auto_size_t() noexcept              = delete;
    auto_size_t(const auto_size_t&)     = delete;
    auto_size_t(auto_size_t&&) noexcept = delete;

    ~auto_size_t() { pimpl_->~concept_t(); }

    void resize(size_t new_size) { pimpl_->resize(*this, new_size); }

protected:
    // type-erased and generic concept (duck-typing) for resizable containers
    struct concept_t {
        virtual ~concept_t() = default;
        virtual void resize(bin_edit_t&, size_t) = 0;
    };

    template <typename Container>
    struct model_t final : concept_t {
        Container& container;
        explicit model_t(bin_edit_t& self, Container& c) : container{c} {
            assign(self);
        }
        void resize(bin_edit_t& self, size_t new_size) override {
            mbedcrypto::resize(container, new_size);
            assign(self);
        }
        void assign(bin_edit_t& self) {
            self.data = reinterpret_cast<uint8_t*>(&container[0]);
            self.size = container.size();
        }
    };

    static constexpr size_t Size_     = 2 * sizeof(void*);
    alignas(void*) char stack_[Size_] = {};
    concept_t* pimpl_                 = nullptr;
}; // struct auto_size_t

//-----------------------------------------------------------------------------

constexpr inline bin_view_t::bin_view_t(const bin_edit_t& be) noexcept
    : bin_view_t{be.data, be.size} {}

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
