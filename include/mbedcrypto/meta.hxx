/** @file meta.hxx
 *
 * @copyright (C) 2019
 * @date 2019.10.12
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef MBEDCRYPTO_META_HXX
#define MBEDCRYPTO_META_HXX

#include <type_traits>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

// help c++14 for missing tools
template <typename...>
using void_t = void;

template<bool B>
using bool_constant = std::integral_constant<bool, B>;

//-----------------------------------------------------------------------------

// checks if T has a resize member function as: C::resize(size_t/int)
template <typename T, typename = void_t<>>
struct has_resize_mfn : std::false_type {};

template <typename T>
struct has_resize_mfn<T, void_t<decltype(std::declval<T>().resize(42))>>
    : std::true_type {};

//-----------------------------------------------------------------------------

// checks if T has writable buffer via operator[]
template <
    typename T,
    typename R = decltype(std::declval<T&>().operator[](8)),
    typename   = decltype(std::declval<T&>()[0] = 0)>
using has_writable_buffer_t = bool_constant<
    std::is_reference<R>::value &&
    sizeof(std::remove_reference_t<R>) == 1
>;

template <typename T, typename = void_t<>>
struct has_writable_buffer : std::false_type {};

template <typename T>
struct has_writable_buffer<T,
    void_t<std::enable_if_t<has_writable_buffer_t<T>::value>>
> : std::true_type {};

//-----------------------------------------------------------------------------

// checks if C is container with resize()/operator[]() member functions.
template <typename C>
using is_output_container = bool_constant<
    has_resize_mfn<C>::value && has_writable_buffer<C>::value
>;

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
#endif // MBEDCRYPTO_META_HXX
