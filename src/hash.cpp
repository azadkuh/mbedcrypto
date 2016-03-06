#include "mbedcrypto/hash.hpp"
#include "conversions.hpp"

#include <type_traits>
#include "mbedtls/md.h"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<hash>::value == false, "");
static_assert(std::is_move_constructible<hash>::value == false, "");

const mbedtls_md_info_t*
native_type(hash_t type) {
    const auto* info = mbedtls_md_info_from_type(to_native(type));
    if ( info == nullptr )
        throw exception(MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE, "unimplemented type");

    return info;
}

auto
digest_pair(hash_t type) {
    const auto* cinfot = native_type(type);
    size_t length      = mbedtls_md_get_size(cinfot);

    return std::make_tuple(cinfot, buffer_t(length, '\0'));
}

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

class hash::impl
{
public:

}; // hash::impl
///////////////////////////////////////////////////////////////////////////////

hash::hash() : d_ptr(new hash::impl{}) {
}

hash::~hash() {
}

size_t
hash::length(hash_t type) {
    const auto* cinfot = native_type(type);
    return mbedtls_md_get_size(cinfot);
}

buffer_t
hash::make(hash_t type, const buffer_t& src) {
    auto digest = digest_pair(type);

    int ret = mbedtls_md(
            std::get<0>(digest),
            reinterpret_cast<const unsigned char*>(src.data()), src.size(),
            reinterpret_cast<unsigned char*>(&std::get<1>(digest).front())
            );

    if ( ret != 0 )
        throw exception(ret, "failed to compute digest");

    return std::get<1>(digest);
}

buffer_t
hash::of_file(hash_t type, const char* filePath) {
#if defined(MBEDTLS_FS_IO)
    auto digest = digest_pair(type);

    int ret = mbedtls_md_file(
            std::get<0>(digest),
            filePath,
            reinterpret_cast<unsigned char*>(&std::get<1>(digest).front())
            );

    if ( ret != 0 )
        throw exception(ret, "failed to compute file digest");

    return std::get<1>(digest);

#else
    throw exception("feature is not available in this build");

#endif
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
