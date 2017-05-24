#include "mbedcrypto/hash.hpp"
#include "conversions.hpp"

#include "mbedtls/md.h"
#include <tuple>
#include <type_traits>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<hash>::value == false, "");
static_assert(std::is_move_constructible<hash>::value == true, "");
static_assert(std::is_copy_constructible<hmac>::value == false, "");
static_assert(std::is_move_constructible<hmac>::value == true, "");

const mbedtls_md_info_t*
native_type(hash_t type) {
    const auto* info = mbedtls_md_info_from_type(to_native(type));
    if (info == nullptr)
        throw exceptions::unknown_hash{};

    return info;
}

auto
digest_pair(hash_t type) {
    const auto* cinfot = native_type(type);
    size_t      length = mbedtls_md_get_size(cinfot);

    return std::make_tuple(cinfot, length);
}

template <class T, class Tuple>
T
_zero_initialized_buffer(const Tuple& p) {
    using length_t = decltype(T().size());
    return T(static_cast<length_t>(std::get<1>(p)), '\0');
}

template <class T>
T
_make(hash_t type, buffer_view_t src) {
    auto digest = digest_pair(type);
    auto buf    = _zero_initialized_buffer<T>(digest);

    mbedcrypto_c_call(
        mbedtls_md, std::get<0>(digest), src.data(), src.size(), to_ptr(buf));

    return buf;
}

template <class T>
T
_make(hash_t type, buffer_view_t key, buffer_view_t src) {
    auto digest = digest_pair(type);
    auto buf    = _zero_initialized_buffer<T>(digest);

    mbedcrypto_c_call(
        mbedtls_md_hmac,
        std::get<0>(digest),
        key.data(),
        key.size(),
        src.data(),
        src.size(),
        to_ptr(buf));

    return buf;
}
///////////////////////////////////////////////////////////////////////////////

struct impl_base {
    mbedtls_md_context_t ctx_;

    explicit impl_base() noexcept {
        mbedtls_md_init(&ctx_);
    }

    ~impl_base() {
        mbedtls_md_free(&ctx_);
    }

    void setup(hash_t type, bool hmac) {
        const auto* cinfot = native_type(type);
        mbedcrypto_c_call(mbedtls_md_setup, &ctx_, cinfot, (hmac) ? 1 : 0);
    }

    size_t size() const noexcept {
        if (ctx_.md_info == nullptr)
            return 0;

        return mbedtls_md_get_size(ctx_.md_info);
    }

}; // struct impl_base

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

struct hash::impl : public impl_base {};
struct hmac::impl : public impl_base {};

///////////////////////////////////////////////////////////////////////////////

hash::hash(hash_t type) : pimpl(new hash::impl) {
    pimpl->setup(type, false);
}

hash::~hash() {}

hmac::hmac(hash_t type) : pimpl(new hmac::impl) {
    pimpl->setup(type, true);
}

hmac::~hmac() {}

size_t
hash::length(hash_t type) {
    const auto* cinfot = native_type(type);
    return mbedtls_md_get_size(cinfot);
}

size_t
hash::length() const noexcept {
    return pimpl->size();
}

buffer_t
hash::make(hash_t type, buffer_view_t src) {
    return _make<buffer_t>(type, src);
}

buffer_t
hash::of_file(hash_t type, const char* filePath) {
#if defined(MBEDTLS_FS_IO)
    auto digest = digest_pair(type);
    buffer_t buf(std::get<1>(digest), '\0');

    mbedcrypto_c_call(
        mbedtls_md_file,
        std::get<0>(digest),
        filePath,
        to_ptr(buf));

    return buf;

#else
    throw support_exception{};

#endif
}

buffer_t
hmac::make(hash_t type, buffer_view_t key, buffer_view_t src) {
    return _make<buffer_t>(type, key, src);
}

void
hash::start() {
    mbedcrypto_c_call(mbedtls_md_starts, &pimpl->ctx_);
}

void
hash::update(const unsigned char* src, size_t length) {
    mbedcrypto_c_call(mbedtls_md_update, &pimpl->ctx_, src, length);
}

buffer_t
hash::finish() {
    buffer_t digest(pimpl->size(), '\0');
    mbedcrypto_c_call(mbedtls_md_finish, &pimpl->ctx_, to_ptr(digest));

    return digest;
}

void
hmac::start(buffer_view_t key) {
    mbedcrypto_c_call(
        mbedtls_md_hmac_starts, &pimpl->ctx_, key.data(), key.size());
}

void
hmac::start() {
    mbedcrypto_c_call(mbedtls_md_hmac_reset, &pimpl->ctx_);
}

void
hmac::update(const unsigned char* src, size_t length) {
    mbedcrypto_c_call(mbedtls_md_hmac_update, &pimpl->ctx_, src, length);
}

buffer_t
hmac::finish() {
    buffer_t digest(pimpl->size(), '\0');
    mbedcrypto_c_call(mbedtls_md_hmac_finish, &pimpl->ctx_, to_ptr(digest));

    return digest;
}

///////////////////////////////////////////////////////////////////////////////
#if defined(QT_CORE_LIB)
///////////////////////////////////////////////////////////////////////////////
QByteArray
hash::make(hash_t type, const QByteArray& src) {
    return _make<QByteArray>(type, src);
}

QByteArray
hmac::make(hash_t type, const QByteArray& key, const QByteArray& src) {
    return _make<QByteArray>(type, key, src);
}
///////////////////////////////////////////////////////////////////////////////
#endif // QT_CORE_LIB
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
