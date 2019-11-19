#include "./private/pk_context.hpp"

//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace pk {
namespace {
//-----------------------------------------------------------------------------

bool
is_supported(pk_t t) noexcept {
    switch (t) {
    case pk_t::rsa:
#if defined(MBEDCRYPTO_EC)
    case pk_t::eckey:
    case pk_t::eckey_dh:
    case pk_t::ecdsa:
#endif
        return true;
    default:
        return false;
    }
}

bool
is_rsa(pk_t t) noexcept {
    switch (t) {
    case pk_t::rsa:
    case pk_t::rsa_alt:
    case pk_t::rsassa_pss:
        return true;
    default:
        return false;
    }
}

bool
is_ec(pk_t t) noexcept {
    switch (t) {
    case pk_t::eckey:
    case pk_t::eckey_dh:
    case pk_t::ecdsa:
        return true;
    default:
        return false;
    }
}

bool
is_compatible(pk_t a, pk_t b) noexcept {
    return a == pk_t::unknown   // unknown (empty) is compatible with any type
        || b == pk_t::unknown
        || (is_rsa(a) && is_rsa(b)) // both have same type
        || (is_ec(a) && is_ec(b));
}

template <typename Func, class... Args>
std::error_code
open_key_impl(context& d, Func fn, Args&&... args) noexcept {
    const auto oldt = type_of(d);
    reset(d);
    int ret = fn(&d.pk, std::forward<Args>(args)...);
    if (ret != 0)
        return mbedtls::make_error_code(ret);
    // make sure the new key is compatible with previous type
    if (!is_compatible(type_of(d), oldt))
        return make_error_code(error_t::type);
    return std::error_code{};
}

size_t
min_pri_export_size(const context& d, key_io_t kio) noexcept {
    return 47 + (kio == key_io_t::pem ? 2 : 1) * key_size(d);
}

size_t
min_pub_export_size(const context& d, key_io_t kio) noexcept {
    return 47 + (kio == key_io_t::pem ? 2 : 1) * key_size(d);
}

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

void
reset(context& d) noexcept {
    d.has_pri_key = false;
    mbedtls_pk_free(&d.pk);
}

std::error_code
setup(context& d, pk_t neu) noexcept {
    reset(d);
    if (!is_supported(neu))
        return make_error_code(error_t::not_supported);
    int ret = mbedtls_pk_setup(&d.pk, find_native_info(neu));
    return ret == 0 ? std::error_code{} : mbedtls::make_error_code(ret);
}

bool
is_valid(const context& d) noexcept {
    return d.pk.pk_info               != nullptr
        && d.pk.pk_ctx                != nullptr
        && mbedtls_pk_get_type(&d.pk) != MBEDTLS_PK_NONE;
}

pk_t
type_of(const context& d) noexcept {
    return from_native(mbedtls_pk_get_type(&d.pk));
}

size_t
key_bitlen(const context& d) noexcept {
    return mbedtls_pk_get_bitlen(&d.pk);
}

size_t
key_size(const context& d) noexcept {
    return mbedtls_pk_get_len(&d.pk);
}

size_t
max_crypt_size(const context& d) noexcept {
    // padding and/or header data (11 bytes for PKCS#1 v1.5 padding).
    if (type_of(d) == pk_t::rsa)
        return key_size(d) - 11;
#   if defined(MBEDTLS_ECDSA_C)
    else if (can_do(d, pk_t::ecdsa))
        return (size_t)MBEDTLS_ECDSA_MAX_LEN;
#   endif
    return 0;
}

bool
has_private_key(const context& d) noexcept {
    return d.has_pri_key;
}

bool
can_do(const context& d, pk_t pt) noexcept {
    int ret = mbedtls_pk_can_do(&d.pk, to_native(pt));
    // refine by build options
    if (type_of(d) == pk_t::eckey && pt == pk_t::ecdsa) {
        if (!supports(pk_t::ecdsa))
            ret = 0;
    }
    return ret == 1;
}

capability
what_can_do(const context& d) noexcept {
    capability  c;
    const auto* info = d.pk.pk_info;
    if (info != nullptr && key_bitlen(d) > 0) {
        c.encrypt = info->encrypt_func != nullptr;
        c.decrypt = info->decrypt_func != nullptr;
        c.sign    = info->sign_func    != nullptr;
        c.verify  = info->verify_func  != nullptr;
        // refine by pub/pri key
        const auto type = type_of(d);
        if (type == pk_t::rsa && !d.has_pri_key)
            c.decrypt = c.sign = false;
        else if ((type == pk_t::eckey || type == pk_t::ecdsa) && !d.has_pri_key)
            c.sign = false;
    }
    return c;
}

bool
check_pair(const context& pub, const context& pri) noexcept {
    return mbedtls_pk_check_pair(&pub.pk, &pri.pk) == 0;
}

std::error_code
import_pri_key(context& d, bin_view_t pri, bin_view_t pass) noexcept {
    auto ec = open_key_impl(
        d, mbedtls_pk_parse_key, pri.data, pri.size, pass.data, pass.size);
    if (!ec)
        d.has_pri_key = true;
    return std::error_code{};
}

std::error_code
import_pub_key(context& d, bin_view_t pub) noexcept {
    return open_key_impl(d, mbedtls_pk_parse_public_key, pub.data, pub.size);
}

std::error_code
open_pri_key(context& d, const char* fpath, const char* pass) noexcept {
    auto ec = open_key_impl(d, mbedtls_pk_parse_keyfile, fpath, pass);
    if (!ec)
        d.has_pri_key = true;
    return std::error_code{};
}

std::error_code
open_pub_key(context& d, const char* fpath) noexcept {
    return open_key_impl(d, mbedtls_pk_parse_public_keyfile, fpath);
}

std::error_code
export_pri_key(bin_edit_t& out, context& d, key_io_t kio) noexcept {
#if defined(MBEDTLS_PK_WRITE_C)
    const auto min_size = min_pri_export_size(d, kio);
    if (is_empty(out)) {
        out.size = min_size;
    } else if (out.size < min_size) {
        return make_error_code(error_t::small_output);
    } else {
        int ret = 0;
        if (kio == key_io_t::pem) {
            ret = mbedtls_pk_write_key_pem(&d.pk, out.data, out.size);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
            out.size = std::strlen(reinterpret_cast<const char*>(out.data));
        } else {
            ret = mbedtls_pk_write_key_der(&d.pk, out.data, out.size);
            if (ret < 0)
                return mbedtls::make_error_code(ret);
            out.size = ret;
        }
    }
    return std::error_code{};
#else
    return make_error_code(error_t::not_supported);
#endif
}

std::error_code
export_pri_key(obuffer_t&& out, context& d, key_io_t kio) {
    bin_edit_t expected;
    const auto ec = export_pri_key(expected, d, kio);
    if (!ec)
        return ec;
    out.resize(expected.size);
    return export_pri_key(static_cast<bin_edit_t&>(out), d, kio);
}

std::error_code
export_pub_key(bin_edit_t& out, context& d, key_io_t kio) noexcept {
#if defined(MBEDTLS_PK_WRITE_C)
    const auto min_size = min_pub_export_size(d, kio);
    if (is_empty(out)) {
        out.size = min_size;
    } else if (out.size < min_size) {
        return make_error_code(error_t::small_output);
    } else {
        int ret = 0;
        if (kio == key_io_t::pem) {
            ret = mbedtls_pk_write_pubkey_pem(&d.pk, out.data, out.size);
            if (ret != 0)
                return mbedtls::make_error_code(ret);
            out.size = std::strlen(reinterpret_cast<const char*>(out.data));
        } else {
            ret = mbedtls_pk_write_pubkey_der(&d.pk, out.data, out.size);
            if (ret < 0)
                return mbedtls::make_error_code(ret);
            out.size = ret;
        }
    }
    return std::error_code{};
#else
    return make_error_code(error_t::not_supported);
#endif
}

std::error_code
export_pub_key(obuffer_t&& out, context& d, key_io_t kio) {
    bin_edit_t expected;
    const auto ec = export_pub_key(expected, d, kio);
    if (!ec)
        return ec;
    out.resize(expected.size);
    return export_pub_key(static_cast<bin_edit_t&>(out), d, kio);
}

//-----------------------------------------------------------------------------
} // namespace pk
} // namespace mbedcrypto
//-----------------------------------------------------------------------------

