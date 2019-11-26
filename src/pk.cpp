#include "./private/pk_context.hpp"

//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace pk {
namespace {
//-----------------------------------------------------------------------------

void
free_context(context* p) noexcept {
    if (p)
        delete p;
}

bool
is_supported(pk_t t) noexcept {
    switch (t) {
    case pk_t::rsa:
#if defined(MBEDCRYPTO_PK_EC)
    case pk_t::ec:
    case pk_t::ecdh:
    case pk_t::ecdsa:
#endif
        return true;
    default:
        return false;
    }
}

template <typename Func, class... Args>
std::error_code
open_key_impl(context& d, Func fn, Args&&... args) noexcept {
    d.reset();
    int ret = fn(&d.pk, std::forward<Args>(args)...);
    return (ret != 0) ? mbedtls::make_error_code(ret) : std::error_code{};
}

size_t
min_pri_export_size(const context& d, key_io_t kio) noexcept {
    return (kio == key_io_t::pem ? 2 : 1) * key_size(d) * 5;
}

size_t
min_pub_export_size(const context& d, key_io_t kio) noexcept {
    return 47 + (kio == key_io_t::pem ? 2 : 1) * key_size(d);
}

// TODO: requires performance optimization, use memcpy instead of byte copy
void
shift_left(bin_edit_t& be, size_t len) noexcept {
    auto* begin = be.data + len;
    be.size     = be.size - len;
    for (size_t i = 0; i < be.size; ++i) {
        be.data[i] = begin[i];
    }
}

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

pk::unique_ptr
make_context() {
    auto* ptr = new context{};
    return {ptr, free_context};
}

std::error_code
setup(context& d, pk_t neu) noexcept {
    d.reset();
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
        return static_cast<size_t>(MBEDTLS_ECDSA_MAX_LEN);
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
    if (type_of(d) == pk_t::ec && pt == pk_t::ecdsa) {
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
        else if ((type == pk_t::ec || type == pk_t::ecdsa) && !d.has_pri_key)
            c.sign = false;
    }
    return c;
}

bool
is_pri_pub_pair(const context& pri, const context& pub) noexcept {
    return mbedtls_pk_check_pair(&pub.pk, &pri.pk) == 0;
}

std::error_code
make_rsa_key(context& d, size_t kbits, size_t expo) noexcept {
#if defined(MBEDTLS_GENPRIME)
    // resets previous states
    auto ec = pk::setup(d, pk_t::rsa);
    if (ec)
        return ec;
    int ret = mbedtls_rsa_gen_key(
        mbedtls_pk_rsa(d.pk),
        ctr_drbg::make,
        &d.rnd,
        static_cast<unsigned int>(kbits),
        static_cast<int>(expo));
    if (ret != 0)
        return mbedtls::make_error_code(ret);
    // set the key type
    d.has_pri_key = true;
    return ec;
#else  // MBEDTLS_GENPRIME
    return make_error_code(error_t::not_supported);
#endif // MBEDTLS_GENPRIME
}

std::error_code
make_ec_key(context& d, curve_t curve) noexcept {
#if defined(MBEDTLS_ECP_C)
    // resets previous states
    auto ec = pk::setup(d, pk_t::ec);
    if (ec)
        return ec;
    int ret = mbedtls_ecp_gen_key(
        to_native(curve), mbedtls_pk_ec(d.pk), ctr_drbg::make, &d.rnd);
    if (ret != 0)
        return mbedtls::make_error_code(ret);
    // set the key type
    d.has_pri_key = true;
    return ec;
#else  // MBEDTLS_ECP_C
    return make_error_code(error_t::not_supported);
#endif // MBEDTLS_ECP_C
}

std::error_code
import_pri_key(context& d, bin_view_t pri, bin_view_t pass) noexcept {
    auto ec = open_key_impl(
        d, mbedtls_pk_parse_key, pri.data, pri.size, pass.data, pass.size);
    if (!ec)
        d.has_pri_key = true;
    return ec;
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
    return ec;
}

std::error_code
open_pub_key(context& d, const char* fpath) noexcept {
    return open_key_impl(d, mbedtls_pk_parse_public_keyfile, fpath);
}

std::error_code
export_pri_key(bin_edit_t& out, context& d, key_io_t kio) noexcept {
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
            // the null terminator is also required
            out.size = std::strlen(reinterpret_cast<const char*>(out.data)) + 1;
        } else {
            ret = mbedtls_pk_write_key_der(&d.pk, out.data, out.size);
            if (ret < 0)
                return mbedtls::make_error_code(ret);
            shift_left(out, static_cast<size_t>(out.size - ret));
        }
    }
    return std::error_code{};
}

std::error_code
export_pri_key(obuffer_t&& out, context& d, key_io_t kio) {
    bin_edit_t expected;
    auto       ec = export_pri_key(expected, d, kio);
    if (ec)
        return ec;
    out.resize(expected.size);
    ec = export_pri_key(static_cast<bin_edit_t&>(out), d, kio);
    if (!ec)
        out.resize(out.size);
    return ec;
}

std::error_code
export_pub_key(bin_edit_t& out, context& d, key_io_t kio) noexcept {
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
            // the null terminator is also required
            out.size = std::strlen(reinterpret_cast<const char*>(out.data)) + 1;
        } else {
            ret = mbedtls_pk_write_pubkey_der(&d.pk, out.data, out.size);
            if (ret < 0)
                return mbedtls::make_error_code(ret);
            shift_left(out, static_cast<size_t>(out.size - ret));
        }
    }
    return std::error_code{};
}

std::error_code
export_pub_key(obuffer_t&& out, context& d, key_io_t kio) {
    bin_edit_t expected;
    auto       ec = export_pub_key(expected, d, kio);
    if (ec)
        return ec;
    out.resize(expected.size);
    ec = export_pub_key(static_cast<bin_edit_t&>(out), d, kio);
    if (!ec)
        out.resize(out.size);
    return ec;
}

//-----------------------------------------------------------------------------
} // namespace pk
} // namespace mbedcrypto
//-----------------------------------------------------------------------------

