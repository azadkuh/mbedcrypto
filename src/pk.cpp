#include "./private/pk_context.hpp"
#include "mbedcrypto/hash.hpp"

#include <mbedtls/ecdh.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace pk {
namespace {
//-----------------------------------------------------------------------------

void
_free_context(context* p) noexcept {
    if (p)
        delete p;
}

bool
_is_supported(pk_t t) noexcept {
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

// found by a linear interpolation of different rsa/ec * pem/der key samples
size_t
_pri_min_size(const context& d, key_io_t kio) noexcept {
    constexpr double m_rsa[] = {4.6, 6.2};
    constexpr double m_ec[]  = {3.0, 4.2};
    constexpr size_t c[]     = {32,  100};
    const auto&      m       = is_ec(type_of(d)) ? m_ec : m_rsa;
    const auto       i       = kio == key_io_t::der ? 0 : 1;
    const auto       ks      = key_size(d);
    return m[i] * ks + c[i];
}

// found by a linear interpolation of different rsa/ec * pem/der key samples
size_t
_pub_min_size(const context& d, key_io_t kio) noexcept {
    constexpr double m_rsa[] = {1.04, 1.4};
    constexpr double m_ec[]  = {2.0,  2.8};
    constexpr size_t c[]     = {32,   96};
    const auto&      m       = is_ec(type_of(d)) ? m_ec : m_rsa;
    const auto       i       = kio == key_io_t::der ? 0 : 1;
    const auto       ks      = key_size(d);
    return m[i] * ks + c[i];
}

// TODO: requires performance optimization, use memcpy instead of byte copy
void
_shift_left(bin_edit_t& be, size_t len) noexcept {
    auto* begin = be.data + len;
    be.size     = be.size - len;
    for (size_t i = 0; i < be.size; ++i) {
        be.data[i] = begin[i];
    }
}

std::error_code
_sign(bin_edit_t& out, context& d, bin_view_t input, hash_t ht) noexcept {
    const auto hsize    = hash_size(ht);
    const auto min_size = 16 + max_crypt_size(d);
    if (type_of(d) != pk_t::rsa && !can_do(d, pk_t::ecdsa)) {
        return make_error_code(error_t::bad_input);
    } else if (input.size != hsize) {
        return make_error_code(error_t::bad_input);
    } else if (is_empty(out)) {
        out.size = min_size;
    } else if (out.size < min_size) {
        return make_error_code(error_t::small_output);
    } else {
        auto olen = out.size;
        int  ret  = mbedtls_pk_sign(
            &d.pk,
            to_native(ht),
            input.data,
            input.size,
            out.data,
            &olen,
            ctr_drbg::make,
            &d.rnd);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        out.size = olen;
    }
    return std::error_code{};
}

std::error_code
_encrypt(bin_edit_t& out, context& d, bin_view_t input) noexcept {
    const auto csize    = max_crypt_size(d);
    const auto min_size = 16 + csize;
    if (!is_rsa(d) || key_bitlen(d) == 0 || input.size > csize) {
        return make_error_code(error_t::bad_input);
    } else if (is_empty(out)) {
        out.size = min_size;
    } else if (out.size < min_size) {
        return make_error_code(error_t::small_output);
    } else {
        size_t olen = out.size;
        int    ret  = mbedtls_pk_encrypt(
            &d.pk,
            input.data,
            input.size,
            out.data,
            &olen,
            out.size,
            ctr_drbg::make,
            &d.rnd);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        out.size = olen;
    }
    return std::error_code{};
}

std::error_code
_decrypt(bin_edit_t& out, context& d, bin_view_t input) noexcept {
    const auto min_size = 16 + max_crypt_size(d);
    if (!is_rsa(d) || !d.has_pri_key || (input.size << 3) > key_bitlen(d)) {
        return make_error_code(error_t::bad_input);
    } else if (is_empty(out)) {
        out.size = min_size;
    } else if (out.size < min_size) {
        return make_error_code(error_t::small_output);
    } else {
        size_t olen = out.size;
        int    ret  = mbedtls_pk_decrypt(
            &d.pk,
            input.data,
            input.size,
            out.data,
            &olen,
            out.size,
            ctr_drbg::make,
            &d.rnd);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        out.size = olen;
    }
    return std::error_code{};
}

std::error_code
_export_pri_key(bin_edit_t& out, context& d, key_io_t kio) noexcept {
    const auto min_size = _pri_min_size(d, kio);
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
            _shift_left(out, static_cast<size_t>(out.size - ret));
        }
    }
    return std::error_code{};
}

std::error_code
_export_pub_key(bin_edit_t& out, context& d, key_io_t kio) noexcept {
    const auto min_size = _pub_min_size(d, kio);
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
            _shift_left(out, static_cast<size_t>(out.size - ret));
        }
    }
    return std::error_code{};
}

template <typename Func, class... Args>
std::error_code
_open_key(context& d, Func fn, Args&&... args) noexcept {
    d.reset();
    int ret = fn(&d.pk, std::forward<Args>(args)...);
    return (ret != 0) ? mbedtls::make_error_code(ret) : std::error_code{};
}

template <typename Func, class... Args>
std::error_code
_resize_impl(Func fn, obuffer_t&& out, Args&&... args) {
    bin_edit_t      expected;
    std::error_code ec = fn(expected, std::forward<Args>(args)...);
    if (ec)
        return ec;
    out.resize(expected.size);
    ec = fn(static_cast<bin_edit_t&>(out), std::forward<Args>(args)...);
    if (!ec)
        out.resize(out.size); // final tuning/trimming
    return ec;
}

//-----------------------------------------------------------------------------
#if defined(MBEDTLS_ECP_C)
//-----------------------------------------------------------------------------

mbedtls_ecp_keypair*
_keypair_of(const context& d) noexcept {
    return mbedtls_pk_ec(d.pk);
}

struct ecdh_context {
    mbedtls_ecdh_context ctx;
    ecdh_context() noexcept {
        mbedtls_ecdh_init(&ctx);
    }
    ~ecdh_context() {
        mbedtls_ecdh_free(&ctx);
    }
};

std::error_code
_export_ec_pub_point(bin_edit_t& out, context& d, ec_point_t fmt) noexcept {
    if (!can_do(d, pk_t::ecdh))
        return make_error_code(error_t::not_supported);
    const int zip = fmt.compressed ? MBEDTLS_ECP_PF_COMPRESSED
                                   : MBEDTLS_ECP_PF_UNCOMPRESSED;
    const auto min_len = (key_size(d) + 2) * (fmt.compressed ? 1 : 2);
    if (min_len < 26) { // absolute minimum
        return make_error_code(error_t::bad_input);
    } else if (is_empty(out)) {
        out.size = min_len;
    } else if (out.size < min_len) {
        return make_error_code(error_t::small_output);
    } else {
        const auto*  ecpair = _keypair_of(d);
        ecdh_context ecdh;
        int ret = mbedtls_ecdh_get_params(&ecdh.ctx, ecpair, MBEDTLS_ECDH_OURS);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        size_t olen = 0;
        ret         = (fmt.pack == ec_point_t::tls)
                  ? mbedtls_ecp_tls_write_point(
                        &ecdh.ctx.grp,
                        &ecdh.ctx.Q,
                        zip,
                        &olen,
                        out.data,
                        out.size)
                  : mbedtls_ecp_point_write_binary(
                        &ecdh.ctx.grp,
                        &ecdh.ctx.Q,
                        zip,
                        &olen,
                        out.data,
                        out.size);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        out.size = olen;
    }
    return std::error_code{};
}

std::error_code
_make_shared_secret(
    bin_edit_t& out, context& d, bin_view_t opub, ec_point_t fmt) noexcept {
    if (!can_do(d, pk_t::ecdh) || fmt.compressed)
        return make_error_code(error_t::not_supported);
    const auto min_len = key_size(d) + 1;
    if (min_len < 25) { // absolute minimum
        return make_error_code(error_t::bad_input);
    } else if (is_empty(out)) {
        out.size = min_len;
    } else if (out.size < min_len) {
        return make_error_code(error_t::small_output);
    } else {
        const auto*  ecpair = _keypair_of(d);
        ecdh_context ecdh;
        int ret = mbedtls_ecdh_get_params(&ecdh.ctx, ecpair, MBEDTLS_ECDH_OURS);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        const auto* begin = opub.data;
        ret               = (fmt.pack == ec_point_t::tls)
                  ? mbedtls_ecp_tls_read_point(
                        &ecdh.ctx.grp, &ecdh.ctx.Qp, &begin, opub.size)
                  : mbedtls_ecp_point_read_binary(
                        &ecdh.ctx.grp, &ecdh.ctx.Qp, begin, opub.size);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        size_t olen = 0;
        ret         = mbedtls_ecdh_calc_secret(
            &ecdh.ctx, &olen, out.data, out.size, ctr_drbg::make, &d.rnd);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
        out.size = olen;
    }
    return std::error_code{};
}

//-----------------------------------------------------------------------------
#endif // MBEDTLS_ECP_C
//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

curve_info_t
curve_info(curve_t c) noexcept {
    curve_info_t ci;
    const auto*  ninfo = mbedtls_ecp_curve_info_from_grp_id(to_native(c));
    if (ninfo) {
        ci.tls_id = ninfo->tls_id;
        ci.bitlen = ninfo->bit_size;
    }
    return ci;
}

unique_context
make_context() {
    auto* ptr = new context{};
    return {ptr, _free_context};
}

std::error_code
setup(context& d, pk_t neu) noexcept {
    d.reset();
    if (!_is_supported(neu))
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
make_ec_key(context& d, pk_t algo, curve_t curve) noexcept {
#if defined(MBEDTLS_ECP_C)
    if (!is_ec(algo) || curve == curve_t::unknown)
        return make_error_code(error_t::usage);
    if (curve == curve_t::curve25519 && algo != pk_t::ecdh)
        return make_error_code(error_t::usage);
    // resets previous states
    auto ec = pk::setup(d, algo);
    if (ec)
        return ec;
    int ret = mbedtls_ecp_gen_key(
        to_native(curve), _keypair_of(d), ctr_drbg::make, &d.rnd);
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
verify(context& d, bin_view_t hash_msg, hash_t ht, bin_view_t sig) noexcept {
    const auto hsize = hash_size(ht);
    if (hash_msg.size != hsize || sig.size < hsize) {
        return make_error_code(error_t::bad_input);
    } else if (type_of(d) != pk_t::rsa && !can_do(d, pk_t::ecdsa)) {
        return make_error_code(error_t::bad_input);
    } else {
        int ret = mbedtls_pk_verify(
            &d.pk,
            to_native(ht),
            hash_msg.data,
            hash_msg.size,
            sig.data,
            sig.size);
        if (ret != 0)
            return mbedtls::make_error_code(ret);
    }
    return std::error_code{};
}

std::error_code
sign(bin_edit_t& out, context& d, bin_view_t input, hash_t ht) noexcept {
    return _sign(out, d, input, ht);
}

std::error_code
sign(obuffer_t&& out, context& d, bin_view_t input, hash_t ht) {
    return _resize_impl(_sign, std::forward<obuffer_t>(out), d, input, ht);
}

std::error_code
encrypt(bin_edit_t& out, context& d, bin_view_t input) noexcept {
    return _encrypt(out, d, input);
}

std::error_code
encrypt(obuffer_t&& out, context& d, bin_view_t input) {
    return _resize_impl(_encrypt, std::forward<obuffer_t>(out), d, input);
}

std::error_code
decrypt(bin_edit_t& out, context& d, bin_view_t input) noexcept {
    return _decrypt(out, d, input);
}

std::error_code
decrypt(obuffer_t&& out, context& d, bin_view_t input) {
    return _resize_impl(_decrypt, std::forward<obuffer_t>(out), d, input);
}

std::error_code
import_pri_key(context& d, bin_view_t pri, bin_view_t pass) noexcept {
    auto ec = _open_key(
        d, mbedtls_pk_parse_key, pri.data, pri.size, pass.data, pass.size);
    if (!ec)
        d.has_pri_key = true;
    return ec;
}

std::error_code
import_pub_key(context& d, bin_view_t pub) noexcept {
    return _open_key(d, mbedtls_pk_parse_public_key, pub.data, pub.size);
}

std::error_code
open_pri_key(context& d, const char* fpath, const char* pass) noexcept {
    auto ec = _open_key(d, mbedtls_pk_parse_keyfile, fpath, pass);
    if (!ec)
        d.has_pri_key = true;
    return ec;
}

std::error_code
open_pub_key(context& d, const char* fpath) noexcept {
    return _open_key(d, mbedtls_pk_parse_public_keyfile, fpath);
}

std::error_code
export_pri_key(bin_edit_t& out, context& d, key_io_t kio) noexcept {
    return _export_pri_key(out, d, kio);
}

std::error_code
export_pri_key(obuffer_t&& out, context& d, key_io_t kio) {
    return _resize_impl(_export_pri_key, std::forward<obuffer_t>(out), d, kio);
}

std::error_code
export_pub_key(bin_edit_t& out, context& d, key_io_t kio) noexcept {
    return _export_pub_key(out, d, kio);
}

std::error_code
export_pub_key(obuffer_t&& out, context& d, key_io_t kio) {
    return _resize_impl(_export_pub_key, std::forward<obuffer_t>(out), d, kio);
}

std::error_code
export_pub_key(bin_edit_t& out, context& d, ec_point_t fmt) noexcept {
#if defined(MBEDTLS_ECP_C)
    return _export_ec_pub_point(out, d, fmt);
#else
    return make_error_code(error_t::not_supported);
#endif
}

std::error_code
export_pub_key(obuffer_t&& out, context& d, ec_point_t fmt) {
#if defined(MBEDTLS_ECP_C)
    return _resize_impl(_export_ec_pub_point, std::forward<obuffer_t>(out), d, fmt);
#else
    return make_error_code(error_t::not_supported);
#endif
}

std::error_code
make_shared_secret(
    bin_edit_t& out, context& d, bin_view_t opub, ec_point_t fmt) noexcept {
#if defined(MBEDTLS_ECP_C)
    return _make_shared_secret(out, d, opub, fmt);
#else
    return make_error_code(error_t::not_supported);
#endif
}

std::error_code
make_shared_secret(
    obuffer_t&& out, context& d, bin_view_t opub, ec_point_t fmt) {
#if defined(MBEDTLS_ECP_C)
    return _resize_impl(
        _make_shared_secret, std::forward<obuffer_t>(out), d, opub, fmt);
#else
    return make_error_code(error_t::not_supported);
#endif
}

//-----------------------------------------------------------------------------
} // namespace pk
} // namespace mbedcrypto
//-----------------------------------------------------------------------------

