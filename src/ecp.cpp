#include "mbedcrypto/ecp.hpp"
#include "pk_private.hpp"

#if defined(MBEDTLS_ECP_C)

#include "mbedtls/ecdh.h"

///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<ecp>::value == false, "");
static_assert(std::is_move_constructible<ecp>::value == true,  "");

static_assert(std::is_copy_constructible<ecdsa>::value == false, "");
static_assert(std::is_move_constructible<ecdsa>::value == true,  "");
static_assert(std::is_copy_constructible<ecdh>::value  == false, "");
static_assert(std::is_move_constructible<ecdh>::value  == true,  "");

enum K {
    psk_length = 150,
};
///////////////////////////////////////////////////////////////////////////////
void
copy_from(mbedtls_ecp_group& a, const mbedtls_ecp_group& b) {
    mbedcrypto_c_call(mbedtls_ecp_group_copy, &a, &b);
}

void
copy_from(mbedtls_ecp_point& a, const mbedtls_ecp_point& b) {
    mbedcrypto_c_call(mbedtls_ecp_copy, &a, &b);
}

void
copy_from(mbedtls_mpi& a, const mbedtls_mpi& b) {
    mbedcrypto_c_call(mbedtls_mpi_copy, &a, &b);
}

void
copy_from(pk::context& ctx, const mbedtls_ecdh_context* ecdh) {
    auto* keypair = mbedtls_pk_ec(ctx.pk_);
    copy_from(keypair->grp, ecdh->grp);
    copy_from(keypair->Q,   ecdh->Q);
    copy_from(keypair->d,   ecdh->d);
}

void
copy_from(mbedtls_ecdh_context* ecdh, const pk::context& ctx) {
    const auto* keypair = mbedtls_pk_ec(ctx.pk_);
    copy_from(ecdh->grp, keypair->grp);
    copy_from(ecdh->Q,   keypair->Q);
    copy_from(ecdh->d,   keypair->d);
}

size_t
write_ecp_point(
    const mbedtls_ecdh_context* ecdh,
    unsigned char*              buffer,
    size_t                      buffer_length) {
    size_t olen = 0;

    mbedcrypto_c_call(
        mbedtls_ecp_tls_write_point,
        &ecdh->grp,
        &ecdh->Q,
        ecdh->point_format,
        &olen,
        buffer,
        buffer_length);

    return olen;
}

size_t
write_ecp_group(
    const mbedtls_ecp_group* grp, unsigned char* buffer, size_t buffer_length) {
    size_t olen = 0;

    mbedcrypto_c_call(
        mbedtls_ecp_tls_write_group, grp, &olen, buffer, buffer_length);

    return olen;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
struct ecp::impl : public pk::context {
    // only if the ecp is an eckey_dh
    std::unique_ptr<mbedtls_ecdh_context> ecdh_{nullptr};

    ~impl() {
        if (ecdh_) // only if ecdh_ is valid
            mbedtls_ecdh_free(ecdh_.get());
    }

    void ecdh_generate_keys(curve_t ctype) {
        mbedcrypto_c_call(
            mbedtls_ecp_group_load, &ecdh_->grp, to_native(ctype));

        ecdh_gen_public();
    }

    auto ecdh_public_point() {
        buffer_t mypub(psk_length, '\0');
        size_t   olen = write_ecp_point(ecdh_.get(), to_ptr(mypub), psk_length);
        mypub.resize(olen);
        return mypub;
    }

    auto ecdh_server_key_exchange() {
        buffer_t skex(psk_length, '\0');
        auto*    buf = to_ptr(skex);
        size_t   cap = psk_length;

        auto glen = write_ecp_group(&ecdh_->grp, buf, cap);
        buf += glen;
        cap -= glen;

        auto plen = write_ecp_point(ecdh_.get(), buf, cap);

        skex.resize(glen + plen);
        return skex;
    }

    auto ecdh_client_peer_key(const buffer_t& skex) {
        const unsigned char* p = to_const_ptr(skex);
        mbedcrypto_c_call(
            mbedtls_ecdh_read_params, ecdh_.get(), &p, p + skex.size());

        ecdh_gen_public();
    }

    // the peer's public key is already loaded
    auto ecdh_calc_secret() {
        buffer_t secret(psk_length, '\0');
        size_t   olen = 0;
        mbedcrypto_c_call(
            mbedtls_ecdh_calc_secret,
            ecdh_.get(),
            &olen,
            to_ptr(secret),
            psk_length,
            rnd_generator::maker,
            &rnd_);

        secret.resize(olen);
        return secret;
    }

    auto ecdh_calc_secret(const buffer_t& otherpub) {
        mbedcrypto_c_call(
            mbedtls_ecdh_read_public,
            ecdh_.get(),
            to_const_ptr(otherpub),
            otherpub.size());

        return ecdh_calc_secret();
    }

private:
    void ecdh_gen_public() {
        if (key_is_private_) { // if there is a key
            pk::reset_as(*this, pk_t::eckey_dh);
        }

        mbedcrypto_c_call(
            mbedtls_ecdh_gen_public,
            &ecdh_->grp,
            &ecdh_->d,
            &ecdh_->Q,
            mbedcrypto::rnd_generator::maker,
            &rnd_);

        // the private key has been built
        copy_from(*this, ecdh_.get()); // copy keypair to pk_ context
        key_is_private_ = true;
    }

}; // ecp::impl
///////////////////////////////////////////////////////////////////////////////
ecp::ecp(pk_t ptype) : pimpl(std::make_unique<impl>()) {
    switch (ptype) {
    case pk_t::eckey:
    case pk_t::ecdsa:
        pk::reset_as(*pimpl, ptype);
        break;

    case pk_t::eckey_dh:
        pimpl->ecdh_ = std::make_unique<mbedtls_ecdh_context>();
        mbedtls_ecdh_init(pimpl->ecdh_.get());
        pk::reset_as(*pimpl, ptype);
        break;

    default:
        throw exceptions::usage_error{"invalid or unsupported ec type"};
        break;
    }
}

ecp::~ecp() {}

pk::context&
ecp::context() {
    return *pimpl;
}

const pk::context&
ecp::context() const {
    return *pimpl;
}

void
ecp::operator>>(struct ecp::key_info& ki) const {
    const auto* ec_ctx = mbedtls_pk_ec(pimpl->pk_);
    ki.Qx << ec_ctx->Q.X;
    ki.Qy << ec_ctx->Q.Y;
    ki.Qz << ec_ctx->Q.Z;

    // copies a an empty value if the key is not private
    ki.d << ec_ctx->d;
}

///////////////////////////////////////////////////////////////////////////////
buffer_t
ecdh::make_peer_key(curve_t ctype) {
    pimpl->ecdh_generate_keys(ctype);
    return pimpl->ecdh_public_point();
}

buffer_t
ecdh::peer_key() {
    if (!has_private_key())
        throw exceptions::usage_error{"ecdh has no key"};

    copy_from(pimpl->ecdh_.get(), *pimpl);
    return pimpl->ecdh_public_point();
}

buffer_t
ecdh::shared_secret(const buffer_t& peer_pub) {
    return pimpl->ecdh_calc_secret(peer_pub);
}

buffer_t
ecdh::shared_secret() {
    return pimpl->ecdh_calc_secret();
}

buffer_t
ecdh::make_server_key_exchange(curve_t ctype) {
    pimpl->ecdh_generate_keys(ctype);
    return pimpl->ecdh_server_key_exchange();
}

buffer_t
ecdh::make_client_peer_key(const buffer_t& server_key_exchange) {
    pimpl->ecdh_client_peer_key(server_key_exchange);
    return pimpl->ecdh_public_point();
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDTLS_ECP_C
