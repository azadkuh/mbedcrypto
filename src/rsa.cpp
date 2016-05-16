#include "mbedcrypto/rsa.hpp"
#include "pk_private.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<rsa>::value == false, "");
static_assert(std::is_move_constructible<rsa>::value == true,  "");
///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
struct rsa::impl : public pk::context
{
}; // rsa::impl

///////////////////////////////////////////////////////////////////////////////
rsa::rsa() : pimpl(std::make_unique<impl>()) {
    pk::reset_as(*pimpl, pk_t::rsa);
}

rsa::~rsa() {
}

pk::context&
rsa::context() {
    return *pimpl;
}

const pk::context&
rsa::context() const {
    return *pimpl;
}

void
rsa::operator>>(struct rsa::key_info& ki)const {
    auto* rsa_ctx = mbedtls_pk_rsa(pimpl->pk_);
    ki.N << rsa_ctx->N;
    ki.E << rsa_ctx->E;

    // copies a an empty value if the key is not private
    ki.D  << rsa_ctx->D;
    ki.P  << rsa_ctx->P;
    ki.Q  << rsa_ctx->Q;
    ki.DP << rsa_ctx->DP;
    ki.DQ << rsa_ctx->DQ;
    ki.QP << rsa_ctx->QP;
}
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
