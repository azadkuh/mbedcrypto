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

struct rsa::key_info
rsa::key_info()const {
    struct key_info ki;
    auto* rsa_ctx = mbedtls_pk_rsa(pimpl->pk_);
    pk::context::mpi(ki.N, rsa_ctx->N);
    pk::context::mpi(ki.E, rsa_ctx->E);

    if ( pimpl->key_is_private_ ) {
        pk::context::mpi(ki.D,  rsa_ctx->D);
        pk::context::mpi(ki.P,  rsa_ctx->P);
        pk::context::mpi(ki.Q,  rsa_ctx->Q);
        pk::context::mpi(ki.DP, rsa_ctx->DP);
        pk::context::mpi(ki.DQ, rsa_ctx->DQ);
        pk::context::mpi(ki.QP, rsa_ctx->QP);
    }

    return ki;
}
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
