#include "mbedcrypto/ecp.hpp"
#include "pk_private.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<ecp>::value == false, "");
static_assert(std::is_move_constructible<ecp>::value == true,  "");
///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
struct ecp::impl : public pk::context
{
}; // ecp::impl

///////////////////////////////////////////////////////////////////////////////
ecp::ecp(pk_t ptype) : pimpl(std::make_unique<impl>()) {
    switch ( ptype ) {
        case pk_t::eckey:
        case pk_t::eckey_dh:
        case pk_t::ecdsa:
            pk::reset_as(*pimpl, pk_t::eckey);
            break;

        default:
            throw exceptions::usage_error{
                "invalid or unsupported ec type"
            };
            break;
    }
    pk::reset_as(*pimpl, ptype);
}

ecp::~ecp() {
}

pk::context&
ecp::context() {
    return *pimpl;
}

const pk::context&
ecp::context()const {
    return *pimpl;
}

struct ecp::key_info
ecp::key_info()const {
    struct ecp::key_info ki;
    auto* ec_ctx = mbedtls_pk_ec(pimpl->pk_);
    pk::context::mpi(ki.Qx, ec_ctx->Q.X);
    pk::context::mpi(ki.Qy, ec_ctx->Q.Y);
    pk::context::mpi(ki.Qz, ec_ctx->Q.Z);

    if ( pimpl->key_is_private_ ) {
        pk::context::mpi(ki.D, ec_ctx->d);
    }

    return ki;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////

