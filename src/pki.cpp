#include "mbedcrypto/pki.hpp"
#include "mbedcrypto/hash.hpp"
#include "pk_private.hpp"

#include <cstring>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<pki>::value == false, "");
static_assert(std::is_move_constructible<pki>::value == true, "");

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

struct pki::impl : public pk::context
{
}; // pki::impl

///////////////////////////////////////////////////////////////////////////////

pki::pki() : pimpl(std::make_unique<impl>()) {}

pki::pki(pk_t type) : pimpl(std::make_unique<impl>()) {
    pk::reset_as(*pimpl, type);
}

pki::~pki() {
}

pk::context&
pki::context() {
    return *pimpl;
}

const pk::context&
pki::context() const {
    return *pimpl;
}

bool
pki::check_pair(const pki& pub, const pki& priv) {
    return pk::check_pair(*pub.pimpl, *priv.pimpl);
}

buffer_t
pki::sign(const buffer_t& h_m, hash_t halgo) {
    return pk::sign(*pimpl, h_m, halgo);
}

bool
pki::verify(const buffer_t& sig, const buffer_t& h_m, hash_t halgo) {
    return pk::verify(*pimpl, sig, h_m, halgo);
}

buffer_t
pki::encrypt(const buffer_t& h_m, hash_t halgo) {
    return pk::encrypt(*pimpl, h_m, halgo);
}

buffer_t
pki::decrypt(const buffer_t& enc) {
    return pk::decrypt(*pimpl, enc);
}
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
