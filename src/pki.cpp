#include "mbedcrypto/pki.hpp"
#include "mbedcrypto/random.hpp"
#include "conversions.hpp"

#include "mbedtls/pk.h"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<pki>::value == false, "");
static_assert(std::is_move_constructible<pki>::value == true, "");

const mbedtls_pk_info_t*
native_info(pk_t type) {
    auto ntype         = to_native(type);
    const auto* pinfot = mbedtls_pk_info_from_type(ntype);

    if ( pinfot == nullptr )
        throw exception(
                MBEDTLS_ERR_PK_UNKNOWN_PK_ALG, "unsupported pki"
                );

    return pinfot;
}

bool
ends_with(const buffer_t& str, char c) {
    return str.rfind(c) == str.size()-1;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

struct pki::impl
{
    mbedtls_pk_context ctx_;

    explicit impl() {
        mbedtls_pk_init(&ctx_);
    }

    ~impl() {
        mbedtls_pk_free(&ctx_);
    }

    void setup(pk_t type) {
        const auto* pinfot = native_info(type);
        c_call(mbedtls_pk_setup,
                &ctx_,
                pinfot
              );
    }


}; // pki::impl

///////////////////////////////////////////////////////////////////////////////

pki::pki() : pimpl(std::make_unique<impl>()) {}

pki::pki(pk_t type) : pimpl(std::make_unique<impl>()) {
    pimpl->setup(type);
}

pki::~pki() {
}

pk_t
pki::type()const noexcept {
    return from_native(
            mbedtls_pk_get_type(&pimpl->ctx_)
            );
}

void
pki::parse_key(const buffer_t& private_key, const buffer_t& password) {
    if ( !ends_with(private_key, '\0') )
        throw exception("private key data must be ended by null byte");

    // resets
    mbedtls_pk_free(&pimpl->ctx_);

    const auto* ppass = (password.size() != 0) ?
        reinterpret_cast<const unsigned char*>(password.data()) : nullptr;

    c_call(mbedtls_pk_parse_key,
            &pimpl->ctx_,
            reinterpret_cast<const unsigned char*>(private_key.data()),
            private_key.size(),
            ppass,
            password.size()
          );
}

void
pki::parse_public_key(const buffer_t& public_key) {
    if ( !ends_with(public_key, '\0') )
        throw exception("private key data must be ended by null byte");

    // resets
    mbedtls_pk_free(&pimpl->ctx_);

    c_call(mbedtls_pk_parse_public_key,
        &pimpl->ctx_,
        reinterpret_cast<const unsigned char*>(public_key.data()),
        public_key.size()
        );
}

bool
pki::can_do(pk_t type) const noexcept {
    return mbedtls_pk_can_do(&pimpl->ctx_, to_native(type)) == 1;
}

size_t
pki::bitlen()const {
    int ret = mbedtls_pk_get_bitlen(&pimpl->ctx_);
    if ( ret == 0 )
        throw exception("failed to determine the key bit size");

    return size_t(ret);
}

size_t
pki::length()const {
    int ret = mbedtls_pk_get_len(&pimpl->ctx_);
    if ( ret == 0 )
        throw exception("failed to determine the key size");

    return size_t(ret);
}

bool
pki::verify(hash_t hash_type, const buffer_t& hash_value,
        const buffer_t& signature) {
    int ret = mbedtls_pk_verify(&pimpl->ctx_,
            to_native(hash_type),
            reinterpret_cast<const unsigned char*>(hash_value.data()),
            hash_value.size(),
            reinterpret_cast<const unsigned char*>(signature.data()),
            signature.size()
            );

    // TODO: check when to report other errors
    switch ( ret ) {
        case 0:
            return true;

        case MBEDTLS_ERR_PK_BAD_INPUT_DATA:
        case MBEDTLS_ERR_PK_TYPE_MISMATCH:
                throw exception(ret, "failed to verify the signature");
                break;
        default:
            break;
    }

    return false;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////