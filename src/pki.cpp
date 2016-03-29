#include "mbedcrypto/pki.hpp"
#include "mbedcrypto/random.hpp"
#include "mbedcrypto/hash.hpp"
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

int
random_func(void* ctx, unsigned char* p, size_t len) {
    mbedcrypto::random* rnd = reinterpret_cast<mbedcrypto::random*>(ctx);
    return rnd->make(p, len);
}

class hm_prepare
{
    buffer_t hash_;

public:
    auto operator()(const pki* pk,
            hash_t halgo, const buffer_t& hmvalue) -> const buffer_t& {

        if ( halgo == hash_t::none ) {
            if ( (hmvalue.size() << 3) > pk->bitlen() )
                throw exception("the message is larger than the key size");

            return hmvalue;
        }

        hash_ = hash::make(halgo, hmvalue);
        return hash_;
    }
}; // hm_prepare

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

struct pki::impl
{
    mbedtls_pk_context ctx_;
    mbedcrypto::random rnd_;

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

const char*
pki::name()const noexcept {
    return mbedtls_pk_get_name(&pimpl->ctx_);
}

void
pki::parse_key(const buffer_t& private_key, const buffer_t& password) {
    if ( !ends_with(private_key, '\0') )
        throw exception("private key data must be ended by null byte");

    // resets
    mbedtls_pk_free(&pimpl->ctx_);

    const auto* ppass = (password.size() != 0) ? to_const_ptr(password) : nullptr;

    c_call(mbedtls_pk_parse_key,
            &pimpl->ctx_,
            to_const_ptr(private_key),
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
        to_const_ptr(public_key),
        public_key.size()
        );
}

void
pki::load_key(const char* file_path, const buffer_t& password) {
    #if !defined(MBEDTLS_FS_IO)
    throw exception("not implemented in current build system");
    #endif // MBEDTLS_FS_IO

    // resets
    mbedtls_pk_free(&pimpl->ctx_);

    const auto* ppass = (password.size() != 0) ? password.data() : nullptr;

    c_call(mbedtls_pk_parse_keyfile,
            &pimpl->ctx_,
            file_path,
            ppass
          );
}

void
pki::load_public_key(const char* file_path) {
    #if !defined(MBEDTLS_FS_IO)
    throw exception("not implemented in current build system");
    #endif // MBEDTLS_FS_IO

    // resets
    mbedtls_pk_free(&pimpl->ctx_);

    c_call(mbedtls_pk_parse_public_keyfile,
            &pimpl->ctx_,
            file_path
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

buffer_t
pki::sign(const buffer_t& hmvalue, hash_t halgo) {
    const auto& hvalue = hm_prepare{}(this, halgo, hmvalue);

    size_t olen = MBEDTLS_MPI_MAX_SIZE;
    buffer_t output(olen, '\0');
    c_call(mbedtls_pk_sign,
            &pimpl->ctx_,
            to_native(halgo),
            to_const_ptr(hvalue),
            hvalue.size(),
            to_ptr(output),
            &olen,
            random_func,
            &pimpl->rnd_
          );

    output.resize(olen);
    return output;
}

bool
pki::verify(const buffer_t& signature,
        const buffer_t& hm_value, hash_t hash_type) {
    const auto& hvalue = hm_prepare{}(this, hash_type, hm_value);

    int ret = mbedtls_pk_verify(&pimpl->ctx_,
            to_native(hash_type),
            to_const_ptr(hvalue),
            hvalue.size(),
            to_const_ptr(signature),
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

buffer_t
pki::encrypt(const buffer_t& hmvalue, hash_t hash_type) {
    const auto& hvalue = hm_prepare{}(this, hash_type, hmvalue);

    size_t olen = MBEDTLS_MPI_MAX_SIZE;
    buffer_t output(olen, '\0');
    c_call(mbedtls_pk_encrypt,
            &pimpl->ctx_,
            to_const_ptr(hvalue),
            hvalue.size(),
            to_ptr(output),
            &olen,
            olen,
            random_func,
            &pimpl->rnd_
          );

    output.resize(olen);
    return output;
}

buffer_t
pki::decrypt(const buffer_t& encrypted_value) {
    if ( (encrypted_value.size() << 3) > bitlen() )
        throw exception("the encrypted value is larger than the key size");

    size_t olen = MBEDTLS_MPI_MAX_SIZE;
    buffer_t output(olen, '\0');

    c_call(mbedtls_pk_decrypt,
            &pimpl->ctx_,
            to_const_ptr(encrypted_value),
            encrypted_value.size(),
            to_ptr(output),
            &olen,
            olen,
            random_func,
            &pimpl->rnd_
          );

    output.resize(olen);
    return output;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
