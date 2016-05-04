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

class hm_prepare
{
    buffer_t hash_;

public:
    auto operator()(const pki* pk,
            hash_t halgo, const buffer_t& hmvalue) -> const buffer_t& {

        if ( halgo == hash_t::none ) {
            if ( hmvalue.size() > pk->max_crypt_size() )
                throw usage_exception{"the message is larger than max_crypt_size()"};

            return hmvalue;
        }

        hash_ = hash::make(halgo, hmvalue);
        return hash_;
    }
}; // hm_prepare

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

size_t
pki::max_crypt_size()const {
    // padding / header data (11 bytes for PKCS#1 v1.5 padding).
    if ( type() == pk_t::rsa )
        return key_length() - 11;

    return key_length();

    // other pk types are note yet supported
    //throw support_exception{};
}

buffer_t
pki::sign(const buffer_t& hmvalue, hash_t halgo) {
    hm_prepare hm;
    const auto& hvalue = hm(this, halgo, hmvalue);

    size_t olen = 32 + max_crypt_size();
    buffer_t output(olen, '\0');
    mbedcrypto_c_call(mbedtls_pk_sign,
            &pimpl->pk_,
            to_native(halgo),
            to_const_ptr(hvalue),
            hvalue.size(),
            to_ptr(output),
            &olen,
            pk::random_func,
            &pimpl->rnd_
          );

    output.resize(olen);
    return output;
}

bool
pki::verify(const buffer_t& signature,
        const buffer_t& hm_value, hash_t hash_type) {
    hm_prepare hm;
    const auto& hvalue = hm(this, hash_type, hm_value);

    int ret = mbedtls_pk_verify(&pimpl->pk_,
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
                throw exception{ret, "failed to verify the signature"};
                break;
        default:
            break;
    }

    return false;
}

buffer_t
pki::encrypt(const buffer_t& hmvalue, hash_t hash_type) {
    hm_prepare hm;
    const auto& hvalue = hm(this, hash_type, hmvalue);

    size_t olen = 32 + max_crypt_size();
    buffer_t output(olen, '\0');
    mbedcrypto_c_call(mbedtls_pk_encrypt,
            &pimpl->pk_,
            to_const_ptr(hvalue),
            hvalue.size(),
            to_ptr(output),
            &olen,
            olen,
            pk::random_func,
            &pimpl->rnd_
          );

    output.resize(olen);
    return output;
}

buffer_t
pki::decrypt(const buffer_t& encrypted_value) {
    if ( (encrypted_value.size() << 3) > key_bitlen() )
        throw usage_exception{"the encrypted value is larger than the key size"};

    size_t olen = 32 + max_crypt_size();
    buffer_t output(olen, '\0');

    mbedcrypto_c_call(mbedtls_pk_decrypt,
            &pimpl->pk_,
            to_const_ptr(encrypted_value),
            encrypted_value.size(),
            to_ptr(output),
            &olen,
            olen,
            pk::random_func,
            &pimpl->rnd_
          );

    output.resize(olen);
    return output;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
