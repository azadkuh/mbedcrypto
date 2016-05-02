#include "mbedcrypto/pki.hpp"
#include "mbedcrypto/hash.hpp"
#include "pk_private.hpp"

#include "mbedtls/ecp.h"
#include <cstring>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<pki>::value == false, "");
static_assert(std::is_move_constructible<pki>::value == true, "");

int
random_func(void* ctx, unsigned char* p, size_t len) {
    rnd_generator* rnd = reinterpret_cast<rnd_generator*>(ctx);
    return rnd->make(p, len);
}

class hm_prepare
{
    buffer_t hash_;

public:
    auto operator()(const pki* pk,
            hash_t halgo, const buffer_t& hmvalue) -> const buffer_t& {

        if ( halgo == hash_t::none ) {
            if ( hmvalue.size() > pk->max_crypt_size() )
                throw exception("the message is larger than max_crypt_size()");

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
    pimpl->setup(type);
}

pki::~pki() {
}

void
pki::reset_as(pk_t ntype) {
    pimpl->reset_as(ntype);
}

bool
pki::check_pair(const pki& pub, const pki& priv) {
    return pk::check_pair(*pub.pimpl, *priv.pimpl);
}

pk_t
pki::type()const {
    return pk::type_of(*pimpl);
}

size_t
pki::length()const noexcept {
    return pk::key_length(*pimpl);
}

size_t
pki::bitlen()const noexcept {
    return pk::key_bitlen(*pimpl);
}

size_t
pki::max_crypt_size()const {
    // padding / header data (11 bytes for PKCS#1 v1.5 padding).
    if ( type() == pk_t::rsa )
        return length() - 11;

    return length();

    // other pk types are note yet supported
    //throw exception("unsupported pk type");
}

bool
pki::has_private_key()const noexcept {
    return pimpl->key_is_private_;
}

const char*
pki::name()const noexcept {
    return mbedtls_pk_get_name(&pimpl->pk_);
}

void
pki::parse_key(const buffer_t& private_key, const buffer_t& password) {
    pk::import_key(*pimpl, private_key, password);
}

void
pki::parse_public_key(const buffer_t& public_key) {
    pk::import_public_key(*pimpl, public_key);
}

void
pki::load_key(const char* file_path, const buffer_t& password) {
    pk::load_key(*pimpl, file_path, password);
}

void
pki::load_public_key(const char* file_path) {
    pk::load_public_key(*pimpl, file_path);
}

buffer_t
pki::export_key(pk::key_format fmt) {
    return pk::export_key(*pimpl, fmt);
}

buffer_t
pki::export_public_key(pk::key_format fmt) {
    return pk::export_public_key(*pimpl, fmt);
}

pk::action_flags
pki::what_can_do() const noexcept {
    pk::action_flags f{false, false, false, false};

    if ( pimpl->pk_.pk_info != nullptr   &&   bitlen() > 0 ) {
        const auto* info = pimpl->pk_.pk_info;

        f.encrypt = info->encrypt_func != nullptr;
        f.decrypt = info->decrypt_func != nullptr;
        f.sign    = info->sign_func    != nullptr;
        f.verify  = info->verify_func  != nullptr;

        // refine due to pub/priv key
        // pub keys can not sign, nor decrypt
        switch ( type() ) {
            case pk_t::rsa:
                if ( !pimpl->key_is_private_ )
                    f.decrypt = f.sign = false;
                break;

            case pk_t::eckey:
            case pk_t::ecdsa:
                if ( !pimpl->key_is_private_ )
                    f.sign = false;
                break;

            default:
                break;
        }
    }

    return f;
}

bool
pki::can_do(pk_t ptype) const noexcept {
    return pk::can_do(*pimpl, ptype);
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
            random_func,
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
                throw exception(ret, "failed to verify the signature");
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

    size_t olen = 32 + max_crypt_size();
    buffer_t output(olen, '\0');

    mbedcrypto_c_call(mbedtls_pk_decrypt,
            &pimpl->pk_,
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

void
pki::rsa_generate_key(size_t key_bitlen, size_t exponent) {
#if defined(MBEDTLS_GENPRIME)
    if ( !can_do(pk_t::rsa) )
        throw exception("the instance is not initialized as rsa");

    // resets previous states
    pimpl->reset_as(pk_t::rsa);

    mbedcrypto_c_call(mbedtls_rsa_gen_key,
            mbedtls_pk_rsa(pimpl->pk_),
            random_func,
            &pimpl->rnd_,
            key_bitlen,
            exponent
            );
    // set the key type
    pimpl->key_is_private_ = true;


#else // MBEDTLS_GENPRIME
    throw rsa_keygen_exception();
#endif // MBEDTLS_GENPRIME
}

void
pki::ec_generate_key(curve_t ctype) {
#if defined(MBEDTLS_ECP_C)
    if ( !can_do(pk_t::eckey)
            && !can_do(pk_t::eckey_dh)
            && !can_do(pk_t::ecdsa) )
        throw exception("the instance is not initialized as ec");

    // resets previous states
    pimpl->reset_as(type());

    mbedcrypto_c_call(mbedtls_ecp_gen_key,
            to_native(ctype),
            mbedtls_pk_ec(pimpl->pk_),
            random_func,
            &pimpl->rnd_
            );
    // set the key type
    pimpl->key_is_private_ = true;

#else // MBEDTLS_ECP_C
    throw ecp_exception();
#endif // MBEDTLS_ECP_C
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
