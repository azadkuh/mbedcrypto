#include "mbedcrypto/pki.hpp"
#include "mbedcrypto/random.hpp"
#include "mbedcrypto/hash.hpp"
#include "conversions.hpp"

#include "mbedtls/pk_internal.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include <cstring>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<pki>::value == false, "");
static_assert(std::is_move_constructible<pki>::value == true, "");

enum K {
    DefaultExportBufferSize = 16000,
};

struct rsa_keygen_exception : public exception {
    explicit rsa_keygen_exception() :
        exception("needs RSA_KEYGEN, check build options"){}
}; // struct rsa_keygen_exception

struct pk_export_exception : public exception {
    explicit pk_export_exception() :
        exception("needs PK_EXPORT, check build options"){}
}; // struct pk_export_exception

struct ecp_exception : public exception {
    explicit ecp_exception() :
        exception("needs EC (elliptic curves), check build options"){}
}; // struct ecp_exception


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

void
finalize_pem(buffer_t& pem) {
    pem.push_back('\0');
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

struct pki::impl
{
    bool key_is_private_ = false;
    mbedcrypto::random rnd_{"mbedcrypto pki implementation"};
    mbedtls_pk_context ctx_;

    explicit impl() {
        mbedtls_pk_init(&ctx_);
    }

    ~impl() {
        mbedtls_pk_free(&ctx_);
    }

    void setup(pk_t type) {
        mbedcrypto_c_call(mbedtls_pk_setup,
                &ctx_,
                native_info(type)
                );
    }

    void reset() {
        mbedtls_pk_free(&ctx_);
        key_is_private_ = false;
    }
    void reset_as(pk_t type) {
        reset();
        setup(type);
    }


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
    int ret = mbedtls_pk_check_pair(&pub.pimpl->ctx_, &priv.pimpl->ctx_);

    switch ( ret ) {
        case 0:
            return true;

        case MBEDTLS_ERR_PK_BAD_INPUT_DATA:
        case MBEDTLS_ERR_PK_TYPE_MISMATCH:
            throw exception(ret, __FUNCTION__);
            break;

        default:
            return false;
            break;
    }
}

pk_t
pki::type()const noexcept {
    return from_native(
            mbedtls_pk_get_type(&pimpl->ctx_)
            );
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
    return mbedtls_pk_get_name(&pimpl->ctx_);
}

void
pki::parse_key(const buffer_t& private_key, const buffer_t& password) {
    pimpl->reset();

    const auto* ppass = (password.size() != 0) ? to_const_ptr(password) : nullptr;

    mbedcrypto_c_call(mbedtls_pk_parse_key,
            &pimpl->ctx_,
            to_const_ptr(private_key),
            private_key.size(),
            ppass,
            password.size()
          );
    // set the key type
    pimpl->key_is_private_ = true;
}

void
pki::parse_public_key(const buffer_t& public_key) {
    pimpl->reset();

    mbedcrypto_c_call(mbedtls_pk_parse_public_key,
        &pimpl->ctx_,
        to_const_ptr(public_key),
        public_key.size()
        );
    // set the key type
    pimpl->key_is_private_ = false;
}

void
pki::load_key(const char* file_path, const buffer_t& password) {
    pimpl->reset();

    const auto* ppass = (password.size() != 0) ? password.data() : nullptr;

    mbedcrypto_c_call(mbedtls_pk_parse_keyfile,
            &pimpl->ctx_,
            file_path,
            ppass
          );
    // set the key type
    pimpl->key_is_private_ = true;
}

void
pki::load_public_key(const char* file_path) {
    pimpl->reset();

    mbedcrypto_c_call(mbedtls_pk_parse_public_keyfile,
            &pimpl->ctx_,
            file_path
          );
    // set the key type
    pimpl->key_is_private_ = false;
}

bool
pki::supports_pk_export() {
#if defined(MBEDTLS_PK_WRITE_C)
    return true;
#else // MBEDTLS_PK_WRITE_C
    return false;
#endif // MBEDTLS_PK_WRITE_C
}

buffer_t
pki::export_key(pki::key_format fmt) {
#if defined(MBEDTLS_PK_WRITE_C)
    buffer_t output(K::DefaultExportBufferSize, '\0');

    if ( fmt == pem_format ) {
        mbedcrypto_c_call(mbedtls_pk_write_key_pem,
                &pimpl->ctx_,
                to_ptr(output),
                K::DefaultExportBufferSize
                );

        output.resize(std::strlen(output.c_str()));
        finalize_pem(output);

    } else if ( fmt == der_format ) {
        int ret = mbedtls_pk_write_key_der(
                &pimpl->ctx_,
                to_ptr(output),
                K::DefaultExportBufferSize
                );
        if ( ret < 0 )
            throw exception(ret, __FUNCTION__);

        size_t length = ret;
        output.erase(0, K::DefaultExportBufferSize - length);
        output.resize(length);
    }

    return output;

#else // MBEDTLS_PK_WRITE_C
    throw pk_export_exception();
#endif // MBEDTLS_PK_WRITE_C
}

buffer_t
pki::export_public_key(pki::key_format fmt) {
#if defined(MBEDTLS_PK_WRITE_C)
    buffer_t output(K::DefaultExportBufferSize, '\0');

    if ( fmt == pem_format ) {
        mbedcrypto_c_call(mbedtls_pk_write_pubkey_pem,
                &pimpl->ctx_,
                to_ptr(output),
                K::DefaultExportBufferSize
                );

        output.resize(std::strlen(output.c_str()));
        finalize_pem(output);

    } else if ( fmt == der_format ) {
        int ret = mbedtls_pk_write_pubkey_der(
                &pimpl->ctx_,
                to_ptr(output),
                K::DefaultExportBufferSize
                );
        if ( ret < 0 )
            throw exception(ret, __FUNCTION__);

        size_t length = ret;
        output.erase(0, K::DefaultExportBufferSize - length);
        output.resize(length);
    }

    return output;

#else // MBEDTLS_PK_WRITE_C
    throw pk_export_exception();
#endif // MBEDTLS_PK_WRITE_C
}

pki::action_flags
pki::what_can_do() const noexcept {
    action_flags f{false, false, false, false};

    if ( pimpl->ctx_.pk_info != nullptr   &&   bitlen() > 0 ) {
        const auto* info = pimpl->ctx_.pk_info;

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
    int ret = mbedtls_pk_can_do(&pimpl->ctx_, to_native(ptype));

    // refinement due to build options
    if ( type() == pk_t::eckey  &&  ptype == pk_t::ecdsa ) {
        #if !defined(MBEDTLS_ECDSA_C)
        ret = 0;
        #endif // MBEDTLS_ECDSA_C
    }

    return ret == 1;
}

size_t
pki::bitlen()const noexcept {
    return (size_t) mbedtls_pk_get_bitlen(&pimpl->ctx_);
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
    hm_prepare hm;
    const auto& hvalue = hm(this, halgo, hmvalue);

    size_t olen = 32 + max_crypt_size();
    buffer_t output(olen, '\0');
    mbedcrypto_c_call(mbedtls_pk_sign,
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
    hm_prepare hm;
    const auto& hvalue = hm(this, hash_type, hm_value);

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
    hm_prepare hm;
    const auto& hvalue = hm(this, hash_type, hmvalue);

    size_t olen = 32 + max_crypt_size();
    buffer_t output(olen, '\0');
    mbedcrypto_c_call(mbedtls_pk_encrypt,
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

    size_t olen = 32 + max_crypt_size();
    buffer_t output(olen, '\0');

    mbedcrypto_c_call(mbedtls_pk_decrypt,
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

bool
pki::supports_rsa_keygen() {
#if defined(MBEDTLS_GENPRIME)
    return true;
#else
    return false;
#endif
}

void
pki::rsa_generate_key(size_t key_bitlen, size_t exponent) {
#if defined(MBEDTLS_GENPRIME)
    if ( !can_do(pk_t::rsa) )
        throw exception("the instance is not initialized as rsa");

    // resets previous states
    pimpl->reset_as(pk_t::rsa);

    mbedcrypto_c_call(mbedtls_rsa_gen_key,
            mbedtls_pk_rsa(pimpl->ctx_),
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

bool
pki::supports_ec_keygen() {
#if defined(MBEDTLS_ECP_C)
    return true;
#else
    return false;
#endif
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
            mbedtls_pk_ec(pimpl->ctx_),
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
