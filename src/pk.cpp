#include "mbedcrypto/pk.hpp"
#include "mbedcrypto/hash.hpp"
#include "pk_private.hpp"

#include <cstring>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace pk {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<context>::value == false, "");
static_assert(std::is_move_constructible<context>::value == true,  "");
///////////////////////////////////////////////////////////////////////////////
namespace {
///////////////////////////////////////////////////////////////////////////////
// constants
enum K {
    DefaultExportBufferSize = 16000,
};

void
finalize_pem(buffer_t& pem) {
    pem.push_back('\0');
}

class hm_prepare
{
    buffer_t hash_;

public:
    const buffer_t operator()(const context& pk,
            const buffer_t& hmvalue, hash_t halgo) {

        if ( halgo == hash_t::none ) {
            if ( hmvalue.size() > max_crypt_size(pk) )
                throw exceptions::usage_error{
                    "the message is larger than max_crypt_size()"
                };

            return hmvalue;
        }

        hash_ = hash::make(halgo, hmvalue);
        return hash_;
    }
}; // hm_prepare

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

void
reset(context& d) noexcept {
    d.key_is_private_ = false;
    mbedtls_pk_free(&d.pk_);
}

void
reset_as(context& d, pk_t ptype) {
    reset(d);
    mbedcrypto_c_call(mbedtls_pk_setup,
            &d.pk_,
            native_info(ptype)
            );
}

pk_t
type_of(const context& d) {
    return from_native(mbedtls_pk_get_type(&d.pk_));
}

const char*
name_of(const context& d) noexcept {
    return mbedtls_pk_get_name(&d.pk_);
}

size_t
key_length(const context& d) noexcept {
    return (size_t) mbedtls_pk_get_len(&d.pk_);
}

size_t
key_bitlen(const context& d) noexcept {
    return (size_t) mbedtls_pk_get_bitlen(&d.pk_);
}

size_t
max_crypt_size(const context& d) {
    if ( type_of(d) != pk_t::rsa )
        throw exceptions::support_error{};

    // padding / header data (11 bytes for PKCS#1 v1.5 padding).
    return key_length(d) - 11;
}

bool
has_private_key(const context& d) noexcept {
    return d.key_is_private_;
}

bool
can_do(const context& d, pk_t ptype) {
    int ret = mbedtls_pk_can_do(&d.pk_, to_native(ptype));

    // refinement due to build options
    if ( type_of(d) == pk_t::eckey  &&  ptype == pk_t::ecdsa ) {
        if ( !supports(pk_t::ecdsa) )
            ret = 0;
    }

    return ret == 1;
}

action_flags
what_can_do(const context& d) {
    pk::action_flags f{false, false, false, false};

    if ( d.pk_.pk_info != nullptr   &&   key_bitlen(d) > 0 ) {
        const auto* info = d.pk_.pk_info;

        f.encrypt = info->encrypt_func != nullptr;
        f.decrypt = info->decrypt_func != nullptr;
        f.sign    = info->sign_func    != nullptr;
        f.verify  = info->verify_func  != nullptr;

        // refine due to pub/priv key
        // pub keys can not sign, nor decrypt
        switch ( type_of(d) ) {
            case pk_t::rsa:
                if ( !d.key_is_private_ )
                    f.decrypt = f.sign = false;
                break;

            case pk_t::eckey:
            case pk_t::ecdsa:
                if ( !d.key_is_private_ )
                    f.sign = false;
                break;

            default:
                break;
        }
    }

    return f;
}

bool
check_pair(const context& pub, const context& priv) {
    int ret = mbedtls_pk_check_pair(&pub.pk_, &priv.pk_);

    switch ( ret ) {
        case 0:
            return true;

        case MBEDTLS_ERR_PK_BAD_INPUT_DATA:
        case MBEDTLS_ERR_PK_TYPE_MISMATCH:
            throw exception{ret, __FUNCTION__};
            break;

        default:
            return false;
            break;
    }
}

void
import_key(context& d, const buffer_t& priv_data, const buffer_t& pass) {
    reset(d);

    const auto* ppass = (pass.size() != 0) ? to_const_ptr(pass) : nullptr;

    mbedcrypto_c_call(mbedtls_pk_parse_key,
            &d.pk_,
            to_const_ptr(priv_data),
            priv_data.size(),
            ppass,
            pass.size()
          );
    // set the key type
    d.key_is_private_ = true;
}

void
import_public_key(context& d, const buffer_t& pub_data) {
    reset(d);

    mbedcrypto_c_call(mbedtls_pk_parse_public_key,
        &d.pk_,
        to_const_ptr(pub_data),
        pub_data.size()
        );
    // set the key type
    d.key_is_private_ = false;
}

void
load_key(context& d, const char* fpath, const buffer_t& pass) {
    reset(d);

    const auto* ppass = (pass.size() != 0) ? pass.data() : nullptr;

    mbedcrypto_c_call(mbedtls_pk_parse_keyfile,
            &d.pk_,
            fpath,
            ppass
          );
    // set the key type
    d.key_is_private_ = true;
}

void
load_public_key(context& d, const char* fpath) {
    reset(d);

    mbedcrypto_c_call(mbedtls_pk_parse_public_keyfile,
            &d.pk_,
            fpath
          );
    // set the key type
    d.key_is_private_ = false;
}

buffer_t
export_key(context& d, key_format fmt) {
#if defined(MBEDTLS_PK_WRITE_C)
    buffer_t output(K::DefaultExportBufferSize, '\0');

    if ( fmt == pem_format ) {
        mbedcrypto_c_call(mbedtls_pk_write_key_pem,
                &d.pk_,
                to_ptr(output),
                K::DefaultExportBufferSize
                );

        output.resize(std::strlen(output.c_str()));
        finalize_pem(output);

    } else if ( fmt == pk::der_format ) {
        int ret = mbedtls_pk_write_key_der(
                &d.pk_,
                to_ptr(output),
                K::DefaultExportBufferSize
                );
        if ( ret < 0 )
            throw exception{ret, __FUNCTION__};

        size_t length = ret;
        output.erase(0, K::DefaultExportBufferSize - length);
        output.resize(length);
    }

    return output;

#else // MBEDTLS_PK_WRITE_C
    throw pk_export_exception{};
#endif // MBEDTLS_PK_WRITE_C
}

buffer_t
export_public_key(context& d, key_format fmt) {
#if defined(MBEDTLS_PK_WRITE_C)
    buffer_t output(K::DefaultExportBufferSize, '\0');

    if ( fmt == pk::pem_format ) {
        mbedcrypto_c_call(mbedtls_pk_write_pubkey_pem,
                &d.pk_,
                to_ptr(output),
                K::DefaultExportBufferSize
                );

        output.resize(std::strlen(output.c_str()));
        finalize_pem(output);

    } else if ( fmt == pk::der_format ) {
        int ret = mbedtls_pk_write_pubkey_der(
                &d.pk_,
                to_ptr(output),
                K::DefaultExportBufferSize
                );
        if ( ret < 0 )
            throw exception{ret, __FUNCTION__};

        size_t length = ret;
        output.erase(0, K::DefaultExportBufferSize - length);
        output.resize(length);
    }

    return output;

#else // MBEDTLS_PK_WRITE_C
    throw pk_export_exception{};
#endif // MBEDTLS_PK_WRITE_C
}

bool
supports_key_export() noexcept {
#if defined(MBEDTLS_PK_WRITE_C)
    return true;
#else // MBEDTLS_PK_WRITE_C
    return false;
#endif // MBEDTLS_PK_WRITE_C
}

bool
supports_rsa_keygen() noexcept {
#if defined(MBEDTLS_GENPRIME)
    return true;
#else
    return false;
#endif
}

bool
supports_ec_keygen() noexcept {
#if defined(MBEDTLS_ECP_C)
    return true;
#else
    return false;
#endif
}

void
generate_rsa_key(context& d, size_t key_bitlen, size_t exponent) {
#if defined(MBEDTLS_GENPRIME)
    // resets previous states
    pk::reset_as(d, pk_t::rsa);

    mbedcrypto_c_call(mbedtls_rsa_gen_key,
            mbedtls_pk_rsa(d.pk_),
            pk::random_func,
            &d.rnd_,
            key_bitlen,
            exponent
            );
    // set the key type
    d.key_is_private_ = true;


#else // MBEDTLS_GENPRIME
    throw rsa_keygen_exception{};
#endif // MBEDTLS_GENPRIME
}

void
generate_ec_key(context& d, curve_t ctype) {
#if defined(MBEDTLS_ECP_C)
    // resets previous states
    pk::reset_as(d, pk_t::eckey);

    mbedcrypto_c_call(mbedtls_ecp_gen_key,
            to_native(ctype),
            mbedtls_pk_ec(d.pk_),
            pk::random_func,
            &d.rnd_
            );
    // set the key type
    d.key_is_private_ = true;

#else // MBEDTLS_ECP_C
    throw ecp_exception{};
#endif // MBEDTLS_ECP_C
}

buffer_t
sign(context& d, const buffer_t& hmvalue, hash_t halgo) {
    hm_prepare hm;
    const auto& hvalue = hm(d, hmvalue, halgo);

    size_t olen = 32 + max_crypt_size(d);
    buffer_t output(olen, '\0');
    mbedcrypto_c_call(mbedtls_pk_sign,
            &d.pk_,
            to_native(halgo),
            to_const_ptr(hvalue),
            hvalue.size(),
            to_ptr(output),
            &olen,
            pk::random_func,
            &d.rnd_
          );

    output.resize(olen);
    return output;
}

bool
verify(context& d,
        const buffer_t& signature,
        const buffer_t& hm_value, hash_t halgo) {
    hm_prepare hm;
    const auto& hvalue = hm(d, hm_value, halgo);

    int ret = mbedtls_pk_verify(&d.pk_,
            to_native(halgo),
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
encrypt(context& d, const buffer_t& hmvalue, hash_t halgo) {
    hm_prepare hm;
    const auto& hvalue = hm(d, hmvalue, halgo);

    size_t olen = 32 + max_crypt_size(d);
    buffer_t output(olen, '\0');
    mbedcrypto_c_call(mbedtls_pk_encrypt,
            &d.pk_,
            to_const_ptr(hvalue),
            hvalue.size(),
            to_ptr(output),
            &olen,
            olen,
            pk::random_func,
            &d.rnd_
          );

    output.resize(olen);
    return output;
}

buffer_t
decrypt(context& d, const buffer_t& encrypted_value) {
    if ( (encrypted_value.size() << 3) > key_bitlen(d) )
        throw exceptions::usage_error{
            "the encrypted value is larger than the key size"
        };

    size_t olen = 32 + max_crypt_size(d);
    buffer_t output(olen, '\0');

    mbedcrypto_c_call(mbedtls_pk_decrypt,
            &d.pk_,
            to_const_ptr(encrypted_value),
            encrypted_value.size(),
            to_ptr(output),
            &olen,
            olen,
            pk::random_func,
            &d.rnd_
          );

    output.resize(olen);
    return output;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace pk
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
