#include "mbedcrypto/pk.hpp"
#include "pk_private.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
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

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
namespace pk {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<context>::value == false, "");
static_assert(std::is_move_constructible<context>::value == true, "");
///////////////////////////////////////////////////////////////////////////////

pk_t
type_of(const context& d) {
    return from_native(mbedtls_pk_get_type(&d.pk_));
}

size_t
key_length(const context& d) noexcept {
    return (size_t) mbedtls_pk_get_len(&d.pk_);
}

size_t
key_bitlen(const context& d) noexcept {
    return (size_t) mbedtls_pk_get_bitlen(&d.pk_);
}

bool
can_do(const context& d, pk_t ptype) {
    int ret = mbedtls_pk_can_do(&d.pk_, to_native(ptype));

    // refinement due to build options
    if ( type_of(d) == pk_t::eckey  &&  ptype == pk_t::ecdsa ) {
        #if !defined(MBEDTLS_ECDSA_C)
        ret = 0;
        #endif // MBEDTLS_ECDSA_C
    }

    return ret == 1;
}

bool
check_pair(const context& pub, const context& priv) {
    int ret = mbedtls_pk_check_pair(&pub.pk_, &priv.pk_);

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

void
import_key(context& d, const buffer_t& priv_data, const buffer_t& pass) {
    d.reset();

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
    d.reset();

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
    d.reset();

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
    d.reset();

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

///////////////////////////////////////////////////////////////////////////////
} // namespace pk
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
