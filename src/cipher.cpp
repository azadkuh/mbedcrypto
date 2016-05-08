#include "mbedcrypto/cipher.hpp"
#include "conversions.hpp"

#include "mbedtls/cipher.h"
#include "mbedtls/aesni.h"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<cipher>::value == false, "");
static_assert(std::is_move_constructible<cipher>::value == true , "");

const mbedtls_cipher_info_t*
native_info(cipher_t type) {
    auto ntype         = to_native(type);
    const auto* cinfot = mbedtls_cipher_info_from_type(ntype);

    if ( cinfot == nullptr )
        throw exceptions::unknown_cipher{};

    return cinfot;
}

///////////////////////////////////////////////////////////////////////////////

struct cipher_impl
{
    mbedtls_cipher_context_t ctx_;
    buffer_t iv_data_;

    explicit cipher_impl() {
        mbedtls_cipher_init(&ctx_);
    }

    ~cipher_impl() {
        mbedtls_cipher_free(&ctx_);
    }

    void setup(cipher_t type) {
        const auto* cinfot = native_info(type);
        mbedcrypto_c_call(mbedtls_cipher_setup, &ctx_, cinfot);
    }

    size_t block_size()const noexcept {
        return mbedtls_cipher_get_block_size(&ctx_);
    }

    size_t iv_size()const noexcept {
        return ctx_.cipher_info->iv_size;
    }

    size_t key_bitlen()const noexcept {
        return ctx_.cipher_info->key_bitlen;
    }

    cipher_bm block_mode() const noexcept {
        return from_native(ctx_.cipher_info->mode);
    }

    void iv() {
        iv(iv_data_);
    }

    void iv(const buffer_t& iv_data) {
        mbedcrypto_c_call(mbedtls_cipher_set_iv,
                &ctx_,
                to_const_ptr(iv_data),
                iv_data.size()
              );
    }

    void key(const buffer_t& key_data, cipher::mode m) {
        mbedcrypto_c_call(mbedtls_cipher_setkey,
                &ctx_,
                to_const_ptr(key_data),
                key_data.size() << 3, // bitlen
                m == cipher::encrypt_mode ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT
              );
    }

    void padding(padding_t p) {
        if ( p == padding_t::none )
            return; // do nothing!

        mbedcrypto_c_call(mbedtls_cipher_set_padding_mode,
                &ctx_,
                to_native(p)
              );
    }

    // updates in chunks
    int update_chunked(const unsigned char* pinput, size_t isize,
            unsigned char* poutput, size_t& osize) {

        auto bsize = block_size();
        if ( isize % bsize )
            return MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED;

        size_t i_index = 0;
        size_t o_index = 0;

        size_t chunks = isize / bsize;
        for ( size_t i = 0;    i < chunks;    ++i ) {
            size_t usize = 0;
            int ret = mbedtls_cipher_update(
                    &ctx_,
                    pinput + i_index,
                    bsize,
                    poutput + o_index,
                    &usize
                    );
            if ( ret < 0 )
                return ret;

            i_index += bsize;
            o_index += usize;
        }

        osize = o_index;
        return 0; // success
    }

}; // struct cipher_impl

///////////////////////////////////////////////////////////////////////////////

class crypt_engine {
    cipher_t  type_       = cipher_t::none;
    cipher_bm block_mode_ = cipher_bm::none;
    size_t    block_size_ = 0;
    size_t    input_size_ = 0;
    size_t    chunks_     = 0;
    const buffer_t& input_;

    explicit crypt_engine(cipher_t type, const buffer_t& input)
        : type_(type),
        block_mode_(cipher::block_mode(type)),
        block_size_(cipher::block_size(type)),
        input_size_(input.size()),
        input_(input) {

            // compute number of chunks
            if ( block_mode_ == cipher_bm::ecb ) {
                if ( input_size_ == 0   ||   input_size_ % block_size_ )
                    throw exceptions::usage_error{
                        "ecb cipher block:"
                        " a valid input size must be dividable by block size"
                    };

                chunks_ = input_size_ / block_size_;

            } else { // for any other cipher block do in single shot
                chunks_ = 1;
            }
        }

    buffer_t compute(padding_t pad,
        const buffer_t& iv, const buffer_t& key, cipher::mode m) {

        // prepare ciphering parameters
        cipher_impl cim;
        cim.setup(type_);
        cim.padding(pad);
        cim.iv(iv);
        cim.key(key, m);

        // prepare output size
        size_t osize = 32 + input_size_ + block_size_;
        buffer_t output(osize, '\0');

        const auto* pSrc = to_const_ptr(input_);
        auto* pDes       = to_ptr(output);

        if ( chunks_ == 1 ) {
            mbedcrypto_c_call(mbedtls_cipher_crypt,
                    &cim.ctx_,
                    to_const_ptr(iv),
                    iv.size(),
                    pSrc, input_size_,
                    pDes, &osize
                  );

        } else {
            osize = 0;

            for ( size_t i = 0;    i < chunks_;    ++i ) {
                size_t done_size = 0;
                mbedcrypto_c_call(mbedtls_cipher_crypt,
                        &cim.ctx_,
                        to_const_ptr(iv),
                        iv.size(),
                        pSrc, block_size_,
                        pDes, &done_size
                      );

                osize += done_size;
                pSrc  += block_size_;
                pDes  += block_size_;
            }
        }

        output.resize(osize);
        return output;
    }

public:
    static buffer_t run(cipher_t type, padding_t pad,
            const buffer_t& iv, const buffer_t& key, cipher::mode m,
            const buffer_t& input) {

        // check cipher mode against input size
        crypt_engine cengine(type, input);
        return cengine.compute(pad, iv, key, m);
    }

}; // struct crypt_engine

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
struct cipher::impl : public cipher_impl{};

cipher::cipher(cipher_t type) : pimpl(std::make_unique<impl>()) {
    pimpl->setup(type);
}

cipher::~cipher() {
}

bool
cipher::supports_aes_ni() {
#if defined(MBEDTLS_HAVE_X86_64)    &&    defined(MBEDTLS_AESNI_C)
    return mbedtls_aesni_has_support(MBEDTLS_AESNI_AES) == 1;
#else
    return false;
#endif
}

size_t
cipher::block_size(cipher_t type) {
    const auto* cinfot = native_info(type);
    return cinfot->block_size;
}

size_t
cipher::iv_size(cipher_t type) {
    const auto* cinfot = native_info(type);
    return cinfot->iv_size;
}

cipher_bm
cipher::block_mode(cipher_t type) {
    const auto* cinfot = native_info(type);
    return from_native(cinfot->mode);
}

size_t
cipher::key_bitlen(cipher_t type) {
    const auto* cinfot = native_info(type);
    return cinfot->key_bitlen;
}

size_t
cipher::block_size() const noexcept {
    return pimpl->block_size();
}

size_t
cipher::iv_size() const noexcept {
    return pimpl->iv_size();
}

size_t
cipher::key_bitlen() const noexcept {
    return pimpl->key_bitlen();
}

cipher_bm
cipher::block_mode() const noexcept {
    return pimpl->block_mode();
}

buffer_t
cipher::encrypt(cipher_t type, padding_t pad,
        const buffer_t& iv, const buffer_t& key,
        const buffer_t& input) {
    return crypt_engine::run(type, pad, iv, key, encrypt_mode, input);
}

buffer_t
cipher::decrypt(cipher_t type, padding_t pad,
        const buffer_t& iv, const buffer_t& key,
        const buffer_t& input) {
    return crypt_engine::run(type, pad, iv, key, decrypt_mode, input);
}

bool
cipher::supports_aead() {
#if defined(MBEDTLS_CIPHER_MODE_AEAD)
    return true;
#endif
    return false;
}

std::tuple<buffer_t, buffer_t>
cipher::encrypt_aead(cipher_t type,
        const buffer_t& iv, const buffer_t& key,
        const buffer_t& ad,
        const buffer_t& input) {
#if defined(MBEDTLS_CIPHER_MODE_AEAD)

    cipher::impl cip;
    cip.setup(type);
    cip.key(key, cipher::encrypt_mode);

    size_t olen = input.size() + cip.block_size();
    buffer_t output(olen, '\0');
    buffer_t tag(16, '\0');

    mbedcrypto_c_call(mbedtls_cipher_auth_encrypt,
            &cip.ctx_,
            to_const_ptr(iv),    iv.size(),
            to_const_ptr(ad),    ad.size(),
            to_const_ptr(input), input.size(),
            to_ptr(output),      &olen,
            to_ptr(tag),         16
            );

    output.resize(olen);
    return std::make_tuple(tag, output);

#else // MBEDTLS_CIPHER_MODE_AEAD
    throw aead_exception{};
#endif
}

std::tuple<bool, buffer_t>
cipher::decrypt_aead(cipher_t type,
        const buffer_t& iv, const buffer_t& key,
        const buffer_t& ad,
        const buffer_t& tag,
        const buffer_t& input) {
#if defined(MBEDTLS_CIPHER_MODE_AEAD)

    cipher::impl cip;
    cip.setup(type);
    cip.key(key, cipher::decrypt_mode);

    size_t olen = input.size() + cip.block_size();
    buffer_t output(olen, '\0');

    int ret = mbedtls_cipher_auth_decrypt(
            &cip.ctx_,
            to_const_ptr(iv), iv.size(),
            to_const_ptr(ad), ad.size(),
            to_const_ptr(input), input.size(),
            to_ptr(output), &olen,
            to_const_ptr(tag), tag.size()
            );

    output.resize(olen);

    if ( ret == MBEDTLS_ERR_CIPHER_AUTH_FAILED )
        return std::make_tuple(false, output);
    else if ( ret == 0 )
        return std::make_tuple(true, output);

    // ret is non zero
    throw exception{ret, __FUNCTION__};

#else // MBEDTLS_CIPHER_MODE_AEAD
    throw aead_exception{};
#endif
}

cipher&
cipher::iv(const buffer_t& iv_data) {
    pimpl->iv(iv_data);
    pimpl->iv_data_ = iv_data;
    return *this;
}

cipher&
cipher::key(const buffer_t& key_data, mode m) {
    pimpl->key(key_data, m);
    return *this;
}

cipher&
cipher::padding(padding_t p) {
    pimpl->padding(p);
    return *this;
}

void
cipher::start() {
    pimpl->iv();
    mbedcrypto_c_call(mbedtls_cipher_reset, &pimpl->ctx_);
}

buffer_t
cipher::update(const buffer_t& input) {
    size_t osize = input.size() + pimpl->block_size() + 32;
    buffer_t output(osize, '\0');

    if ( block_mode() == cipher_bm::ecb ) {
        int ret = pimpl->update_chunked(
                to_const_ptr(input),
                input.size(),
                to_ptr(output),
                osize
                );
        if ( ret != 0 )
            throw exception{ret, __FUNCTION__};

    } else {
        mbedcrypto_c_call(mbedtls_cipher_update,
                &pimpl->ctx_,
                to_const_ptr(input),
                input.size(),
                to_ptr(output),
                &osize
              );
    }

    output.resize(osize);
    return output;
}

size_t
cipher::update(size_t count,
        const buffer_t& input, size_t in_index,
        buffer_t& output, size_t out_index) {
    size_t usize = 0;

    if ( block_mode() == cipher_bm::ecb ) {
        int ret = pimpl->update_chunked(
                to_const_ptr(input) + in_index,
                count,
                to_ptr(output) + out_index,
                usize
                );
        if ( ret != 0 )
            throw exception{ret, __FUNCTION__};

    } else {
        mbedcrypto_c_call(mbedtls_cipher_update,
                &pimpl->ctx_,
                to_const_ptr(input) + in_index,
                count,
                to_ptr(output) + out_index,
                &usize
              );
    }

    return usize;
}

int
cipher::update(const unsigned char* input, size_t input_size,
        unsigned char* output, size_t& output_size) noexcept {
    if ( block_mode() == cipher_bm::ecb ) {
        return pimpl->update_chunked(
                input, input_size,
                output, output_size
                );
    }

    // for other block modes
    return mbedtls_cipher_update(
            &pimpl->ctx_,
            input, input_size,
            output, &output_size
            );
}

buffer_t
cipher::finish() {
    size_t osize = pimpl->block_size() + 32;
    buffer_t output(osize, '\0');

    mbedcrypto_c_call(mbedtls_cipher_finish,
            &pimpl->ctx_,
            to_ptr(output),
            &osize
          );

    output.resize(osize);
    return output;
}

size_t
cipher::finish(buffer_t& output, size_t out_index) {
    size_t fsize = 0;
    mbedcrypto_c_call(mbedtls_cipher_finish,
            &pimpl->ctx_,
            to_ptr(output) + out_index,
            &fsize
          );

    return fsize;
}

int
cipher::finish(unsigned char* output, size_t& output_size) noexcept {
    return mbedtls_cipher_finish(
            &pimpl->ctx_,
            output, &output_size
            );
}

buffer_t
cipher::crypt(const buffer_t& input) {
    start();

    const size_t osize = 32 + input.size() + pimpl->block_size();
    buffer_t output(osize, '\0');
    auto* out_ptr = to_ptr(output);

    size_t out_index = 0;
    mbedcrypto_c_call(mbedtls_cipher_update,
            &pimpl->ctx_,
            to_const_ptr(input),
            input.size(),
            out_ptr,
            &out_index
          );

    size_t fin_len = 0;
    mbedcrypto_c_call(mbedtls_cipher_finish,
            &pimpl->ctx_,
            out_ptr + out_index,
            &fin_len
          );

    output.resize(out_index + fin_len);
    return output;
}

void
cipher::gcm_additional_data(const buffer_t& ad) {
#if defined(MBEDTLS_GCM_C)
    mbedcrypto_c_call(mbedtls_cipher_update_ad,
            &pimpl->ctx_,
            to_const_ptr(ad),
            ad.size()
            );

#else // MBEDTLS_
    throw gcm_exception{};
#endif // MBEDTLS_
}

buffer_t
cipher::gcm_encryption_tag(size_t length) {
#if defined(MBEDTLS_GCM_C)
    buffer_t tag(length, '\0');
    mbedcrypto_c_call(mbedtls_cipher_write_tag,
            &pimpl->ctx_,
            to_ptr(tag),
            length
            );

    return tag;
#else // MBEDTLS_
    throw gcm_exception{};
#endif // MBEDTLS_
}

bool
cipher::gcm_check_decryption_tag(const buffer_t& tag) {
#if defined(MBEDTLS_GCM_C)
    int ret = mbedtls_cipher_check_tag(&pimpl->ctx_,
            to_const_ptr(tag),
            tag.size()
            );

    switch ( ret ) {
        case 0:
            return true;  // authneticated
        case MBEDTLS_ERR_CIPHER_AUTH_FAILED:
            return false; // authentication failed

        default: // other ret codes means error in data or context
            throw exception{ret, __FUNCTION__};
            break;
    }
#else // MBEDTLS_GCM_C
    throw gcm_exception{};
#endif // MBEDTLS_GCM_C
}
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
