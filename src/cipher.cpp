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
        throw exception(
                MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE, "unsuppotred cipher"
                );

    return cinfot;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

struct cipher::impl
{
    mbedtls_cipher_context_t ctx_;

    explicit impl() {
        mbedtls_cipher_init(&ctx_);
    }

    ~impl() {
        mbedtls_cipher_free(&ctx_);
    }

    void setup(cipher_t type) {
        const auto* cinfot = native_info(type);
        c_call(mbedtls_cipher_setup, &ctx_, cinfot);
    }

    size_t block_size()const noexcept {
        return mbedtls_cipher_get_block_size(&ctx_);
    }

    void iv(const buffer_t& iv_data) {
        c_call(mbedtls_cipher_set_iv,
                &ctx_,
                reinterpret_cast<const unsigned char*>(iv_data.data()),
                iv_data.size()
              );
    }

    void key(const buffer_t& key_data, cipher::mode m) {
        c_call(mbedtls_cipher_setkey,
                &ctx_,
                reinterpret_cast<const unsigned char*>(key_data.data()),
                key_data.size(),
                m == cipher::encrypt_mode ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT
              );
    }

    void padding(padding_t p) {
        c_call(mbedtls_cipher_set_padding_mode,
                &ctx_,
                to_native(p)
              );
    }

    static buffer_t crypt(
            cipher_t type, padding_t pad,
            const buffer_t& iv, const buffer_t& key,
            cipher::mode m,
            const buffer_t& input) {

        impl im;
        im.setup(type);
        im.padding(pad);
        im.iv(iv);
        im.key(key, m);

        size_t osize = 32 + input.size() + im.block_size();
        buffer_t output(osize, '\0');

        c_call(mbedtls_cipher_crypt,
                &im.ctx_,
                reinterpret_cast<const unsigned char*>(iv.data()),
                iv.size(),
                reinterpret_cast<const unsigned char*>(input.data()),
                input.size(),
                reinterpret_cast<unsigned char*>(&output.front()),
                &osize
              );

        output.resize(osize);
        return output;
    }


}; // cipher::impl

///////////////////////////////////////////////////////////////////////////////

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

size_t
cipher::key_bitlen(cipher_t type) {
    const auto* cinfot = native_info(type);
    return cinfot->key_bitlen;
}

buffer_t
cipher::encrypt(cipher_t type, padding_t pad,
        const buffer_t& iv, const buffer_t& key,
        const buffer_t& input) {
    return impl::crypt(type, pad, iv, key, encrypt_mode, input);
}

buffer_t
cipher::decrypt(cipher_t type, padding_t pad,
        const buffer_t& iv, const buffer_t& key,
        const buffer_t& input) {
    return impl::crypt(type, pad, iv, key, decrypt_mode, input);
}

cipher&
cipher::iv(const buffer_t& iv_data) {
    pimpl->iv(iv_data);
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
    c_call(mbedtls_cipher_reset, &pimpl->ctx_);
}

buffer_t
cipher::update(const buffer_t& input) {
    size_t osize = input.size() + pimpl->block_size();
    buffer_t output(osize, '\0');

    c_call(mbedtls_cipher_update,
            &pimpl->ctx_,
            reinterpret_cast<const unsigned char*>(input.data()),
            input.size(),
            reinterpret_cast<unsigned char*>(&output.front()),
            &osize
          );

    output.resize(osize);
    return output;
}

int
cipher::update(const unsigned char* input, size_t input_size,
        unsigned char* output, size_t& output_size) noexcept {
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

    c_call(mbedtls_cipher_finish,
            &pimpl->ctx_,
            reinterpret_cast<unsigned char*>(&output.front()),
            &osize
          );

    output.resize(osize);
    return output;
}

int
cipher::finish(unsigned char* output, size_t& output_size) noexcept {
    return mbedtls_cipher_finish(
            &pimpl->ctx_,
            output, &output_size
            );
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
