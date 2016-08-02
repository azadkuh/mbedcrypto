#include "mbedcrypto/cipher.hpp"
#include "conversions.hpp"

#include "mbedtls/aesni.h"
#include "mbedtls/cipher.h"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<cipher>::value == false, "");
static_assert(std::is_move_constructible<cipher>::value == true, "");

const mbedtls_cipher_info_t*
native_info(cipher_t type) {
    auto        ntype  = to_native(type);
    const auto* cinfot = mbedtls_cipher_info_from_type(ntype);

    if (cinfot == nullptr)
        throw exceptions::unknown_cipher{};

    return cinfot;
}

///////////////////////////////////////////////////////////////////////////////

struct cipher_impl {
    mbedtls_cipher_context_t ctx_;
    buffer_t                 iv_data_;

    explicit cipher_impl() {
        mbedtls_cipher_init(&ctx_);
    }

    ~cipher_impl() {
        mbedtls_cipher_free(&ctx_);
    }

    auto& setup(cipher_t type) {
        const auto* cinfot = native_info(type);
        mbedcrypto_c_call(mbedtls_cipher_setup, &ctx_, cinfot);
        return *this;
    }

    size_t block_size() const noexcept {
        return mbedtls_cipher_get_block_size(&ctx_);
    }

    size_t iv_size() const noexcept {
        return ctx_.cipher_info->iv_size;
    }

    size_t key_bitlen() const noexcept {
        return ctx_.cipher_info->key_bitlen;
    }

    cipher_bm block_mode() const noexcept {
        return from_native(ctx_.cipher_info->mode);
    }

    constexpr const auto& iv() const noexcept {
        return iv_data_;
    }

    auto& iv(buffer_view_t iv_data) {
        iv_data_ = iv_data.to<buffer_t>();
        mbedcrypto_c_call(
            mbedtls_cipher_set_iv, &ctx_, iv_data.data(), iv_data.size());

        return *this;
    }

    void reset_last_iv() {
        iv(iv_data_);
    }

    auto& key(buffer_view_t key_data, cipher::mode m) {
        mbedcrypto_c_call(
            mbedtls_cipher_setkey,
            &ctx_,
            key_data.data(),
            key_data.size() << 3, // bitlen
            m == cipher::encrypt_mode ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT);

        return *this;
    }

    auto& padding(padding_t p) {
        if (p != padding_t::none)
            mbedcrypto_c_call(
                mbedtls_cipher_set_padding_mode, &ctx_, to_native(p));

        return *this;
    }

    // updates in chunks
    int update_chunked(buffer_view_t achunk, uchars poutput, size_t& osize) {
        auto bsize = block_size();
        if (achunk.size() % bsize)
            return MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED;

        size_t i_index = 0;
        size_t o_index = 0;
        size_t chunks  = achunk.size() / bsize;

        for (size_t i = 0; i < chunks; ++i) {
            size_t usize = 0;

            int ret = mbedtls_cipher_update(
                &ctx_,
                achunk.data() + i_index,
                bsize,
                poutput + o_index,
                &usize);

            if (ret < 0)
                return ret;

            i_index += bsize;
            o_index += usize;
        }

        osize = o_index;
        return 0; // success
    }

}; // struct cipher_impl

///////////////////////////////////////////////////////////////////////////////

class crypt_engine
{
    size_t        block_size_ = 0;
    size_t        chunks_     = 0;
    cipher_impl   cim_;
    buffer_view_t input_;

    explicit crypt_engine(cipher_t type, buffer_view_t input)
        : block_size_(cipher::block_size(type)), input_(input) {
        setup_chunks(type);
    }

    void setup_chunks(cipher_t type) {
        // compute number of chunks
        if (cipher::block_mode(type) == cipher_bm::ecb) {
            if (input_.size() == 0 || input_.size() % block_size_)
                throw exceptions::usage_error{
                    "ecb cipher block:"
                    " a valid input size must be dividable by block size"};

            chunks_ = input_.size() / block_size_;

        } else { // for any other cipher block do in single shot
            chunks_ = 1;
        }
    }

    void setup_engine(
        cipher_t      type,
        padding_t     pad,
        buffer_view_t iv,
        buffer_view_t key,
        cipher::mode  m) {
        cim_.setup(type).padding(pad).iv(iv).key(key, m);
    }

    constexpr size_t output_size() const noexcept {
        return 32 + input_.size() + block_size_;
    }

    size_t compute(uchars output) {
        size_t  final_size = 0;
        uchars  pDes       = output;
        cuchars pSrc       = input_.data();

        if (chunks_ == 1) {
            mbedcrypto_c_call(
                mbedtls_cipher_crypt,
                &cim_.ctx_,
                to_const_ptr(cim_.iv()),
                cim_.iv_size(),
                pSrc,
                input_.size(),
                pDes,
                &final_size);

        } else {
            final_size = 0;

            for (size_t i = 0; i < chunks_; ++i) {
                size_t done_size = 0;
                mbedcrypto_c_call(
                    mbedtls_cipher_crypt,
                    &cim_.ctx_,
                    to_const_ptr(cim_.iv()),
                    cim_.iv_size(),
                    pSrc,
                    block_size_,
                    pDes,
                    &done_size);

                final_size += done_size;
                pSrc += block_size_;
                pDes += block_size_;
            }
        }

        return final_size;
    }

public:
    template <typename TBuff>
    static TBuff
    run(cipher_t      type,
        padding_t     pad,
        buffer_view_t iv,
        buffer_view_t key,
        cipher::mode  m,
        buffer_view_t input) {

        // check cipher mode against input size
        crypt_engine cengine(type, input);
        cengine.setup_engine(type, pad, iv, key, m);

        TBuff output(cengine.output_size(), '\0');
        auto  written_size = cengine.compute(to_ptr(output));
        output.resize(written_size);
        return output;
    }

    template <typename TBuff>
    static TBuff pencrypt(
        cipher_t      type,
        padding_t     pad,
        buffer_view_t iv,
        buffer_view_t key,
        buffer_view_t input) {

        // check cipher mode against input size
        crypt_engine cengine(type, input);
        cengine.setup_engine(type, pad, iv, key, cipher::mode::encrypt_mode);

        TBuff output(cengine.output_size() + iv.size(), '\0');
        // prepend the iv to the output
        std::memcpy(to_ptr(output), iv.data(), iv.size());
        // offset the output by iv
        auto written_size = cengine.compute(to_ptr(output) + iv.size());
        output.resize(written_size + iv.size());
        return output;
    }

    template <typename TBuff>
    static TBuff pdecrypt(
        cipher_t type, padding_t pad, buffer_view_t key, buffer_view_t pinput) {

        buffer_view_t iv{pinput.data(), cipher::iv_size(type)};
        buffer_view_t input{pinput.data() + iv.size(),
                            pinput.size() - iv.size()};

        // check cipher mode against input size
        crypt_engine cengine(type, input);
        cengine.setup_engine(type, pad, iv, key, cipher::mode::decrypt_mode);

        TBuff output(cengine.output_size(), '\0');
        auto  written_size = cengine.compute(to_ptr(output));
        output.resize(written_size);
        return output;
    }

}; // struct crypt_engine

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
struct cipher::impl : public cipher_impl {};

cipher::cipher(cipher_t type) : pimpl(std::make_unique<impl>()) {
    pimpl->setup(type);
}

cipher::~cipher() {}

bool
cipher::supports_aes_ni() {
#if defined(MBEDTLS_HAVE_X86_64) && defined(MBEDTLS_AESNI_C)
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
cipher::_encrypt(
    cipher_t      type,
    padding_t     pad,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t input) {
    return crypt_engine::run<buffer_t>(type, pad, iv, key, encrypt_mode, input);
}

buffer_t
cipher::_decrypt(
    cipher_t      type,
    padding_t     pad,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t input) {
    return crypt_engine::run<buffer_t>(type, pad, iv, key, decrypt_mode, input);
}

buffer_t
cipher::_pencrypt(
    cipher_t      type,
    padding_t     pad,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t input) {
    return crypt_engine::pencrypt<buffer_t>(type, pad, iv, key, input);
}

buffer_t
cipher::_pdecrypt(
    cipher_t type, padding_t pad, buffer_view_t key, buffer_view_t input) {
    return crypt_engine::pdecrypt<buffer_t>(type, pad, key, input);
}

#if defined(QT_CORE_LIB)
QByteArray
cipher::_qencrypt(
    cipher_t      type,
    padding_t     pad,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t input) {
    return crypt_engine::run<QByteArray>(type, pad, iv, key, encrypt_mode, input);
}

QByteArray
cipher::_qdecrypt(
    cipher_t      type,
    padding_t     pad,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t input) {
    return crypt_engine::run<QByteArray>(type, pad, iv, key, decrypt_mode, input);
}

QByteArray
cipher::_qpencrypt(
    cipher_t      type,
    padding_t     pad,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t input) {
    return crypt_engine::pencrypt<QByteArray>(type, pad, iv, key, input);
}

QByteArray
cipher::_qpdecrypt(
    cipher_t type, padding_t pad, buffer_view_t key, buffer_view_t input) {
    return crypt_engine::pdecrypt<QByteArray>(type, pad, key, input);
}
#endif // QT_CORE_LIB

bool
cipher::supports_aead() {
#if defined(MBEDTLS_CIPHER_MODE_AEAD)
    return true;
#endif
    return false;
}

std::tuple<buffer_t, buffer_t>
cipher::encrypt_aead(
    cipher_t      type,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t ad,
    buffer_view_t input) {
#if defined(MBEDTLS_CIPHER_MODE_AEAD)

    cipher::impl cip;
    cip.setup(type);
    cip.key(key, cipher::encrypt_mode);

    size_t   olen = input.size() + cip.block_size();
    buffer_t output(olen, '\0');
    buffer_t tag(16, '\0');

    mbedcrypto_c_call(
        mbedtls_cipher_auth_encrypt,
        &cip.ctx_,
        iv.data(),
        iv.size(),
        ad.data(),
        ad.size(),
        input.data(),
        input.size(),
        to_ptr(output),
        &olen,
        to_ptr(tag),
        16);

    output.resize(olen);
    return std::make_tuple(tag, output);

#else // MBEDTLS_CIPHER_MODE_AEAD
    throw exceptions::aead_error{};
#endif
}

std::tuple<bool, buffer_t>
cipher::decrypt_aead(
    cipher_t      type,
    buffer_view_t iv,
    buffer_view_t key,
    buffer_view_t ad,
    buffer_view_t tag,
    buffer_view_t input) {
#if defined(MBEDTLS_CIPHER_MODE_AEAD)

    cipher::impl cip;
    cip.setup(type);
    cip.key(key, cipher::decrypt_mode);

    size_t   olen = input.size() + cip.block_size();
    buffer_t output(olen, '\0');

    int ret = mbedtls_cipher_auth_decrypt(
        &cip.ctx_,
        iv.data(),
        iv.size(),
        ad.data(),
        ad.size(),
        input.data(),
        input.size(),
        to_ptr(output),
        &olen,
        tag.data(),
        tag.size());

    output.resize(olen);

    if (ret == MBEDTLS_ERR_CIPHER_AUTH_FAILED)
        return std::make_tuple(false, output);
    else if (ret == 0)
        return std::make_tuple(true, output);

    // ret is non zero
    throw exception{ret, __FUNCTION__};

#else // MBEDTLS_CIPHER_MODE_AEAD
    throw exceptions::aead_error{};
#endif
}

cipher&
cipher::iv(buffer_view_t iv_data) {
    pimpl->iv(iv_data);
    return *this;
}

cipher&
cipher::key(buffer_view_t key_data, mode m) {
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
    pimpl->reset_last_iv();
    mbedcrypto_c_call(mbedtls_cipher_reset, &pimpl->ctx_);
}

buffer_t
cipher::update(buffer_view_t input) {
    size_t   osize = input.size() + pimpl->block_size() + 32;
    buffer_t output(osize, '\0');

    if (block_mode() == cipher_bm::ecb) {
        int ret = pimpl->update_chunked(input, to_ptr(output), osize);
        if (ret != 0)
            throw exception{ret, __FUNCTION__};

    } else {
        mbedcrypto_c_call(
            mbedtls_cipher_update,
            &pimpl->ctx_,
            input.data(),
            input.size(),
            to_ptr(output),
            &osize);
    }

    output.resize(osize);
    return output;
}

size_t
cipher::update(
    buffer_view_t input,
    size_t        in_index,
    size_t        count,
    buffer_t&     output,
    size_t        out_index) {
    size_t usize = 0;

    if (block_mode() == cipher_bm::ecb) {
        int ret = pimpl->update_chunked(
            {input.data() + in_index, count}, to_ptr(output) + out_index, usize);
        if (ret != 0)
            throw exception{ret, __FUNCTION__};

    } else {
        mbedcrypto_c_call(
            mbedtls_cipher_update,
            &pimpl->ctx_,
            input.data() + in_index,
            count,
            to_ptr(output) + out_index,
            &usize);
    }

    return usize;
}

int
cipher::update(
    buffer_view_t input, unsigned char* output, size_t& output_size) noexcept {
    if (block_mode() == cipher_bm::ecb) {
        return pimpl->update_chunked(input, output, output_size);
    }

    // for other block modes
    return mbedtls_cipher_update(
        &pimpl->ctx_, input.data(), input.size(), output, &output_size);
}

buffer_t
cipher::finish() {
    size_t   osize = pimpl->block_size() + 32;
    buffer_t output(osize, '\0');

    mbedcrypto_c_call(
        mbedtls_cipher_finish, &pimpl->ctx_, to_ptr(output), &osize);

    output.resize(osize);
    return output;
}

size_t
cipher::finish(buffer_t& output, size_t out_index) {
    size_t fsize = 0;
    mbedcrypto_c_call(
        mbedtls_cipher_finish,
        &pimpl->ctx_,
        to_ptr(output) + out_index,
        &fsize);

    return fsize;
}

int
cipher::finish(unsigned char* output, size_t& output_size) noexcept {
    return mbedtls_cipher_finish(&pimpl->ctx_, output, &output_size);
}

buffer_t
cipher::crypt(buffer_view_t input) {
    start();

    const size_t osize = 32 + input.size() + pimpl->block_size();
    buffer_t     output(osize, '\0');
    auto*        out_ptr = to_ptr(output);

    size_t out_index = 0;
    mbedcrypto_c_call(
        mbedtls_cipher_update,
        &pimpl->ctx_,
        input.data(),
        input.size(),
        out_ptr,
        &out_index);

    size_t fin_len = 0;
    mbedcrypto_c_call(
        mbedtls_cipher_finish, &pimpl->ctx_, out_ptr + out_index, &fin_len);

    output.resize(out_index + fin_len);
    return output;
}

void
cipher::gcm_additional_data(buffer_view_t ad) {
#if defined(MBEDTLS_GCM_C)
    mbedcrypto_c_call(
        mbedtls_cipher_update_ad, &pimpl->ctx_, ad.data(), ad.size());

#else  // MBEDTLS_
    throw exceptions::gcm_error{};
#endif // MBEDTLS_
}

buffer_t
cipher::gcm_encryption_tag(size_t length) {
#if defined(MBEDTLS_GCM_C)
    buffer_t tag(length, '\0');
    mbedcrypto_c_call(
        mbedtls_cipher_write_tag, &pimpl->ctx_, to_ptr(tag), length);

    return tag;
#else  // MBEDTLS_
    throw exceptions::gcm_error{};
#endif // MBEDTLS_
}

bool
cipher::gcm_check_decryption_tag(buffer_view_t tag) {
#if defined(MBEDTLS_GCM_C)
    int ret =
        mbedtls_cipher_check_tag(&pimpl->ctx_, tag.data(), tag.size());

    switch (ret) {
    case 0:
        return true; // authneticated
    case MBEDTLS_ERR_CIPHER_AUTH_FAILED:
        return false; // authentication failed

    default: // other ret codes means error in data or context
        throw exception{ret, __FUNCTION__};
        break;
    }
#else  // MBEDTLS_GCM_C
    throw exceptions::gcm_error{};
#endif // MBEDTLS_GCM_C
}
///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
