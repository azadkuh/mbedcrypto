#include "mbedcrypto/mpi.hpp"
#include "pk_private.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<mpi>::value == false, "");
static_assert(std::is_move_constructible<mpi>::value == true,  "");
///////////////////////////////////////////////////////////////////////////////

struct mpi::impl
{
    mbedtls_mpi ctx_;

public:
    explicit impl() {
        mbedtls_mpi_init(&ctx_);
    }

    ~impl() {
        mbedtls_mpi_free(&ctx_);
    }

}; // struct mpi::impl

///////////////////////////////////////////////////////////////////////////////

mpi::mpi() : pimpl(std::make_unique<impl>()) {
}

mpi::~mpi() {
}

void
mpi::reset() {
    mbedtls_mpi_free(&pimpl->ctx_);
}

const mpi::impl&
mpi::context()const {
    return *pimpl;
}

mpi::impl&
mpi::context() {
    return *pimpl;
}

size_t
mpi::bitlen()const noexcept {
    return mbedtls_mpi_bitlen(&pimpl->ctx_);
}

size_t
mpi::size()const noexcept {
    return mbedtls_mpi_size(&pimpl->ctx_);
}

std::string
mpi::to_string(int radix)const {
    size_t olen = 0;

    // get the string size
    mbedtls_mpi_write_string(
            &pimpl->ctx_,
            radix,
            nullptr,
            0,
            &olen
            );

    std::string buffer(olen+1, '\0');
    mbedcrypto_c_call(mbedtls_mpi_write_string,
            &pimpl->ctx_,
            radix,
            &buffer.front(),
            olen,
            &olen
            );

    // remove trailing null byte
    buffer.resize(olen-1);
    return buffer;
}

std::string
mpi::dump()const {
    std::string buffer(size(), '\0');
    mbedcrypto_c_call(mbedtls_mpi_write_binary,
            &pimpl->ctx_,
            to_ptr(buffer),
            buffer.size()
            );
    return buffer;
}

void
operator<<(mpi& m, const mbedtls_mpi& p) {
    mbedcrypto_c_call(mbedtls_mpi_copy,
            &m.context().ctx_,
            &p
            );
}

void
operator>>(const mpi& m, mbedtls_mpi& p) {
    mbedcrypto_c_call(mbedtls_mpi_copy,
            &p,
            &m.context().ctx_
            );
}


///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
