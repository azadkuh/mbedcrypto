#include "mbedcrypto/mpi.hpp"
#include "pk_private.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////
static_assert(std::is_copy_constructible<mpi>::value == true, "");
static_assert(std::is_move_constructible<mpi>::value == true, "");
///////////////////////////////////////////////////////////////////////////////

mpi::mpi() : pimpl{std::make_unique<impl>()} {
}

mpi::mpi(const mpi& other) : mpi() {
    pimpl->copy_from(*other.pimpl);
}

mpi::mpi(mpi&& other) : pimpl{std::move(other.pimpl)} {
}

mpi::~mpi() {
}

mpi&
mpi::operator=(const mpi& other) {
    pimpl->copy_from(*other.pimpl);
    return *this;
}

mpi&
mpi::operator=(mpi&& other) {
    pimpl.swap(other.pimpl);
    return *this;
}

void
mpi::reset() {
    mbedtls_mpi_free(&pimpl->ctx_);
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

int
mpi::compare(const mpi& a, const mpi& b) noexcept {
    return mbedtls_mpi_cmp_mpi(&a.pimpl->ctx_, &b.pimpl->ctx_);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
