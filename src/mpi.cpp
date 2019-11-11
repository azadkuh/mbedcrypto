#include "./mpi_impl.hpp"

//-----------------------------------------------------------------------------
namespace mbedcrypto {
//-----------------------------------------------------------------------------

struct mpi::impl : mpi_impl {};

mpi::mpi() : pimpl{std::make_unique<impl>()} {}

mpi::~mpi() = default;

void
mpi::reset() noexcept {
    return pimpl->reset();
}

size_t
mpi::bitlen() const noexcept {
    return pimpl->bitlen();
}

size_t
mpi::size() const noexcept {
    return pimpl->size();
}

int
mpi::compare(const mpi& o) const noexcept {
    return pimpl->compare(*o.pimpl);
}

std::error_code
mpi::to_string(bin_edit_t& out, int radix) const noexcept {
    return pimpl->to_string(out, radix);
}

std::error_code
mpi::to_string(obuffer_t&& out, int radix) const {
    return pimpl->to_string(std::forward<obuffer_t>(out), radix);
}

std::error_code
mpi::from_string(const char* cstr, int radix) noexcept {
    return pimpl->from_string(cstr, radix);
}

std::error_code
mpi::to_binary(bin_edit_t& out) const noexcept {
    return pimpl->to_binary(out);
}

std::error_code
mpi::to_binary(obuffer_t&& out) const {
    return pimpl->to_binary(std::forward<obuffer_t>(out));
}

std::error_code
mpi::from_binary(bin_view_t bin) noexcept {
    return pimpl->from_binary(bin);
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
