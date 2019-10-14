#include "mbedcrypto/errors.hpp"

#include <mbedtls/error.h>
//-----------------------------------------------------------------------------
namespace mbedcrypto {
namespace {
//-----------------------------------------------------------------------------

/// mbedtls error codes
struct mbedtls_category : std::error_category
{
    ~mbedtls_category() override = default;

    const char* name() const noexcept override {
        return "mbedtls";
    }

    std::string message(int err) const override {
        std::string msg;
        if (err != 0) {
            constexpr size_t MaxSize           = 127;
            char             buff[MaxSize + 1] = {0};
            mbedtls_strerror(err, buff, MaxSize);
            msg = buff;
        }
        return msg;
    }
}; // struct mbedtls_category

//-----------------------------------------------------------------------------

struct mbedcrypto_category : std::error_category
{
    ~mbedcrypto_category() override = default;

    const char* name() const noexcept override {
        return "mbedcrypto";
    }

    std::string message(int err) const override {
        switch (err) {
        case static_cast<int>(error_t::success):
            return "success";
        case static_cast<int>(error_t::type):
            return "invalid or unknown type";
        case static_cast<int>(error_t::usage):
            return "bad api call or invalid argument";
        case static_cast<int>(error_t::not_supported):
            return "not supported by this build";
        case static_cast<int>(error_t::invalid_size):
            return "invalid size";
        case static_cast<int>(error_t::invalid_content):
            return "invalid content/data";
        case static_cast<int>(error_t::bad_hash):
            return "invalid or unsupported hash type";
        case static_cast<int>(error_t::bad_cipher):
            return "invalid or unsupported cipher type";
        case static_cast<int>(error_t::aead):
            return "requires CCM or GCM modules, check build options";
        case static_cast<int>(error_t::gcm):
            return "requires CGM module, check build options";
        case static_cast<int>(error_t::pk):
            return "invalid or unsupported PK type";
        case static_cast<int>(error_t::pk_export):
            return "requires PE_EXPORT module, check build options";
        case static_cast<int>(error_t::rsa_keygen):
            return "requires RSA_KEYGEN, check build options";
        case static_cast<int>(error_t::ecp):
            return "invalid or unsupported EC (elliptic curve) type";
        default:
            return "unknown error";
        }
    }

}; // struct mbedcrypto_category

//-----------------------------------------------------------------------------
} // namespace anon
//-----------------------------------------------------------------------------

namespace mbedtls {
const std::error_category&
error_category() {
    static mbedtls_category ecat;
    return ecat;
}
} // namespace mbedtls

//-----------------------------------------------------------------------------

const std::error_category&
error_category() {
    static mbedcrypto_category ecat;
    return ecat;
}

//-----------------------------------------------------------------------------
} // namespace mbedcrypto
//-----------------------------------------------------------------------------
