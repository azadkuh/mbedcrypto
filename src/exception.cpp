#include "mbedcrypto/exception.hpp"

#include "mbedtls/cipher.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"

#include <cstring>
#include <sstream>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

std::string
mbedtls_error_string(int err, const char* message) {
    if (err == 0) {
        return (message) ? std::string(message) : std::string();
    }

    constexpr size_t KMaxSize             = 160;
    char             buffer[KMaxSize + 1] = {0};
    mbedtls_strerror(err, buffer, KMaxSize);

    std::stringstream ss;
    if (message && std::strlen(message) > 0)
        ss << message;
    ss << "(-0x" << std::hex << -1 * err << "): " << buffer;
    return ss.str();
}

///////////////////////////////////////////////////////////////////////////////
namespace exceptions {
///////////////////////////////////////////////////////////////////////////////

type_error::type_error()
    : exception("invalid or unknown type, or conversion error") {}

support_error::support_error()
    : exception("not supported and/or implemented yet") {}

unknown_hash::unknown_hash()
    : exception(MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE, "unsupported hash") {}

unknown_cipher::unknown_cipher()
    : exception(MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE, "unsupported cipher") {}

aead_error::aead_error()
    : exception("needs CCM or GCM module, check build options") {}

gcm_error::gcm_error() : exception("needs GCM module, check build options") {}

unknown_pk::unknown_pk()
    : exception(MBEDTLS_ERR_PK_UNKNOWN_PK_ALG, "unsupported pk") {}

pk_export_missed::pk_export_missed()
    : exception("needs PK_EXPORT, check build options") {}

rsa_keygen_missed::rsa_keygen_missed()
    : exception("needs RSA_KEYGEN, check build options") {}

ecp_missed::ecp_missed()
    : exception("needs EC (elliptic curves), check build options") {}

///////////////////////////////////////////////////////////////////////////////
} // namespace exceptions
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
