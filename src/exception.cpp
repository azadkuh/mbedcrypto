#include "mbedcrypto/exception.hpp"

#include <sstream>
#include <cstring>
#include "mbedtls/error.h"
#include "mbedtls/cipher.h"
#include "mbedtls/pk.h"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

std::string
mbedtls_error_string(int err, const char* message) {
    if ( err == 0 ) {
        return (message) ? std::string(message) : std::string();
    }

    constexpr size_t KMaxSize = 160;
    char buffer[KMaxSize+1] = {0};
    mbedtls_strerror(err, buffer, KMaxSize);

    std::stringstream ss;
    if ( message  &&  std::strlen(message) > 0 )
        ss << message;
    ss << "(-0x" << std::hex << -1*err << "): " << buffer;
    return ss.str();
}

///////////////////////////////////////////////////////////////////////////////

type_exception::type_exception() :
    exception("invalid or unknown type") {
}

support_exception::support_exception() :
    exception("not supported and/or implemented yet") {
}

unknown_hash_exception::unknown_hash_exception() :
    exception(MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE, "unsupported hash") {
}

unknown_cipher_exception::unknown_cipher_exception() :
    exception(MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE, "unsupported cipher") {
}

aead_exception::aead_exception() :
    exception("needs CCM or GCM module, check build options"){
}

gcm_exception::gcm_exception() :
    exception("needs GCM module, check build options") {
}

unknown_pk_exception::unknown_pk_exception() :
    exception(MBEDTLS_ERR_PK_UNKNOWN_PK_ALG, "unsupported pk") {
}

pk_export_exception::pk_export_exception() :
    exception("needs PK_EXPORT, check build options") {
}

rsa_keygen_exception::rsa_keygen_exception() :
    exception("needs RSA_KEYGEN, check build options") {
}

ecp_exception::ecp_exception() :
    exception("needs EC (elliptic curves), check build options") {
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
