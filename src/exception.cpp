#include "mbedcrypto/exception.hpp"

#include <sstream>
#include <cstring>
#include "mbedtls/error.h"
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
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
