#include "mbedcrypto/exception.hpp"

#include <sstream>
#include <cstring>
#include "mbedtls/error.h"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

std::string
exception::error_string()const {
    if ( code_ == 0 )
        return std::string{};
    return mbedtls_error_string(code_);
}

std::string
exception::to_string()const {
    const char* w = what();
    if ( code_ == 0 )
        return w;

    if ( std::strlen(w) == 0 )
        return mbedtls_error_string(code_);

    return std::string(w) + " " + mbedtls_error_string(code_);
}

///////////////////////////////////////////////////////////////////////////////

std::string
mbedtls_error_string(int err) {
    constexpr size_t KMaxSize = 160;
    char buffer[KMaxSize+1] = {0};
    mbedtls_strerror(err, buffer, KMaxSize);

    std::stringstream ss;
    ss << "(-0x" << std::hex << -1*err << "): " << buffer;
    return ss.str();
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
