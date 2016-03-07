#include "mbedcrypto/exception.hpp"

#include <sstream>
#include "mbedtls/error.h"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

std::string
exception::error_string()const {
    if ( code_ == 0 )
        return std::string{};

    std::string message(160, '\0'); // mbedtls error strings are smaller than this
    mbedtls_strerror(code_, &message.front(), message.size()-1);
    message.resize(std::strlen(message.data()));

    return message;
}

std::string
exception::to_string()const {
    const char* w = what();
    if ( code_ == 0 )
        return w;

    std::stringstream ss;
    if ( std::strlen(w) > 0 )
        ss << w << " ";

    ss << "(" << code_ << "): " << error_string();
    return ss.str();
}


///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
