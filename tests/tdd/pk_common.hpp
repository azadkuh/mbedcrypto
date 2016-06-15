/** @file pk_common.hpp
 *
 * @copyright (C) 2016
 * @date 2016.05.14
 * @version 1.0.0
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef __PK_COMMON_HPP__
#define __PK_COMMON_HPP__

#include "mbedcrypto/ecp.hpp"
#include "mbedcrypto/rsa.hpp"
#include "mbedcrypto/tcodec.hpp"

#include "generator.hpp"

#include <iostream>
///////////////////////////////////////////////////////////////////////////////
namespace tests {
///////////////////////////////////////////////////////////////////////////////

inline std::ostream&
operator<<(std::ostream& s, const mbedcrypto::pk::action_flags& f) {
    auto bs = [](bool b) { return b ? "true" : "false"; };

    s << "encrypt: " << bs(f.encrypt) << " , "
      << "decrypt: " << bs(f.decrypt) << " , "
      << "sign: "    << bs(f.sign)    << " , "
      << "verify: "  << bs(f.verify);
    return s;
}

inline void
dumper(const char* name, const mbedcrypto::mpi& mpi) {
    using namespace mbedcrypto;

    std::cout << name << ": (size = "
        << mpi.size() << " , " << mpi.bitlen() << ")\n"
        << mpi.to_string(16) << "\n"
        << to_hex(mpi.dump()) << std::endl;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace tests
///////////////////////////////////////////////////////////////////////////////
#endif // __PK_COMMON_HPP__
