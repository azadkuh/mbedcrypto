#include "mbedcrypto/mbedtls_wrapper.hxx"

#include <iostream>
#include <memory>

///////////////////////////////////////////////////////////////////////////////
int
main(int, char**) {

    try {
        mbedtls::md      md1;
        mbedtls::cipher  cc1;
        mbedtls::rnd_gen rg1;
        mbedtls::entropy en1;
        mbedtls::pki     pk1;

        mbedtls_c_call(mbedtls_md_starts, md1);

    } catch (std::exception& cerr) {
        std::cerr << "the desired error message:\n  " << cerr.what()
                  << std::endl;
    }

    return 0;
}
