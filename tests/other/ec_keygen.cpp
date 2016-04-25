#include "mbedcrypto/pki.hpp"
#include "mbedcrypto/random.hpp"

#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedcrypto/mbedtls_wrapper.hxx"

#include <initializer_list>
#include <iostream>

namespace {
using cuchars = const unsigned char*;
using uchars  = unsigned char*;

///////////////////////////////////////////////////////////////////////////////
int
my_random1(void* prng, unsigned char* output, size_t olen) {
    auto* rnd = reinterpret_cast<mbedtls_ctr_drbg_context*>(prng);
    return mbedtls_ctr_drbg_random(rnd, output, olen);
}

void
test1() {
    static const char gibberish[] = "a ec creator sample";
    mbedtls::entropy entropy;
    mbedtls::rnd_gen ctr_drbg;
    mbedtls::pki     pk;

    mbedtls_c_call(mbedtls_ctr_drbg_seed,
            ctr_drbg,
            mbedtls_entropy_func,
            entropy,
            reinterpret_cast<cuchars>(gibberish),
            std::strlen(gibberish)
            );
    mbedtls_c_call(mbedtls_pk_setup,
            pk,
            mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)
            );
    mbedtls_c_call(mbedtls_ecp_gen_key,
            MBEDTLS_ECP_DP_SECP192K1,
            mbedtls_pk_ec(pk.ref()),
            my_random1,
            ctr_drbg
            );

    std::cout << "raw c: successful. done!" << std::endl;
}

int
my_random2(void* prng, unsigned char* output, size_t olen) {
    auto* rnd = reinterpret_cast<mbedcrypto::random*>(prng);
    return rnd->make(output, olen);
}

void
test2() {
    using namespace mbedcrypto;
    mbedcrypto::random rnd{"mbedcrypto sample implementation for you"};
    mbedtls::pki pk;

    mbedcrypto_c_call(mbedtls_pk_setup,
            pk,
            mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)
            );
    mbedcrypto_c_call(mbedtls_ecp_gen_key,
            MBEDTLS_ECP_DP_SECP192R1,
            mbedtls_pk_ec(pk.ref()),
            my_random2,
            &rnd
            );

    std::cout << "mbedcrypto::random: successful. done!" << std::endl;
}


void
test3() {
    using namespace mbedcrypto;
    pki pk(pk_t::eckey);
    pk.ec_generate_key(curve_t::secp192r1);

    std::cout << "mbedcrypto::pki: successful. done!" << std::endl;
}

} // namespace anon
///////////////////////////////////////////////////////////////////////////////
int
main(int argc, char *argv[]) {
    using namespace mbedcrypto;

    int test_num = 2;
    if ( argc == 2 )
        test_num = std::stoi(argv[1]);

    try {
        switch ( test_num ) {
            case 1: test1(); break;
            case 2: test2(); break;
            case 3: test3(); break;

            default:
                break;
        }

    } catch ( exception& cerr ) {
        std::cerr << cerr.what() << std::endl;
    }

    return 0;
}


