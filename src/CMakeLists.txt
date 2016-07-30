project(mbedcrypto)

# modify this file to add/remove features and modules from mbedtls
add_definitions( -DMBEDTLS_CONFIG_FILE=\"mbedcrypto_mbedtls_config.h\" )

# mbedcrypto main files
set(MBEDCRYPTO_SRC
    ../src/exception.cpp
    ../src/conversions.cpp
    ../src/types.cpp
    ../src/tcodec.cpp
    ../src/hash.cpp
    ../src/cipher.cpp
    ../src/mpi.cpp
    ../src/rnd_generator.cpp
    ../src/pk.cpp
    ../src/rsa.cpp
    )

# mandatory mbedtls sources
set(MBEDTLS_PATH "../3rdparty/mbedtls/library")
set(MBEDTLS_SRC
    ${MBEDTLS_PATH}/error.c
    ${MBEDTLS_PATH}/base64.c
    ${MBEDTLS_PATH}/md5.c
    ${MBEDTLS_PATH}/sha1.c
    ${MBEDTLS_PATH}/sha256.c
    ${MBEDTLS_PATH}/sha512.c
    ${MBEDTLS_PATH}/md_wrap.c
    ${MBEDTLS_PATH}/md.c
    ${MBEDTLS_PATH}/aes.c
    ${MBEDTLS_PATH}/aesni.c
    ${MBEDTLS_PATH}/cipher_wrap.c
    ${MBEDTLS_PATH}/cipher.c
    ${MBEDTLS_PATH}/entropy.c
    ${MBEDTLS_PATH}/entropy_poll.c
    ${MBEDTLS_PATH}/ctr_drbg.c
    ${MBEDTLS_PATH}/rsa.c
    ${MBEDTLS_PATH}/pem.c
    ${MBEDTLS_PATH}/bignum.c
    ${MBEDTLS_PATH}/oid.c
    ${MBEDTLS_PATH}/asn1parse.c
    ${MBEDTLS_PATH}/pkparse.c
    ${MBEDTLS_PATH}/pk_wrap.c
    ${MBEDTLS_PATH}/pk.c
    ${MBEDTLS_PATH}/oid.c
    ${MBEDTLS_PATH}/platform.c
    )

# optional mbedtls definitions and sources based on specified options
#  message digests (hashes)
if(BUILD_MD2)
    set(MBEDTLS_MD2_C ON)
    list(APPEND MBEDTLS_SRC ${MBEDTLS_PATH}/md2.c)
endif()
if(BUILD_MD4)
    set(MBEDTLS_MD4_C ON)
    list(APPEND MBEDTLS_SRC ${MBEDTLS_PATH}/md4.c)
endif()
if(BUILD_RIPEMD160)
    set(MBEDTLS_RIPEMD160_C ON)
    list(APPEND MBEDTLS_SRC ${MBEDTLS_PATH}/ripemd160.c)
endif()

if(BUILD_ALL_CIPHER_PADDINGS)
    set(MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS ON)
    set(MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN ON)
    set(MBEDTLS_CIPHER_PADDING_ZEROS ON)
endif()

#  cipher block modes
if(BUILD_CFB)
    set(MBEDTLS_CIPHER_MODE_CFB ON)
endif()
if(BUILD_CTR)
    set(MBEDTLS_CIPHER_MODE_CTR ON)
endif()
if(BUILD_GCM)
    set(MBEDTLS_GCM_C ON)
    list(APPEND MBEDTLS_SRC ${MBEDTLS_PATH}/gcm.c)
endif()
if(BUILD_CCM)
    set(MBEDTLS_CCM_C ON)
    list(APPEND MBEDTLS_SRC ${MBEDTLS_PATH}/ccm.c)
endif()

#  cipher algorithms
if(BUILD_DES)
    set(MBEDTLS_DES_C ON)
    list(APPEND MBEDTLS_SRC ${MBEDTLS_PATH}/des.c)
endif()
if(BUILD_BLOWFISH)
    set(MBEDTLS_BLOWFISH_C ON)
    list(APPEND MBEDTLS_SRC ${MBEDTLS_PATH}/blowfish.c)
endif()
if(BUILD_CAMELLIA)
    set(MBEDTLS_CAMELLIA_C ON)
    list(APPEND MBEDTLS_SRC ${MBEDTLS_PATH}/camellia.c)
endif()
if(BUILD_ARC4)
    set(MBEDTLS_ARC4_C ON)
    list(APPEND MBEDTLS_SRC ${MBEDTLS_PATH}/arc4.c)
endif()

#  public key options
if(BUILD_PK_EXPORT)
    set(MBEDTLS_ASN1_WRITE_C ON)
    set(MBEDTLS_PK_WRITE_C ON)
    set(MBEDTLS_PEM_WRITE_C ON)
    list(APPEND MBEDTLS_SRC
        ${MBEDTLS_PATH}/asn1write.c
        ${MBEDTLS_PATH}/pkwrite.c)
endif()
if(BUILD_RSA_KEYGEN)
    set(MBEDTLS_GENPRIME ON)
endif()
if(BUILD_EC)
    set(MBEDTLS_ECP_C ON)
    SET(MBEDTLS_ECDH_C ON)
    set(MBEDTLS_DHM_C ON)
    set(MBEDTLS_ECDSA_C ON)
    set(MBEDTLS_ECP_DP_SECP192R1_ENABLED ON)
    set(MBEDTLS_ECP_DP_SECP224R1_ENABLED ON)
    set(MBEDTLS_ECP_DP_SECP256R1_ENABLED ON)
    set(MBEDTLS_ECP_DP_SECP384R1_ENABLED ON)
    set(MBEDTLS_ECP_DP_SECP521R1_ENABLED ON)
    set(MBEDTLS_ECP_DP_SECP192K1_ENABLED ON)
    set(MBEDTLS_ECP_DP_SECP224K1_ENABLED ON)
    set(MBEDTLS_ECP_DP_SECP256K1_ENABLED ON)
    set(MBEDTLS_ECP_DP_BP256R1_ENABLED ON)
    set(MBEDTLS_ECP_DP_BP384R1_ENABLED ON)
    set(MBEDTLS_ECP_DP_BP512R1_ENABLED ON)
    set(MBEDTLS_ECP_DP_CURVE25519_ENABLED ON)
    list(APPEND MBEDTLS_SRC
        ${MBEDTLS_PATH}/ecp.c
        ${MBEDTLS_PATH}/ecp_curves.c
        ${MBEDTLS_PATH}/dhm.c
        ${MBEDTLS_PATH}/ecdh.c
        ${MBEDTLS_PATH}/ecdsa.c
        )
    list(APPEND MBEDCRYPTO_SRC
        ../src/ecp.cpp
        )
endif()

# cofig.h file
configure_file(mbedcrypto_mbedtls_config.h.in ${CMAKE_BINARY_DIR}/mbedcrypto_mbedtls_config.h)

# libraries

add_library(mbedcrypto ${MBEDCRYPTO_SRC})
set_target_properties(mbedcrypto PROPERTIES
    SOVERSION 1
    VERSION 1.0.0
    )

# mbedtls parts
if(BUILD_SINGLE_LIB)
    target_sources(mbedcrypto PRIVATE ${MBEDTLS_SRC})
else()
    add_library(mbedtls ${MBEDTLS_SRC})
    target_link_libraries(mbedcrypto mbedtls)
endif()

if(BUILD_QT5_BIND)
    qt5_use_modules(mbedcrypto Core)
endif()
