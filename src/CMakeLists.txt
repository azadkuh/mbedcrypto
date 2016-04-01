project(mbedcrypto)

# modify this file to add/remove features and modules from mbedtls
add_definitions( -DMBEDTLS_CONFIG_FILE=\"mbedcrypto_mbedtls_config.h\" )

file(GLOB mbedcrypto_src
    ../include/mbedcrypto/**.hpp
    ../src/**.hpp
    ../src/**.cpp
    )

add_library(mbedcrypto ${mbedcrypto_src})
set_target_properties(mbedcrypto PROPERTIES
    SOVERSION 1
    VERSION 1.0.0
    )

# add mandatory mbedtls sources
set(MBEDTLS_PATH "../3rdparty/mbedtls/library")
target_sources(mbedcrypto PRIVATE
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

#optional mbedtls definitions and sources based on specified options

if(BUILD_MD2)
    set(MBEDTLS_MD2_C ON)
    target_sources(mbedcrypto PRIVATE ${MBEDTLS_PATH}/md2.c)
endif()
if(BUILD_MD4)
    set(MBEDTLS_MD4_C ON)
    target_sources(mbedcrypto PRIVATE ${MBEDTLS_PATH}/md4.c)
endif()
if(BUILD_RIPEMD160)
    set(MBEDTLS_RIPEMD160_C ON)
    target_sources(mbedcrypto PRIVATE ${MBEDTLS_PATH}/ripemd160.c)
endif()

if(BUILD_ALL_CIPHER_PADDINGS)
    set(MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS ON)
    set(MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN ON)
    set(MBEDTLS_CIPHER_PADDING_ZEROS ON)
endif()

if(BUILD_CFB)
    set(MBEDTLS_CIPHER_MODE_CFB ON)
endif()
if(BUILD_CTR)
    set(MBEDTLS_CIPHER_MODE_CTR ON)
endif()
if(BUILD_GCM)
    set(MBEDTLS_GCM_C ON)
    target_sources(mbedcrypto PRIVATE ${MBEDTLS_PATH}/gcm.c)
endif()
if(BUILD_CCM)
    set(MBEDTLS_CCM_C ON)
    target_sources(mbedcrypto PRIVATE ${MBEDTLS_PATH}/ccm.c)
endif()

if(BUILD_DES)
    set(MBEDTLS_DES_C ON)
    target_sources(mbedcrypto PRIVATE ${MBEDTLS_PATH}/des.c)
endif()
if(BUILD_BLOWFISH)
    set(MBEDTLS_BLOWFISH_C ON)
    target_sources(mbedcrypto PRIVATE ${MBEDTLS_PATH}/blowfish.c)
endif()
if(BUILD_CAMELLIA)
    set(MBEDTLS_CAMELLIA_C ON)
    target_sources(mbedcrypto PRIVATE ${MBEDTLS_PATH}/camellia.c)
endif()
if(BUILD_ARC4)
    set(MBEDTLS_ARC4_C ON)
    target_sources(mbedcrypto PRIVATE ${MBEDTLS_PATH}/arc4.c)
endif()


configure_file(mbedcrypto_mbedtls_config.h.in ${CMAKE_BINARY_DIR}/mbedcrypto_mbedtls_config.h)
