project(mbedcrypto CXX)

set(MBEDTLS_SRCDIR ${CMAKE_SOURCE_DIR}/3rdparty/mbedtls/library)
set(MBEDTLS_INCDIR ${CMAKE_SOURCE_DIR}/3rdparty/mbedtls/include)
#------------------------------------------------------------------------------
# mbedcrypto main files
add_library(${PROJECT_NAME}
    ${MBEDTLS_SRCDIR}/error.c
    ${MBEDTLS_SRCDIR}/base64.c
    ${MBEDTLS_SRCDIR}/md5.c
    ${MBEDTLS_SRCDIR}/sha1.c
    ${MBEDTLS_SRCDIR}/sha256.c
    ${MBEDTLS_SRCDIR}/sha512.c
    ${MBEDTLS_SRCDIR}/md_wrap.c
    ${MBEDTLS_SRCDIR}/md.c
    ${MBEDTLS_SRCDIR}/aes.c
    ${MBEDTLS_SRCDIR}/aesni.c
    ${MBEDTLS_SRCDIR}/padlock.c
    ${MBEDTLS_SRCDIR}/cipher_wrap.c
    ${MBEDTLS_SRCDIR}/cipher.c
    ${MBEDTLS_SRCDIR}/entropy.c
    ${MBEDTLS_SRCDIR}/entropy_poll.c
    ${MBEDTLS_SRCDIR}/ctr_drbg.c
    ${MBEDTLS_SRCDIR}/rsa.c
    ${MBEDTLS_SRCDIR}/rsa_internal.c
    ${MBEDTLS_SRCDIR}/pem.c
    ${MBEDTLS_SRCDIR}/bignum.c
    ${MBEDTLS_SRCDIR}/oid.c
    ${MBEDTLS_SRCDIR}/asn1parse.c
    ${MBEDTLS_SRCDIR}/pkparse.c
    ${MBEDTLS_SRCDIR}/pk_wrap.c
    ${MBEDTLS_SRCDIR}/pk.c
    ${MBEDTLS_SRCDIR}/oid.c
    ${MBEDTLS_SRCDIR}/platform_util.c
    ${MBEDTLS_SRCDIR}/platform.c
    exception.cpp
    conversions.cpp
    types.cpp
    tcodec.cpp
    hash.cpp
    cipher.cpp
    mpi.cpp
    rnd_generator.cpp
    pk.cpp
    rsa.cpp
    )

# optional mbedtls definitions and sources based on specified options
#  message digests (hashes)
if(MBEDCRYPTO_MD2)
    set(MBEDTLS_MD2_C ON)
    target_sources(${PROJECT_NAME} PRIVATE ${MBEDTLS_SRCDIR}/md2.c)
endif()
if(MBEDCRYPTO_MD4)
    set(MBEDTLS_MD4_C ON)
    target_sources(${PROJECT_NAME} PRIVATE ${MBEDTLS_SRCDIR}/md4.c)
endif()
if(MBEDCRYPTO_RIPEMD160)
    set(MBEDTLS_RIPEMD160_C ON)
    target_sources(${PROJECT_NAME} PRIVATE ${MBEDTLS_SRCDIR}/ripemd160.c)
endif()

#  cipher block modes
if(MBEDCRYPTO_CFB)
    set(MBEDTLS_CIPHER_MODE_CFB ON)
endif()
if(MBEDCRYPTO_CTR)
    set(MBEDTLS_CIPHER_MODE_CTR ON)
endif()
if(MBEDCRYPTO_GCM)
    set(MBEDTLS_GCM_C ON)
    target_sources(${PROJECT_NAME} PRIVATE ${MBEDTLS_SRCDIR}/gcm.c)
endif()
if(MBEDCRYPTO_CCM)
    set(MBEDTLS_CCM_C ON)
    target_sources(${PROJECT_NAME} PRIVATE ${MBEDTLS_SRCDIR}/ccm.c)
endif()

#  cipher algorithms
if(MBEDCRYPTO_DES)
    set(MBEDTLS_DES_C ON)
    target_sources(${PROJECT_NAME} PRIVATE ${MBEDTLS_SRCDIR}/des.c)
endif()
if(MBEDCRYPTO_BLOWFISH)
    set(MBEDTLS_BLOWFISH_C ON)
    target_sources(${PROJECT_NAME} PRIVATE ${MBEDTLS_SRCDIR}/blowfish.c)
endif()
if(MBEDCRYPTO_CAMELLIA)
    set(MBEDTLS_CAMELLIA_C ON)
    target_sources(${PROJECT_NAME} PRIVATE ${MBEDTLS_SRCDIR}/camellia.c)
endif()
if(MBEDCRYPTO_ARC4)
    set(MBEDTLS_ARC4_C ON)
    target_sources(${PROJECT_NAME} PRIVATE ${MBEDTLS_SRCDIR}/arc4.c)
endif()

#  public key options
if(MBEDCRYPTO_PK_EXPORT)
    set(MBEDTLS_ASN1_WRITE_C ON)
    set(MBEDTLS_PK_WRITE_C   ON)
    set(MBEDTLS_PEM_WRITE_C  ON)
    target_sources(${PROJECT_NAME} PRIVATE
        ${MBEDTLS_SRCDIR}/asn1write.c
        ${MBEDTLS_SRCDIR}/pkwrite.c
        )
endif()
if(MBEDCRYPTO_RSA_KEYGEN)
    set(MBEDTLS_GENPRIME ON)
endif()
if(MBEDCRYPTO_EC)
    set(MBEDTLS_ECP_C   ON)
    SET(MBEDTLS_ECDH_C  ON)
    set(MBEDTLS_DHM_C   ON)
    set(MBEDTLS_ECDSA_C ON)
    set(MBEDTLS_ECP_DP_SECP192R1_ENABLED  ON)
    set(MBEDTLS_ECP_DP_SECP224R1_ENABLED  ON)
    set(MBEDTLS_ECP_DP_SECP256R1_ENABLED  ON)
    set(MBEDTLS_ECP_DP_SECP384R1_ENABLED  ON)
    set(MBEDTLS_ECP_DP_SECP521R1_ENABLED  ON)
    set(MBEDTLS_ECP_DP_SECP192K1_ENABLED  ON)
    set(MBEDTLS_ECP_DP_SECP224K1_ENABLED  ON)
    set(MBEDTLS_ECP_DP_SECP256K1_ENABLED  ON)
    set(MBEDTLS_ECP_DP_BP256R1_ENABLED    ON)
    set(MBEDTLS_ECP_DP_BP384R1_ENABLED    ON)
    set(MBEDTLS_ECP_DP_BP512R1_ENABLED    ON)
    set(MBEDTLS_ECP_DP_CURVE25519_ENABLED ON)
    target_sources(${PROJECT_NAME} PRIVATE
        ${MBEDTLS_SRCDIR}/ecp.c
        ${MBEDTLS_SRCDIR}/ecp_curves.c
        ${MBEDTLS_SRCDIR}/dhm.c
        ${MBEDTLS_SRCDIR}/ecdh.c
        ${MBEDTLS_SRCDIR}/ecdsa.c
        ecp.cpp
        )
endif()

#------------------------------------------------------------------------------
configure_file(mbedcrypto_mbedtls_config.h.in
    ${CMAKE_BINARY_DIR}/mbedcrypto_mbedtls_config.h)
configure_file(mbedcrypto_config.h.in
    ${CMAKE_BINARY_DIR}/mbedcrypto_config.h)

target_prepare_build_flags(${PROJECT_NAME})
target_compile_definitions(${PROJECT_NAME} PRIVATE
    -DMBEDTLS_CONFIG_FILE=\"mbedcrypto_mbedtls_config.h\"
    )
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_14)
target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        $<BUILD_INTERFACE:${MBEDTLS_INCDIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}>
    )

#------------------------------------------------------------------------------
add_library(mbedcrypto::mbedcrypto ALIAS ${PROJECT_NAME})

#------------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME} EXPORT MbedCryptoConfig
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/mbedcrypto
    DESTINATION   ${CMAKE_INSTALL_INCLUDEDIR}
    )
install(FILES   ${CMAKE_BINARY_DIR}/mbedcrypto_config.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mbedcrypto
    )
install(EXPORT MbedCryptoConfig
    NAMESPACE mbedcrypto::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake
    )

