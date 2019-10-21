cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(mbedcrypto
    VERSION 1.0.0
    LANGUAGES C CXX
    )

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/setup_build.cmake")

#-----------------------------------------------------------------------------
# options
# cryptograohic features
## optional hash algorithms:
## note: md5, sha1/sha224/sha256/sha384/sha512 are mandatory (not optional)
option(MBEDCRYPTO_MD2       "enable md2 hash (insecure and deprecated)" OFF)
option(MBEDCRYPTO_MD4       "enable md4 hash"                           OFF)
option(MBEDCRYPTO_RIPEMD160 "enable ripemd160 hash"                     OFF)

## optional cipher block modes:
## note: ecb and cbc are mandatory (not optional)
option(MBEDCRYPTO_BM_CFB "enable cfb (cipher feedback mode)"                               OFF)
option(MBEDCRYPTO_BM_OFB "enable ofb (output feedback mode)"                               OFF)
option(MBEDCRYPTO_BM_CTR "enable ctr (cipher counter mode)"                                OFF)
option(MBEDCRYPTO_BM_XTS "enable xts (cipher text stealing mode)"                          OFF)
option(MBEDCRYPTO_BM_GCM "enable gcm (Galois cipher mode, for aead cryptography)"          OFF)
option(MBEDCRYPTO_BM_CCM "enable ccm (counter cbc-mac cipher mode, for aead cryptography)" OFF)

## optional cipher algorithms:
## note: AES is the de facto mandatory algorithm (not optional)
option(MBEDCRYPTO_ARIA     "enable aria cipher"                      OFF)
option(MBEDCRYPTO_BLOWFISH "enable blowfish cipher"                  OFF)
option(MBEDCRYPTO_CAMELLIA "enable camellia cipher"                  OFF)
option(MBEDCRYPTO_CHACHA20 "enable chacha20 & chacha20_poly ciphers" OFF)
option(MBEDCRYPTO_DES      "enable des and triple-des cipher"        OFF)
option(MBEDCRYPTO_ARC4     "enable arc4 cipher (insecure)"           OFF)

## optional pk algorithm
## note: rsa is mandatory (not optional)
option(MBEDCRYPTO_PK_EXPORT  "enable export keys in pem or der format"  ON)
option(MBEDCRYPTO_RSA_KEYGEN "enable rsa key generator"                 ON)
option(MBEDCRYPTO_EC         "enable eckey, eckey_dh, ecdsa algorithms" OFF)

# other build options
option(MBEDCRYPTO_Qt5        "adds adaptors around Qt5/QByteArray" OFF)
option(MBEDCRYPTO_STATIC_CRT "build by static c/c++ runtime"       ON)


#------------------------------------------------------------------------------
# sub-projects
add_subdirectory(src)

option(BUILD_TESTS "build test units and apps" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

