cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(libmbedcrypto
    VERSION      2.0.0
    DESCRIPTION  "a portable, small and fast c++14 library for cryptography"
    HOMEPAGE_URL "https://github.com/azadkuh/mbedcrypto"
    )

include("${CMAKE_SOURCE_DIR}/cmake/setup_platforms.cmake")

#-----------------------------------------------------------------------------
# build options

# cryptographic features

## optional hash algorithms:
## note: md5, sha1/sha224/sha256/sha384/sha512 are mandatory (not optional)
option(MBEDCRYPTO_HASH_MD2       "md2 hash (not recommended)" OFF)
option(MBEDCRYPTO_HASH_MD4       "md4 hash (not recommended)" OFF)
option(MBEDCRYPTO_HASH_RIPEMD160 "ripemd160 hash"             OFF)

## optional cipher block modes:
## note: ecb and cbc are mandatory (not optional)
option(MBEDCRYPTO_BM_CFB "cipher feedback mode"                   OFF)
option(MBEDCRYPTO_BM_OFB "output feedback mode"                   OFF)
option(MBEDCRYPTO_BM_CTR "cipher counter mode"                    OFF)
option(MBEDCRYPTO_BM_XTS "cipher text stealing mode"              OFF)
option(MBEDCRYPTO_BM_CCM "counter cbc-mac cipher mode (@sa AEAD)" OFF)
option(MBEDCRYPTO_BM_GCM "Galois cipher mode (@sa AEAD)"          ON)

## optional cipher algorithms:
## note: AES is the de facto mandatory algorithm (not optional)
option(MBEDCRYPTO_CIPHER_ARIA     "aria cipher"                       OFF)
option(MBEDCRYPTO_CIPHER_BLOWFISH "blowfish cipher"                   OFF)
option(MBEDCRYPTO_CIPHER_CAMELLIA "camellia cipher"                   OFF)
option(MBEDCRYPTO_CIPHER_CHACHA20 "chacha20 & chacha20_poly ciphers"  OFF)
option(MBEDCRYPTO_CIPHER_DES      "DES/3DES cipher (not recommended)" OFF)
option(MBEDCRYPTO_CIPHER_ARC4     "arc4 cipher (insecure)"            OFF)

## optional pk algorithm
## note: rsa is mandatory (not optional)
option(MBEDCRYPTO_PK_KEYGEN "private/public key generator" ON)
option(MBEDCRYPTO_PK_EC     "elliptic-curve algorithms"    OFF)

#------------------------------------------------------------------------------
# sub-projects
add_subdirectory(src)

option(BUILD_TESTS "build test units and apps" ON)
if(BUILD_TESTS)
    option(MBEDCRYPTO_STATIC_CRT "build test app by static c/c++ runtime" ON)
    enable_testing()
    add_subdirectory(tests)
endif()

