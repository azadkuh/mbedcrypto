cmake_minimum_required(VERSION 3.8)
project(mbedcrypto
    VERSION 1.0.0
    LANGUAGES C CXX
    )

#-----------------------------------------------------------------------------
# options
# cryptograohic features
## optional hash algorithms:
option(MBEDCRYPTO_MD2       "enable md2 hash (insecure and deprecated)" OFF)
option(MBEDCRYPTO_MD4       "enable md4 hash"                           OFF)
option(MBEDCRYPTO_RIPEMD160 "enable ripemd160 hash"                     OFF)

## optional cipher block modes:
option(MBEDCRYPTO_CFB "enable cfb (cipher feedback mode)"                      OFF)
option(MBEDCRYPTO_CTR "enable ctr (cipher counter mode)"                       ON)
option(MBEDCRYPTO_GCM "enable gcm (Galois cipher mode, for aead cryptography)" ON)
option(MBEDCRYPTO_CCM
    "enable ccm (counter cbc-mac cipher mode, for aead cryptography)" ON)

## optional cipher algorithms:
## note: AES is the de facto mandatory algorithm (not optional)
option(MBEDCRYPTO_DES      "enable des and triple-des cipher" OFF)
option(MBEDCRYPTO_BLOWFISH "enable blowfish cipher"           OFF)
option(MBEDCRYPTO_CAMELLIA "enable camellia cipher"           OFF)
option(MBEDCRYPTO_ARC4     "enable arc4 cipher (insecure)"    OFF)

## optional pk algorithm
option(MBEDCRYPTO_PK_EXPORT  "enable export keys in pem or der format"  ON)
option(MBEDCRYPTO_RSA_KEYGEN "enable rsa key generator"                 ON)
option(MBEDCRYPTO_EC         "enable eckey, eckey_dh, ecdsa algorithms" OFF)

option(MBEDCRYPTO_Qt5        "adds adaptors around Qt5/QByteArray" OFF)
option(MBEDCRYPTO_STATIC_CRT "build by static c/c++ runtime"       ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Choose the type of build: Release Debug"
        FORCE)
endif()
if(WIN32)
    option(BUILD_AS_X32XP "build for a 32bit (XP/2003) targets" OFF)
endif()

option(BUILD_TESTS "build test units and apps" ON)
#------------------------------------------------------------------------------
enable_testing()

# sub-projects
add_subdirectory(src)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()

##-----------------------------------------------------------------------------
## misc stuff
if(UNIX)
    ## doxygen
    ADD_CUSTOM_TARGET(docs
        COMMAND doxygen ./mbedcrypto.doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
    ADD_CUSTOM_TARGET(clean_docs
        COMMAND rm -rf ./docs
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
endif()

