cmake_minimum_required(VERSION 3.8)
project(mbedcrypto
    VERSION 1.0.0
    LANGUAGES C CXX
    )

#-----------------------------------------------------------------------------
# options
option(BUILD_TESTS          "build test units and apps"           ON)
option(BUILD_QT5_BIND       "adds adaptors around Qt5/QByteArray" OFF)
option(BUILD_STATIC_RUNTIME "build by static c/c++ runtime"       ON)

# cryptograohic features
## optional hash algorithms:
option(BUILD_MD2       "enable md2 hash (insecure and deprecated)" OFF)
option(BUILD_MD4       "enable md4 hash"                           OFF)
option(BUILD_RIPEMD160 "enable ripemd160 hash"                     OFF)

## optional cipher padding modes:
## (pkc7 is always built and does not depend on this option)
option(BUILD_ALL_CIPHER_PADDINGS
    "add one_and_zeros, zeros_and_length and zeros modes"
    ON)

## optional cipher block modes:
option(BUILD_CFB "enable cfb (cipher feedback mode)"                      OFF)
option(BUILD_CTR "enable ctr (cipher counter mode)"                       ON)
option(BUILD_GCM "enable gcm (Galois cipher mode, for aead cryptography)" ON)
option(BUILD_CCM
    "enable ccm (counter cbc-mac cipher mode, for aead cryptography)"
    ON)

## optional cipher algorithms:
option(BUILD_DES      "enable des and triple-des cipher" ON)
option(BUILD_BLOWFISH "enable blowfish cipher"           OFF)
option(BUILD_CAMELLIA "enable camellia cipher"           OFF)
option(BUILD_ARC4     "enable arc4 cipher (insecure)"    OFF)

## optional pk algorithm
option(BUILD_PK_EXPORT  "enable export keys in pem or der format"  ON)
option(BUILD_RSA_KEYGEN "enable rsa key generator"                 ON)
option(BUILD_EC         "enable eckey, eckey_dh, ecdsa algorithms" OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Choose the type of build: Release Debug"
        FORCE)
endif()
if(WIN32)
    option(BUILD_AS_X32XP "build for a 32bit (XP/2003) targets" OFF)
endif()

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

