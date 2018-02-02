cmake_minimum_required(VERSION 3.0)
project(mbedcrypto CXX)
enable_testing()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(PlatformSetup)
if (BUILD_QT5_BIND)
    include(Qt5)
endif()

#-----------------------------------------------------------------------------
# options
option(BUILD_SINGLE_LIB  "merge mbedcrypto and mbedtls into a single library"   ON)
option(BUILD_QT5_BIND    "also adds adaptors around Qt5/QByteArray"             OFF)
option(BUILD_TESTS       "build test units and apps"                            ON)
option(BUILD_SHARED_LIBS "build mbedcrypto as a unix shared (so/dylib) library" OFF)

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
option(BUILD_PK_EXPORT  "enable export keys in pem or der format"   ON)
option(BUILD_RSA_KEYGEN "enable rsa key generator"                  ON)
option(BUILD_EC         "enable eckey, eckey_dh, ecdsa algorithms " OFF)


#-----------------------------------------------------------------------------
# common directories
get_filename_component(PARENT_DIR ${CMAKE_SOURCE_DIR} DIRECTORY)
set(DIR_XBIN     ${PARENT_DIR}/${PROJECT_NAME}.xbin${ARCH_TYPE})
set(DIR_3RDPARTY ${CMAKE_SOURCE_DIR}/3rdparty)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${DIR_XBIN})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${DIR_XBIN})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${DIR_XBIN})
set(INSTALL_DIR_INCLUDE include/mbedcrypto)
set(INSTALL_DIR_LIBRARY lib)
set(INSTALL_DIR_RUNTIME bin)

#-----------------------------------------------------------------------------
# sub-projects
add_subdirectory(src)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()


#-----------------------------------------------------------------------------
# misc stuff
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

