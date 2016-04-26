cmake_minimum_required(VERSION 3.0)
project("mbedcrypto" CXX)

option(BUILD_SHARED_LIBS "build mbedcrypto as a unix shared (so/dylib) library" OFF)
option(BUILD_TESTS       "build test units and apps" ON)

# optional hash algorithms:
option(BUILD_MD2       "enable md2 hash (unsecure and deprecated)" OFF)
option(BUILD_MD4       "enable md4 hash" OFF)
option(BUILD_RIPEMD160 "enable ripemd160 hash" OFF)

# optional cipher padding modes: (pkc7 is always built and does not depend on this option)
option(BUILD_ALL_CIPHER_PADDINGS
    "add one_and_zeros, zeros_and_length and zeros modes"
    ON)

# optional cipher block modes:
option(BUILD_CFB "enable cfb (cipher feedback mode)" OFF)
option(BUILD_CTR "enable ctr (cipher counter mode)" ON)
option(BUILD_GCM "enable gcm (Galois cipher mode, for aead cryptography)" ON)
option(BUILD_CCM "enable ccm (counter cbc-mac cipher mode, for aead cryptography)" ON)

# optional cipher algorithms:
option(BUILD_DES      "enable des and triple-des cipher" ON)
option(BUILD_BLOWFISH "enable blowfish cipher" OFF)
option(BUILD_CAMELLIA "enable camellia cipher" OFF)
option(BUILD_ARC4     "enable arc4 cipher (unsecure)" OFF)

# optional pk algorithm
option(BUILD_PK_EXPORT  "enable export keys in pem or der format" ON)
option(BUILD_RSA_KEYGEN "enable rsa key generator" ON)
option(BUILD_EC         "enable eckey and eckey_dh public key algorithms " OFF)
option(BUILD_ECDSA      "enable ecdsa algorithms" OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Choose the type of build: None Release ASan MemSan Debug"
        FORCE)
endif()

# compiler checks and flags
include(CheckCXXCompilerFlag)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_STANDARD_REQUIRED ON)
string(REGEX MATCH "Clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_CXX_COMPILER_ID}")
string(REGEX MATCH "GNU"   CMAKE_COMPILER_IS_GNUXX "${CMAKE_CXX_COMPILER_ID}")

if(CMAKE_COMPILER_IS_CLANG OR CMAKE_COMPILER_IS_GNUXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -W -Wwrite-strings -Wshadow -pedantic -Wcast-align -Wunused -Wno-unused-parameter -Wpointer-arith")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3")
    set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g3")

    if(CMAKE_COMPILER_IS_GNUXX)
        set(CMAKE_CXX_FLAGS_ASAN   "-Werror -fsanitize=address -fno-common -O3")
    elseif(CMAKE_COMPILER_IS_CLANG)
        set(CMAKE_CXX_FLAGS_ASAN   "-Werror -fsanitize=address -fno-common -fno-sanitize-recover -O3")
        set(CMAKE_CXX_FLAGS_MEMSAN "-Werror -fsanitize=memory -O3")
    endif()

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wnon-virtual-dtor -Woverloaded-virtual")

elseif(MSVC)
    if(BUILD_SHARED_LIBS)
        add_definitions(-DMBEDCRYPTO_DYNAMIC -DMBEDCRYPTO_EXPORT)
        message(SEND_ERROR
           "@error: BUILD_SHARED_LIBS=ON is not implemented under Visual Studio"
           " due to stl and __declspec(dllexport) incompatibility.\n"
           " please compile as a static library until someone resolves this problem."
           )
    endif()

    set(CMAKE_CXX_FLAGS_RELEASE "-nologo -Zm200 -Zc:wchar_t -FS -O2 -MD -Zc:strictStrings -W3")

endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin" AND BUILD_SHARED_LIBS)
    message("@warning: rpath is skipped by default under OS X")
    set(CMAKE_SKIP_RPATH TRUE)
endif()


# output directory
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/xbin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/xbin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/xbin)

include_directories(.
    ./include
    ./3rdparty/mbedtls/include
    ./3rdparty/Catch/single_include
    ${CMAKE_CURRENT_BINARY_DIR}
    )

add_subdirectory(src)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()


if(UNIX)
    ADD_CUSTOM_TARGET(docs
        COMMAND doxygen ./mbedcrypto.doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
    ADD_CUSTOM_TARGET(clean_docs
        COMMAND rm -rf ./docs
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
endif()
