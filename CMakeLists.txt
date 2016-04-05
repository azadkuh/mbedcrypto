cmake_minimum_required(VERSION 3.0)

option(BUILD_SHARED_LIBS "build mbedcrypto as a unix shared (so/dylib) library" OFF)
option(BUILD_TESTS "build test units and apps" ON)

# optional hash algorithms:
option(BUILD_MD2       "enable md2 hash (unsecure and deprecated)" OFF)
option(BUILD_MD4       "enable md4 hash" OFF)
option(BUILD_RIPEMD160 "enable ripemd160 hash" OFF)

# optional cipher padding modes: (pkc7 is always built and does not depend on this option)
option(BUILD_ALL_CIPHER_PADDINGS
    "add one_and_zeros, zeros_and_length and zeros modes"
    ON)

# optional cipher block modes:
option(BUILD_CFB "enable cfb (cipher feedback mode)" ON)
option(BUILD_CTR "enable ctr (cipher counter mode)" ON)
option(BUILD_GCM "enable gcm (Galois cipher mode, for aead cryptography)" OFF)
option(BUILD_CCM "enable ccm (counter cbc-mac cipher mode, for aead cryptography)" OFF)

# optional cipher algorithms:
option(BUILD_DES      "enable des and triple-des cipher" ON)
option(BUILD_BLOWFISH "enable blowfish cipher" OFF)
option(BUILD_CAMELLIA "enable camellia cipher" OFF)
option(BUILD_ARC4     "enable arc4 cipher (unsecure)" OFF)

# compiler checks and flags
include(CheckCXXCompilerFlag)

if(CMAKE_C_COMPILER_ID MATCHES ".*Clang" OR CMAKE_C_COMPILER_ID MATCHES "GNU")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -g0 -Wall -Wextra -pedantic -Wcast-align -Wunused -Wno-unused-parameter")
    set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS} -std=c++1y -Wnon-virtual-dtor -Woverloaded-virtual")
elseif(CMAKE_C_COMPILER_ID MATCHES "MSVC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nologo -Zm200 -Zc:wchar_t -FS -O2 -MD -Zc:strictStrings -W3")
    if(BUILD_SHARED_LIBS)
        add_definitions(-DMBEDCRYPTO_DYNAMIC -DMBEDCRYPTO_EXPORT)
        message(SEND_ERROR
           "@error: BUILD_SHARED_LIBS=ON is not implemented under Visual Studio"
           " due to stl and __declspec(dllexport) incompatibility.\n"
           " please compile as a static library until someone resolves this problem."
           )
    endif()
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
