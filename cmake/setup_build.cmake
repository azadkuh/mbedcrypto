
# check for compiler and host os
string(REGEX MATCH "Clang"  IS_CLANG "${CMAKE_CXX_COMPILER_ID}")
string(REGEX MATCH "GNU"    IS_GNUXX "${CMAKE_CXX_COMPILER_ID}")
string(REGEX MATCH "Linux"  IS_LINUX "${CMAKE_SYSTEM_NAME}")
string(REGEX MATCH "Darwin" IS_MACOS "${CMAKE_SYSTEM_NAME}")

# checks for c++17 support
set(HAS_MODERN_COMPILER OFF)
if((IS_CLANG  AND ${CMAKE_CXX_COMPILER_VERSION} VERSION_GREATER_EQUAL "7.0") OR
    (IS_GNUXX AND ${CMAKE_CXX_COMPILER_VERSION} VERSION_GREATER_EQUAL "7.0") OR
    (MSVC     AND ${CMAKE_CXX_COMPILER_VERSION} VERSION_GREATER_EQUAL "19.13"))
    set(HAS_MODERN_COMPILER ON)
endif()

#------------------------------------------------------------------------------
# common properties and platform/compiler specific options

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Release or Debug?" FORCE)
endif()

if(${CMAKE_SIZEOF_VOID_P} LESS 8)
    set(ARCH_TYPE 32)
else()
    set(ARCH_TYPE 64)
endif()
message(STATUS "compiling by ${CMAKE_CXX_COMPILER_ID}"
    "(v${CMAKE_CXX_COMPILER_VERSION}) ${ARCH_TYPE}bit ...")
