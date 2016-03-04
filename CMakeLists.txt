cmake_minimum_required(VERSION 3.1)

include(CheckCXXCompilerFlag)

if ( CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "GNU" )
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -g0 -Wall -Wextra -pedantic -Wcast-align -Wunused -Wno-unused-parameter")
    set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS} -std=c++1y -Wnon-virtual-dtor -Woverloaded-virtual")
elseif ( CMAKE_C_COMPILER_ID STREQUAL "MSVS" )
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nologo -Zm200 -Zc:wchar_t -FS -O2 -MD -Zc:strictStrings -W3")
endif()

if ( ${CMAKE_SYSTEM_NAME} MATCHES "Linux" )
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()


add_definitions()

include_directories(. ./include
    ./3rdparty/mbedtls/include
    ./3rdparty/Catch/single_include
    )

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/xbin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/xbin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/xbin)

add_subdirectory(src)
add_subdirectory(tests)
