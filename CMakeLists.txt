cmake_minimum_required(VERSION 3.0)
option(BUILD_SHARED_LIBS
    "build mbedcrypto as a unix shared (so/dylib) library"
    OFF)

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


include_directories(.
    ./include
    ./3rdparty/mbedtls/include
    ./3rdparty/Catch/single_include
    )

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/xbin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/xbin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/xbin)

add_subdirectory(src)
add_subdirectory(tests)
