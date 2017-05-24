include(CheckCXXCompilerFlag)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_STANDARD_REQUIRED ON)

string(REGEX MATCH "Clang"  IS_CLANG "${CMAKE_CXX_COMPILER_ID}")
string(REGEX MATCH "GNU"    IS_GNUXX "${CMAKE_CXX_COMPILER_ID}")
string(REGEX MATCH "Linux"  IS_LINUX "${CMAKE_SYSTEM_NAME}")
string(REGEX MATCH "Darwin" IS_MACOS "${CMAKE_SYSTEM_NAME}")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Choose the type of build: Release Debug"
        FORCE)
endif()

# custom build options
option(BUILD_AS_STATIC "build against static c++ runtime" OFF)

# os dependent configs
if(IS_LINUX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
elseif(IS_MACOS)
    option(BUILD_AS_BUNDLE "make MacOS bundle apps"    OFF)
    if(BUILD_SHARED_LIBS)
        message("@warning: rpath is skipped by default under OS X")
        set(CMAKE_SKIP_RPATH TRUE)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
    endif()
elseif(WIN32)
    option(BUILD_AS_X32   "build for a 32bit (Win7+) targets"   OFF)
    option(BUILD_AS_X32XP "build for a 32bit (XP/2003) targets" OFF)
    # base definitions
    add_definitions(-D_WINDOWS -DWIN32 -DNDEBUG
        -DWIN32_LEAN_AND_MEAN -DNOMINMAX
        -D_UNICODE -DUNICODE -D_CRT_SECURE_NO_WARNINGS
        )
    # old win32_xp sdk, needs to redefine windows version macro
    # may needd a toolset flag as -T v140_xp for cmake
    if(BUILD_AS_X32XP)
        add_definitions(-D_WIN32_WINNT=0x0502 -DWINVER=0x0502)
    else()
        add_definitions(-DWIN64)
    endif()
endif()

# architecture type, 32bit is only tested under windows (static Qt libs)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "[AMD64|x86_64]" AND NOT (BUILD_AS_X32 OR BUILD_AS_X32XP))
    message(STATUS "compiling on x64 system ...")
    set(ARCH_TYPE 64)
else()
    message(STATUS "compiling on x32 system ...")
    set(ARCH_TYPE 32)
endif()

# compiler dependent settings
if(IS_CLANG OR IS_GNUXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
        -Wall -Wextra -W -Wwrite-strings -Wshadow -pedantic -Wcast-align \
        -Wunused -Wno-unused-parameter -Wpointer-arith \
        -Wnon-virtual-dtor -Woverloaded-virtual")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -g0")
    set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g3")

    if(BUILD_AS_STATIC AND IS_GNUXX)
         set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
            -static-libstdc++ -static-libgcc")
    endif()

elseif(MSVC)
    set(CMAKE_C_FLAGS_RELEASE   "-nologo -Zc:wchar_t -FS -O2 -MD -Zc:strictStrings -W3 -MP")
    set(CMAKE_C_FLAGS_DEBUG     "${CMAKE_C_FLAGS_DEBUG} -MDd -MP")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
    set(CMAKE_CXX_FLAGS_DEBUG   "${CMAKE_C_FLAGS_DEBUG}")

    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE
            "${CMAKE_SHARED_LINKER_FLAGS_RELASE} /Gy /GF /OPT:REF /OPT:ICF")

    if(BUILD_AS_STATIC)
        string(REPLACE "-MD"  "-MT"  CMAKE_C_FLAGS_RELEASE   "${CMAKE_C_FLAGS_RELEASE}")
        string(REPLACE "-MD"  "-MT"  CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
        string(REPLACE "-MDd" "-MTd" CMAKE_C_FLAGS_DEBUG     "${CMAKE_C_FLAGS_DEBUG}")
        string(REPLACE "-MDd" "-MTd" CMAKE_CXX_FLAGS_DEBUG   "${CMAKE_CXX_FLAGS_DEBUG}")
    endif()
endif()
