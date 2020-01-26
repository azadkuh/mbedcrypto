# common properties and platform/compiler specific options

# make compile_commands.json for vim,clang-tidy,ycm,qtcreator, ...
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# placement of 3rdparty dependencies (see setup.sh)
set(DIR_DEPS "${CMAKE_SOURCE_DIR}/.3rdparty" CACHE PATH "3rdparties and dependencies")

# check for compiler and host os
string(REGEX MATCH "Clang"  IS_CLANG "${CMAKE_CXX_COMPILER_ID}")
string(REGEX MATCH "GNU"    IS_GNUXX "${CMAKE_CXX_COMPILER_ID}")
string(REGEX MATCH "Linux"  IS_LINUX "${CMAKE_SYSTEM_NAME}")
string(REGEX MATCH "Darwin" IS_MACOS "${CMAKE_SYSTEM_NAME}")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Release or Debug?" FORCE)
endif()

if(${CMAKE_SIZEOF_VOID_P} LESS 8)
    set(ARCH_TYPE 32)
else()
    set(ARCH_TYPE 64)
endif()
message(STATUS "[[using: "
    "${CMAKE_CXX_COMPILER_ID}(v${CMAKE_CXX_COMPILER_VERSION})"
    "${ARCH_TYPE}bit]]")

#------------------------------------------------------------------------------

# common settings for compilers
function(mbedcrypto_setup_platforms tgt)
    target_compile_features(${tgt} PRIVATE cxx_std_14)
    if(IS_GNUXX OR IS_CLANG)
        target_compile_options(${tgt} PRIVATE
            -Wall -Wextra -Wpedantic -pedantic-errors
            -Wwrite-strings -Wcast-align -Wpointer-arith
            -Wno-c++98-compat -Wno-unused-parameter
            $<$<COMPILE_LANGUAGE:CXX>:-Werror -Wsign-conversion -Wnon-virtual-dtor -Woverloaded-virtual>
            $<$<C_COMPILER_ID:GNU>:-Wshadow=local>
            $<$<C_COMPILER_ID:Clang,AppleClang>:-Wshadow>
            $<$<CONFIG:Release>:-fvisibility=hidden>
            )
    elseif(MSVC)
        target_compile_options(${tgt} PRIVATE
            -W3 -nologo -MP -Zc:strictStrings
            )
    endif()
    if(WIN32)
        # base definitions
        target_compile_definitions(${tgt} PRIVATE
            -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_CRT_SECURE_NO_WARNINGS
            -D_UNICODE -DUNICODE
            )
        if(${ARCH_TYPE} EQUAL 64)
            target_compile_definitions(${tgt} PRIVATE -DWIN64)
        endif()
    endif()
endfunction()

# setup c/c++ runtime
function(mbedcrypto_setup_crt tgt)
    if(IS_GNUXX)
        if(MBEDCRYPTO_STATIC_CRT)
            target_link_options(${tgt} PRIVATE -static-libstdc++ -static-libgcc)
        endif()
    elseif(MSVC)
        foreach(flag
                CMAKE_C_FLAGS_RELEASE   CMAKE_C_FLAGS_MINSIZEREL   CMAKE_C_FLAGS_DEBUG
                CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_DEBUG
                )
            if(MBEDCRYPTO_STATIC_CRT)
                string(REGEX REPLACE "/MD" "/MT" ${flag} "${${flag}}")
            else()
                string(REGEX REPLACE "/MT" "/MD" ${flag} "${${flag}}")
            endif()
            set(${flag} "${${flag}}" CACHE STRING "msvc flags" FORCE)
        endforeach()
    endif()
endfunction()
