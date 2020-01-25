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

function(mbedcrypto_setup_platforms tgt)
    target_compile_features(${tgt} PRIVATE cxx_std_14)
    if(IS_GNUXX OR IS_CLANG)
        _setup_clang_gxx_options(${tgt})
    elseif(MSVC)
        _setup_msvc_options(${tgt})
    endif()
    if(WIN32)
        _setup_win32_builds(${tgt})
    endif()
endfunction()

#------------------------------------------------------------------------------
# private api
function(_setup_clang_gxx_options tgt)
    target_compile_options(${tgt} PRIVATE
        -Wall -Wextra -W -Wwrite-strings -Wshadow=local -pedantic -Wcast-align
        -Wunused -Wno-unused-parameter -Wpointer-arith
        $<$<COMPILE_LANGUAGE:CXX>:-Wnon-virtual-dtor -Woverloaded-virtual>
        $<$<CONFIG:Release>:-fvisibility=hidden>
        )
    if (MBEDCRYPTO_STATIC_CRT)
        if(IS_GNUXX)
            target_link_options(${tgt} PRIVATE -static-libstdc++ -static-libgcc)
        endif()
    endif()
endfunction()

function(_setup_msvc_options tgt)
    target_compile_options(${tgt} PRIVATE -W3 -nologo -MP -Zc:strictStrings)
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
endfunction()

function(_setup_win32_builds tgt)
    # base definitions
    target_compile_definitions(${tgt} PRIVATE
        -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_CRT_SECURE_NO_WARNINGS
        -D_UNICODE -DUNICODE
        )
    if(${ARCH_TYPE} EQUAL 64)
        target_compile_definitions(${tgt} PRIVATE -DWIN64)
    endif()
endfunction()
