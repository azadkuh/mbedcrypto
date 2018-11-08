# some hacks for building mbedcrypto under:
#  - static c++/c runtime library
#  - win32_xp old toolset

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Release or Debug?" FORCE)
endif()

#------------------------------------------------------------------------------
if (WIN32 AND ${CMAKE_SIZEOF_VOID_P} LESS 8)
    option(BUILD_TOOLSET_XP "build for old x32 (XP/2003) targets" OFF)
    message(STATUS "compiling on x32 system ...")
else()
    message(STATUS "compiling on x64 system ...")
endif()

#------------------------------------------------------------------------------
macro(target_prepare_build_flags tgt)
    if(MBEDCRYPTO_Qt5)
        find_package(Qt5Core)
        target_link_libraries(${tgt} PUBLIC Qt5::Core)
    endif()
    if(UNIX)
        find_package(Threads REQUIRED)
        target_link_libraries(${tgt} PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
    elseif(WIN32)
        target_compile_definitions(${tgt} PUBLIC
            -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_CRT_SECURE_NO_WARNINGS
            # old win32_xp sdk, needs to redefine windows version macro
            # may needd a toolset flag as -T v140_xp for cmake
            $<$<BOOL:BUILD_TOOLSET_XP>:-D_WIN32_WINNT=0x0502 -DWINVER=0x0502>
            )
    endif()
    if(MSVC)
        if(MBEDCRYPTO_STATIC_CRT)
            set(_src_opt "/MD")
            set(_dst_opt "/MT")
        else()
            set(_src_opt "/MT")
            set(_dst_opt "/MD")
        endif()
        foreach(flag
                CMAKE_C_FLAGS   CMAKE_C_FLAGS_RELEASE   CMAKE_C_FLAGS_DEBUG
                CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_DEBUG
                )
            string(REGEX REPLACE ${_src_opt} ${_dst_opt} ${flag} "${${flag}}")
            set(${flag} "${${flag}}" CACHE STRING "msvc flags" FORCE)
        endforeach()
    endif()
endmacro()

macro(target_prepare_runtime_crt tgt)
    if (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU" AND MBEDCRYPTO_STATIC_CRT)
        set_target_properties(${tgt} PROPERTIES
            LINK_FLAGS "-s -static-libstdc++ -static-libgcc"
            )
    endif()
endmacro()

#------------------------------------------------------------------------------
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

