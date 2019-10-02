
# public api
function(setup_build_options tgt)
    target_compile_features(${tgt}    PUBLIC cxx_std_14)
    target_compile_definitions(${tgt} PUBLIC $<$<BOOL:MBEDCRYPTO_STATIC_CRT>:MBEDCRYPTO_STATIC_CRT>)
    if(WIN32)
        _setup_win32_builds(${tgt})
    endif()
    if(IS_GNUXX OR IS_CLANG)
        _setup_clang_gcc_options(${tgt})
    elseif(MSVC)
        _setup_msvc_options(${tgt})
    endif()
endfunction()

# private api
function(_setup_clang_gcc_options tgt)
    target_compile_options(${tgt} PUBLIC
        -Wall -Wextra -W -Wwrite-strings -Wshadow -pedantic -Wcast-align
        -Wunused -Wno-unused-parameter -Wpointer-arith
        -Wnon-virtual-dtor -Woverloaded-virtual
        $<$<CONFIG:Release>:-fvisibility=hidden>
        )
    find_package(Threads REQUIRED)
    target_link_libraries(${tgt} PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
    if(IS_GNUXX OR (IS_CLANG AND IS_LINUX))
        # use same settings for clang++/g++ under linux
        # as clang++ does not support c++17 stl completely (filesystem, ...)
        # these flags can not be set by set_target_properties() / target_compile_options()
        set(flag ${CMAKE_CXX_FLAGS})
        string(REPLACE "-static-libstdc++" ""  flag "${flag}")
        string(REPLACE "-static-libgcc"    ""  flag "${flag}")
        string(REGEX REPLACE " +"          " " flag "${flag}") # remove extra whitespaces
        if (MBEDCRYPTO_STATIC_CRT)
            set(flag "${flag} -static-libstdc++ -static-libgcc")
        endif()
        set(CMAKE_CXX_FLAGS "${flag}" CACHE STRING "" FORCE)
    endif()
endfunction()

function(_setup_win32_builds tgt)
    # base definitions
    target_compile_definitions(${tgt} PUBLIC
        -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_CRT_SECURE_NO_WARNINGS
        -D_UNICODE -DUNICODE
        )
    if(${ARCH_TYPE} EQUAL 64)
        target_compile_definitions(${tgt} PUBLIC -DWIN64)
    endif()
endfunction()

function(_setup_msvc_options tgt)
    target_compile_options(${tgt} PUBLIC -W3 -nologo -MP -Zc:strictStrings)
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

