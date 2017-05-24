project(tests)

# modify this file to add/remove features and modules from mbedtls
add_definitions( -DMBEDTLS_CONFIG_FILE=\"mbedcrypto_mbedtls_config.h\" )

file(GLOB tests_src
    ./tdd/**.hpp
    ./tdd/**.cpp
    )
add_executable(tests ${tests_src})
target_link_libraries(tests mbedcrypto)
if(BUILD_QT5_BIND)
    qt5_use_modules(tests Core)
    if(IS_LINUX)
        target_link_libraries(tests dl)
    endif()
    if(BUILD_AS_STATIC)
        # statically build Qt (5.6.2) forgets to link against qtpcre
        # put it into your cmake build directory manually
        target_link_libraries(tests qtpcre ws2_32)
    endif()
endif()

OPTION(BUILD_TESTS_IDEA "build experimental and dirty test applications, you ain't gonna need it" OFF)

if(BUILD_TESTS_IDEA)
    add_executable(c_raii ./other/c_raii.cpp)
    target_link_libraries(c_raii mbedcrypto)

    if(BUILD_EC AND BUILD_PK_EXPORT)
        add_executable(ec_keygen ./other/ec_keygen.cpp)
        target_link_libraries(ec_keygen mbedcrypto)
    endif()

endif()
