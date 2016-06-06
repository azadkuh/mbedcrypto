project(tests)

# modify this file to add/remove features and modules from mbedtls
add_definitions( -DMBEDTLS_CONFIG_FILE=\"mbedcrypto_mbedtls_config.h\" )

file(GLOB tests_src
    ./tdd/**.hpp
    ./tdd/**.cpp
    )
add_executable(tests ${tests_src})
target_link_libraries(tests mbedcrypto)

OPTION(BUILD_TESTS_IDEA "build experimental and dirty test applications, you ain't gonna need it" OFF)

if(BUILD_TESTS_IDEA)
    add_executable(c_raii ./other/c_raii.cpp)
    target_link_libraries(c_raii mbedcrypto)

    if(BUILD_EC AND BUILD_PK_EXPORT)
        add_executable(ec_keygen ./other/ec_keygen.cpp)
        target_link_libraries(ec_keygen mbedcrypto)
    endif()

endif()
