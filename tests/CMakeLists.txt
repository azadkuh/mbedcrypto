project(tests)

# modify this file to add/remove features and modules from mbedtls
add_definitions( -DMBEDTLS_CONFIG_FILE=\"mbedcrypto_mbedtls_config.h\" )

file(GLOB tests_src
    ./tdd/**.hpp
    ./tdd/**.cpp
    )
add_executable(tests ${tests_src})
target_link_libraries(tests mbedcrypto)
