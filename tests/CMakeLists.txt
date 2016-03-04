project(tests)

add_executable(tests
    ./tdd/main.cpp
    ./tdd/test_types.cpp
    )
target_link_libraries(tests mbedcrypto mbedtls)
