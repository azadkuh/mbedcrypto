project(tests)

add_executable(tests
    ./tdd/main.cpp
    )
target_link_libraries(tests mbedcrypto)
