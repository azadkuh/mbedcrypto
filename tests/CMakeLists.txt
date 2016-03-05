project(tests)

file(GLOB tests_src
    ./tdd/**.hpp
    ./tdd/**.cpp
    )
add_executable(tests ${tests_src})
target_link_libraries(tests mbedcrypto mbedtls)
