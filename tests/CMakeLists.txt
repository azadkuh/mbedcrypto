project(mbedcrypto_tests)

add_executable(${PROJECT_NAME}
    ./main.cpp
    ./helper.cpp
    ./test_binutils.cpp
    ./test_errors.cpp
    ./test_types.cpp
    ./test_text_codec.cpp
    ./test_hash.cpp
    ./test_cipher.cpp
    ./test_rnd_generator.cpp
    ./test_mpi.cpp
    ./test_pk.cpp
    )

target_link_libraries(${PROJECT_NAME} PRIVATE mbedcrypto)
target_include_directories(${PROJECT_NAME} PRIVATE ${DIR_DEPS}/)
mbedcrypto_setup_platforms(${PROJECT_NAME})

add_test(NAME mbedcrypto COMMAND ${PROJECT_NAME})
