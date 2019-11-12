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
    )

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}
    ${DIR_DEPS}/
    ${DIR_DEPS}/mbedtls/include
    )
target_link_libraries(${PROJECT_NAME} PRIVATE mbedcrypto)

add_test(NAME mbedcrypto COMMAND ${PROJECT_NAME})
