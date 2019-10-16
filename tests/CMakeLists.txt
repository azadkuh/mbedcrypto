project(mbedcrypto_tests)

add_executable(${PROJECT_NAME}
    ./main.cpp
    ./helper.cpp
    ./test_meta.cpp
    ./test_binutils.cpp
    ./test_errors.cpp
    ./test_types.cpp
    # ./tdd/test_cipher.cpp
    # ./tdd/test_ecp.cpp
    # ./tdd/test_exception.cpp
    # ./tdd/test_hash.cpp
    # ./tdd/test_qt5.cpp
    # ./tdd/test_random.cpp
    # ./tdd/test_rsa.cpp
    # ./tdd/test_tcodec.cpp
    )

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}
    ${DIR_DEPS}/
    ${DIR_DEPS}/mbedtls/include
    )
target_link_libraries(${PROJECT_NAME} PRIVATE mbedcrypto)

add_test(NAME mbedcrypto COMMAND ${PROJECT_NAME})
