project(mbedcrypto_tests)

add_executable(${PROJECT_NAME}
    ./tdd/main.cpp
    ./tdd/generator.cpp
    ./tdd/test_cipher.cpp
    ./tdd/test_ecp.cpp
    ./tdd/test_exception.cpp
    ./tdd/test_hash.cpp
    ./tdd/test_qt5.cpp
    ./tdd/test_random.cpp
    ./tdd/test_rsa.cpp
    ./tdd/test_tcodec.cpp
    ./tdd/test_types.cpp
    )

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/3rdparty/Catch/single_include/catch2
    ${CMAKE_SOURCE_DIR}/3rdparty/mbedtls/include
    )
target_link_libraries(${PROJECT_NAME} PRIVATE mbedcrypto)
if(MBEDCRYPTO_STATIC_CRT)
    if(MSVC)
        target_compile_options(${PROJECT_NAME} PUBLIC "-MT")
    elseif (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
        set_target_properties(${PROJECT_NAME} PROPERTIES
            LINK_FLAGS "-static-libstdc++ -static-libgcc")
    endif()
endif()

add_test(${PROJECT_NAME} ${PROJECT_NAME})
