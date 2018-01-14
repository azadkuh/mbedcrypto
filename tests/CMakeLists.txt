project(mbedcrypto_tests)

# modify this file to add/remove features and modules from mbedtls
add_definitions( -DMBEDTLS_CONFIG_FILE=\"mbedcrypto_mbedtls_config.h\" )

file(GLOB tests_src
    ./tdd/**.hpp
    ./tdd/**.cpp
    )
add_executable(${PROJECT_NAME} ${tests_src})
target_link_libraries(${PROJECT_NAME} mbedcrypto)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR})
if(BUILD_QT5_BIND)
    qt5_use_modules(${PROJECT_NAME} Core)
    if(IS_LINUX)
        target_link_libraries(${PROJECT_NAME} dl)
    endif()
    if(BUILD_AS_STATIC)
        if(WIN32)
            target_link_libraries(${PROJECT_NAME} ws2_32)
        endif()
    endif()
endif()

#-----------------------------------------------------------------------------
# other test application
OPTION(BUILD_TESTS_IDEA "build experimental and dirty test applications, you ain't gonna need it" OFF)
if(BUILD_TESTS_IDEA)
    add_executable(c_raii ./other/c_raii.cpp)
    target_link_libraries(c_raii mbedcrypto)

    if(BUILD_EC AND BUILD_PK_EXPORT)
        add_executable(ec_keygen ./other/ec_keygen.cpp)
        target_link_libraries(ec_keygen mbedcrypto)
    endif()

endif()
