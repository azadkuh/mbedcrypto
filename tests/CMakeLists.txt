project(mbedcrypto_tests)

file(GLOB tests_src
    ${CMAKE_CURRENT_SOURCE_DIR}/tdd/**.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tdd/**.cpp
    )
add_executable(${PROJECT_NAME} ${tests_src})
add_test(${PROJECT_NAME} ${DIR_XBIN}/${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} PRIVATE
    ${MBEDCRYPTO_SOURCE_DIR}
    ${DIR_3RDPARTY}/Catch/single_include
    )
target_link_libraries(${PROJECT_NAME} mbedcrypto)

if(BUILD_QT5_BIND)
    target_link_libraries(${PROJECT_NAME} Qt5::Core)
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
    add_executable(c_raii ${CMAKE_CURRENT_SOURCE_DIR}/other/c_raii.cpp)
    target_link_libraries(c_raii mbedcrypto)

    if(BUILD_EC AND BUILD_PK_EXPORT)
        add_executable(ec_keygen ${CMAKE_CURRENT_SOURCE_DIR}/tests/other/ec_keygen.cpp)
        target_link_libraries(ec_keygen mbedcrypto)
    endif()

endif()
