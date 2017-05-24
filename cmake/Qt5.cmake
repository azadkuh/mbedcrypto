# Qt5 stuff
set(CMAKE_AUTOMOC ON)
if(BUILD_AS_STATIC)
    set(QT_STATIC ON)
    add_definitions(-DQT_STATIC)
endif()

find_package(Qt5Core)

