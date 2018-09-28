if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Choose the type of build: Release Debug"
        FORCE)
endif()
if(WIN32)
    option(BUILD_AS_X32XP "build for a 32bit (XP/2003) targets" OFF)
endif()

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
## misc stuff
if(UNIX)
    ## doxygen
    ADD_CUSTOM_TARGET(docs
        COMMAND doxygen ./mbedcrypto.doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
    ADD_CUSTOM_TARGET(clean_docs
        COMMAND rm -rf ./docs
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
endif()

