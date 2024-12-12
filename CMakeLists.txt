cmake_minimum_required(VERSION 3.10)

project(qkd-etsi-api 
        VERSION 1.0
        LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)

option(QKD_DEBUG_LEVEL "Set debug verbosity (1-4)" 0)
option(BUILD_TESTS "Build test programs" OFF)

option(ENABLE_ETSI004 "Enable ETSI 004 API support" ON)
option(ENABLE_ETSI014 "Enable ETSI 014 API support" ON)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")

set(COMMON_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# QKD backend selection
set(QKD_BACKEND "simulated" CACHE STRING "Select QKD backend (simulated, cerberis_xgr)")
set_property(CACHE QKD_BACKEND PROPERTY STRINGS simulated cerberis_xgr)

# Define sources and includes conditionally based on enabled APIs
if(ENABLE_ETSI004)
    list(APPEND COMMON_INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/etsi004
    )

    set(ETSI004_SOURCES
        src/etsi004/api.c
    )

    if(QKD_BACKEND STREQUAL "simulated")
        list(APPEND ETSI004_SOURCES 
            src/etsi004/backends/simulated.c
        )
        add_compile_definitions(QKD_USE_SIMULATED)
    elseif(QKD_BACKEND STREQUAL "cerberis_xgr")
        #list(APPEND ETSI004_SOURCES 
        #    src/etsi004/backends/cerberis_xgr.c
        #)
        #add_compile_definitions(QKD_USE_CERBERIS_XGR)
    endif()

    add_library(qkd-etsi004-api ${ETSI004_SOURCES})
    target_include_directories(qkd-etsi004-api
        PUBLIC
            ${COMMON_INCLUDES}
    )
    target_link_libraries(qkd-etsi004-api
        PRIVATE
            OpenSSL::Crypto
    )
    target_compile_definitions(qkd-etsi004-api
        PRIVATE
            $<$<BOOL:${QKD_DEBUG_LEVEL}>:QKD_DEBUG_LEVEL=${QKD_DEBUG_LEVEL}>
            ENABLE_ETSI004
    )
endif()

if(ENABLE_ETSI014)
    list(APPEND COMMON_INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/etsi014
    )

    set(ETSI014_SOURCES
        src/etsi014/api.c
    )

    if(QKD_BACKEND STREQUAL "simulated")
        list(APPEND ETSI014_SOURCES 
            src/etsi014/backends/simulated.c
        )
        add_compile_definitions(QKD_USE_SIMULATED)
    elseif(QKD_BACKEND STREQUAL "cerberis_xgr")
        list(APPEND ETSI014_SOURCES 
            src/etsi014/backends/cerberis_xgr.c
        )
        add_compile_definitions(QKD_USE_CERBERIS_XGR)
        
        # Adding required libraries to interpret HTTPs req/res
        set(ADDITIONAL_LIBRARIES curl jansson)

    endif()

    add_library(qkd-etsi014-api ${ETSI014_SOURCES})
    target_include_directories(qkd-etsi014-api
        PUBLIC
            ${COMMON_INCLUDES}
    )
    target_link_libraries(qkd-etsi014-api
        PRIVATE
            OpenSSL::Crypto
            OpenSSL::SSL
            ${ADDITIONAL_LIBRARIES}
    )
    target_compile_definitions(qkd-etsi014-api
        PRIVATE
            $<$<BOOL:${QKD_DEBUG_LEVEL}>:QKD_DEBUG_LEVEL=${QKD_DEBUG_LEVEL}>
            ENABLE_ETSI014
    )
endif()

# Tests with conditional compilation
if(BUILD_TESTS)
    enable_testing()

    if(ENABLE_ETSI004)
        add_executable(etsi004_test
            tests/etsi004/api_test.c
        )
        target_link_libraries(etsi004_test
            PRIVATE
                qkd-etsi004-api
        )
        add_test(NAME etsi004_test COMMAND etsi004_test)
    endif()

    if(ENABLE_ETSI014)
        add_executable(etsi014_test
            tests/etsi014/api_test.c
        )
        target_link_libraries(etsi014_test
            PRIVATE
                qkd-etsi014-api
        )
        add_test(NAME etsi014_test COMMAND etsi014_test)
    endif()
endif()

# Installation
if(ENABLE_ETSI004)
    install(TARGETS qkd-etsi004-api
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
    )
    install(DIRECTORY include/etsi004/
        DESTINATION include/qkd-etsi-api/etsi004
        FILES_MATCHING PATTERN "*.h"
    )
endif()

if(ENABLE_ETSI014)
    install(TARGETS qkd-etsi014-api
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
    )
    install(DIRECTORY include/etsi014/
        DESTINATION include/qkd-etsi-api/etsi014
        FILES_MATCHING PATTERN "*.h"
    )
endif()

install(FILES
    include/debug.h
    include/qkd_etsi_api.h
    DESTINATION include/qkd-etsi-api
)