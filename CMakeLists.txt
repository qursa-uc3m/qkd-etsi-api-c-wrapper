# Copyright (C) 2024 QURSA Project
# SPDX-License-Identifier: MIT
#
# Authors:
# - Javier Blanco-Romero (@fj-blanco) - UC3M
# - Pedro Otero-García (@pedrotega) - UVigo

cmake_minimum_required(VERSION 3.10)

project(qkd-etsi-api-c-wrapper
        VERSION 1.0
        LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(QKD_DEBUG_LEVEL "0" CACHE STRING "Set debug verbosity (0-4)")
set_property(CACHE QKD_DEBUG_LEVEL PROPERTY STRINGS 0 1 2 3 4)
if(NOT QKD_DEBUG_LEVEL MATCHES "^[0-4]$")
    message(FATAL_ERROR "QKD_DEBUG_LEVEL must be an integer from 0 to 4")
endif()
option(BUILD_TESTS "Build test programs" OFF)
option(ENABLE_ETSI004 "Enable ETSI 004 API support" ON)
option(ENABLE_ETSI014 "Enable ETSI 014 API support" ON)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")

set(COMMON_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# QKD backend selection
set(QKD_BACKEND "simulated" CACHE STRING "Select QKD backend (simulated, cerberis_xgr, qukaydee, python_client)")
set_property(CACHE QKD_BACKEND PROPERTY STRINGS simulated cerberis_xgr qukaydee python_client)

set(SUPPORTED_BACKENDS simulated cerberis_xgr qukaydee python_client)
if(NOT QKD_BACKEND IN_LIST SUPPORTED_BACKENDS)
    message(FATAL_ERROR "Unsupported QKD_BACKEND: ${QKD_BACKEND}")
endif()
if(NOT ENABLE_ETSI004 AND NOT ENABLE_ETSI014)
    message(FATAL_ERROR "At least one ETSI API must be enabled")
endif()
if(ENABLE_ETSI004 AND NOT (QKD_BACKEND STREQUAL "simulated" OR QKD_BACKEND STREQUAL "python_client"))
    message(FATAL_ERROR "ETSI 004 supports only the simulated and python_client backends")
endif()
if(ENABLE_ETSI014 AND QKD_BACKEND STREQUAL "python_client")
    message(FATAL_ERROR "The python_client backend does not implement ETSI 014")
endif()

find_package(OpenSSL REQUIRED)
if(ENABLE_ETSI014 AND (QKD_BACKEND STREQUAL "cerberis_xgr" OR QKD_BACKEND STREQUAL "qukaydee"))
    find_package(CURL REQUIRED)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(JANSSON REQUIRED jansson)
    set(ENABLE_ETSI014_BACKEND TRUE)
else()
    set(ENABLE_ETSI014_BACKEND FALSE)
endif()

# Check for Python when using python_client backend
if(QKD_BACKEND STREQUAL "python_client")
    # Try to find python3-config
    find_program(PYTHON3_CONFIG python3-config)
    if(PYTHON3_CONFIG)
        execute_process(
            COMMAND ${PYTHON3_CONFIG} --includes
            OUTPUT_VARIABLE Python3_CFLAGS
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        execute_process(
            COMMAND ${PYTHON3_CONFIG} --ldflags
            OUTPUT_VARIABLE Python3_LDFLAGS
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        
        # Extract include directory
        string(REGEX REPLACE "^-I([^ ]+).*" "\\1" Python3_INCLUDE_DIRS "${Python3_CFLAGS}")
        
        message(STATUS "Found Python via python3-config:")
        message(STATUS "  Include: ${Python3_INCLUDE_DIRS}")
        message(STATUS "  LDFLAGS: ${Python3_LDFLAGS}")
        
        set(Python3_FOUND TRUE)
        set(Python3_LIBRARIES "${Python3_LDFLAGS}")
        list(APPEND COMMON_INCLUDES ${Python3_INCLUDE_DIRS})
    else()
        message(FATAL_ERROR "python3-config not found")
    endif()
endif()

if(QKD_BACKEND STREQUAL "simulated")
    add_compile_definitions(QKD_USE_SIMULATED)
elseif(QKD_BACKEND STREQUAL "cerberis_xgr" OR QKD_BACKEND STREQUAL "qukaydee")
    if(QKD_BACKEND STREQUAL "cerberis_xgr")
        add_compile_definitions(QKD_USE_CERBERIS_XGR)
    else()
        add_compile_definitions(QKD_USE_QUKAYDEE)
    endif()
    add_compile_definitions(QKD_USE_ETSI014_BACKEND)
elseif(QKD_BACKEND STREQUAL "python_client")
    add_compile_definitions(QKD_USE_PYTHON_CLIENT)
endif()

# Display API and backend configuration
message(STATUS "QKD API Configuration:")
if(ENABLE_ETSI004)
    message(STATUS "  -> Using ETSI004 API")
    if(QKD_BACKEND STREQUAL "simulated")
        message(STATUS "     Backend: Simulated")
    elseif(QKD_BACKEND STREQUAL "python_client")
        message(STATUS "     Backend: Python Client")
    endif()
endif()
if(ENABLE_ETSI014)
    message(STATUS "  -> Using ETSI014 API")
    if(QKD_BACKEND STREQUAL "simulated")
        message(STATUS "     Backend: Simulated")
    elseif(QKD_BACKEND STREQUAL "cerberis_xgr")
        message(STATUS "     Backend: Cerberis XGR")
        if(NOT ENABLE_ETSI014_BACKEND)
            message(WARNING "     Warning: Backend support not available")
        endif()
    elseif(QKD_BACKEND STREQUAL "qukaydee")
        message(STATUS "     Backend: QuKayDee")
        if(NOT ENABLE_ETSI014_BACKEND)
            message(WARNING "     Warning: Backend support not available")
        endif()
    endif()
endif()

# Configure and generate qkd_config.h
if(QKD_BACKEND STREQUAL "simulated")
    set(QKD_USE_SIMULATED 1)
    set(QKD_USE_CERBERIS_XGR 0)
    set(QKD_USE_QUKAYDEE 0)
    set(QKD_USE_PYTHON_CLIENT 0)
elseif(QKD_BACKEND STREQUAL "cerberis_xgr")
    set(QKD_USE_SIMULATED 0)
    set(QKD_USE_CERBERIS_XGR 1)
    set(QKD_USE_QUKAYDEE 0)
    set(QKD_USE_PYTHON_CLIENT 0)
elseif(QKD_BACKEND STREQUAL "qukaydee")
    set(QKD_USE_SIMULATED 0)
    set(QKD_USE_CERBERIS_XGR 0)
    set(QKD_USE_QUKAYDEE 1)
    set(QKD_USE_PYTHON_CLIENT 0)
elseif(QKD_BACKEND STREQUAL "python_client")
    set(QKD_USE_SIMULATED 0)
    set(QKD_USE_CERBERIS_XGR 0)
    set(QKD_USE_QUKAYDEE 0)
    set(QKD_USE_PYTHON_CLIENT 1)
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/qkd_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/qkd_config.h
    @ONLY
)

# Add binary dir to includes for qkd_config.h
list(APPEND COMMON_INCLUDES ${CMAKE_CURRENT_BINARY_DIR})

# Define sources based on enabled APIs. The standards both use GET_KEY with
# incompatible C signatures, so a dual-API build must produce separate shared
# libraries. Single-API builds retain the historical library name.
set(BASE_INCLUDES
    ${COMMON_INCLUDES}
    ${CMAKE_CURRENT_BINARY_DIR}
)
set(ETSI004_INCLUDES
    ${BASE_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/include/etsi004
    ${CMAKE_CURRENT_SOURCE_DIR}/include/etsi004/backends
)
set(ETSI014_INCLUDES
    ${BASE_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/include/etsi014
    ${CMAKE_CURRENT_SOURCE_DIR}/include/etsi014/backends
)

set(ETSI004_SOURCES src/etsi004/api.c)
set(ETSI014_SOURCES src/etsi014/api.c)

if(ENABLE_ETSI004)
    if(QKD_BACKEND STREQUAL "simulated")
        list(APPEND ETSI004_SOURCES src/etsi004/backends/simulated.c)
    elseif(QKD_BACKEND STREQUAL "python_client")
        list(APPEND ETSI004_SOURCES src/etsi004/backends/python_client.c)
    endif()
endif()

if(ENABLE_ETSI014)
    if(QKD_BACKEND STREQUAL "simulated")
        list(APPEND ETSI014_SOURCES src/etsi014/backends/simulated.c)
    elseif(QKD_BACKEND STREQUAL "cerberis_xgr" OR QKD_BACKEND STREQUAL "qukaydee")
        list(APPEND ETSI014_SOURCES src/etsi014/backends/qkd_etsi014_backend.c)
        list(APPEND ETSI014_INCLUDES
            ${CURL_INCLUDE_DIRS}
            ${JANSSON_INCLUDE_DIRS}
        )
    endif()
endif()

set(COMMON_LINK_LIBRARIES
    OpenSSL::Crypto
    OpenSSL::SSL
)

if(QKD_BACKEND STREQUAL "python_client")
    execute_process(
        COMMAND ${PYTHON3_CONFIG} --embed --ldflags
        OUTPUT_VARIABLE Python3_EMBED_LDFLAGS
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
    string(REPLACE " " ";" Python3_EMBED_FLAGS_LIST "${Python3_EMBED_LDFLAGS}")
    message(STATUS "Added Python embed libraries: ${Python3_EMBED_FLAGS_LIST}")
endif()

if(NOT WIN32 AND ENABLE_ETSI014 AND QKD_BACKEND STREQUAL "simulated")
    find_library(UUID_LIB uuid)
    if(NOT UUID_LIB)
        message(FATAL_ERROR "UUID library not found")
    endif()
endif()

function(configure_api_target target api)
    target_compile_features(${target} PUBLIC c_std_99)
    target_compile_definitions(${target} PRIVATE
        $<$<BOOL:${QKD_DEBUG_LEVEL}>:QKD_DEBUG_LEVEL=${QKD_DEBUG_LEVEL}>
        ENABLE_ETSI${api}
    )
    target_link_libraries(${target} PUBLIC ${COMMON_LINK_LIBRARIES})

    if(api STREQUAL "004")
        target_include_directories(${target} PUBLIC ${ETSI004_INCLUDES})
        if(QKD_BACKEND STREQUAL "python_client")
            target_link_libraries(${target} PUBLIC ${Python3_EMBED_FLAGS_LIST})
        endif()
    else()
        target_include_directories(${target} PUBLIC ${ETSI014_INCLUDES})
        if(ENABLE_ETSI014_BACKEND)
            target_link_libraries(${target} PUBLIC ${CURL_LIBRARIES} ${JANSSON_LIBRARIES})
        elseif(QKD_BACKEND STREQUAL "simulated" AND NOT WIN32)
            target_link_libraries(${target} PUBLIC ${UUID_LIB})
        endif()
    endif()
endfunction()

set(INSTALL_TARGETS)
if(ENABLE_ETSI004 AND ENABLE_ETSI014)
    add_library(qkd-etsi004-api-c-wrapper SHARED ${ETSI004_SOURCES})
    configure_api_target(qkd-etsi004-api-c-wrapper "004")
    set(ETSI004_TARGET qkd-etsi004-api-c-wrapper)

    add_library(qkd-etsi014-api-c-wrapper SHARED ${ETSI014_SOURCES})
    configure_api_target(qkd-etsi014-api-c-wrapper "014")
    set(ETSI014_TARGET qkd-etsi014-api-c-wrapper)

    list(APPEND INSTALL_TARGETS ${ETSI004_TARGET} ${ETSI014_TARGET})
else()
    if(ENABLE_ETSI004)
        add_library(qkd-etsi-api-c-wrapper SHARED ${ETSI004_SOURCES})
        configure_api_target(qkd-etsi-api-c-wrapper "004")
        set(ETSI004_TARGET qkd-etsi-api-c-wrapper)
    else()
        add_library(qkd-etsi-api-c-wrapper SHARED ${ETSI014_SOURCES})
        configure_api_target(qkd-etsi-api-c-wrapper "014")
        set(ETSI014_TARGET qkd-etsi-api-c-wrapper)
    endif()
    list(APPEND INSTALL_TARGETS qkd-etsi-api-c-wrapper)
endif()

if(BUILD_TESTS)
    enable_testing()
    add_compile_definitions(USE_TEST)
    
    # ETSI004 tests - only build if ETSI004 is enabled
    if(ENABLE_ETSI004)
        add_executable(etsi004_test
            tests/etsi004/api_test.c
        )
        target_link_libraries(etsi004_test
            PRIVATE
            ${ETSI004_TARGET}
        )
        add_test(NAME etsi004_test COMMAND etsi004_test)
    endif()
    
    # ETSI014 tests - only build if ETSI014 is enabled
    if(ENABLE_ETSI014)
        add_executable(etsi014_test
            tests/etsi014/api_test.c
        )
        target_link_libraries(etsi014_test
            PRIVATE
            ${ETSI014_TARGET}
        )
        add_test(NAME etsi014_test COMMAND etsi014_test)
        
        if(NOT QKD_BACKEND STREQUAL "simulated")
            # Full test only for ETSI014 with non-simulated backends
            add_executable(etsi014_full_test
                tests/etsi014/api_full_test.c
            )
            target_link_libraries(etsi014_full_test
                PRIVATE
                ${ETSI014_TARGET}
            )
            add_test(NAME etsi014_full_test COMMAND etsi014_full_test)
        endif()
    endif()
endif()

# Installation
install(TARGETS ${INSTALL_TARGETS}
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include/qkd-etsi-api-c-wrapper
)

install(FILES
    include/debug.h
    include/qkd_etsi_api.h
    DESTINATION include/qkd-etsi-api-c-wrapper
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/qkd_config.h
    DESTINATION include/qkd-etsi-api-c-wrapper
)

if(ENABLE_ETSI004)
    install(DIRECTORY include/etsi004/
        DESTINATION include/qkd-etsi-api-c-wrapper/etsi004
        FILES_MATCHING PATTERN "*.h"
    )
endif()

if(ENABLE_ETSI014)
    install(DIRECTORY include/etsi014/
        DESTINATION include/qkd-etsi-api-c-wrapper/etsi014
        FILES_MATCHING PATTERN "*.h"
    )
endif()
