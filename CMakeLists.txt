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

option(QKD_DEBUG_LEVEL "Set debug verbosity (1-4)" 0)
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
    else()
        message(WARNING "     Error: ETSI004 only supports simulated or python_client backends")
    endif()
elseif(ENABLE_ETSI014)
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
    elseif(QKD_BACKEND STREQUAL "python_client")
        message(STATUS "     Backend: Python Client")
    endif()
else()
    message(WARNING "No ETSI API enabled!")
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

# Define sources based on enabled APIs
set(API_SOURCES "")

if(ENABLE_ETSI004)
    list(APPEND COMMON_INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/etsi004
        ${CMAKE_CURRENT_SOURCE_DIR}/include/etsi004/backends
    )
    list(APPEND API_SOURCES
        src/etsi004/api.c
    )
    if(QKD_BACKEND STREQUAL "simulated")
        list(APPEND API_SOURCES 
            src/etsi004/backends/simulated.c
        )
    elseif(QKD_BACKEND STREQUAL "cerberis_xgr" OR QKD_BACKEND STREQUAL "qukaydee")
        list(APPEND API_SOURCES 
            src/etsi004/backends/qkd_etsi014_backend.c
        )
    elseif(QKD_BACKEND STREQUAL "python_client")
        list(APPEND API_SOURCES 
            src/etsi004/backends/python_client.c
        )
    endif()
endif()

if(ENABLE_ETSI014)
    list(APPEND COMMON_INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/etsi014
        ${CMAKE_CURRENT_SOURCE_DIR}/include/etsi014/backends
    )
    list(APPEND API_SOURCES
        src/etsi014/api.c
    )
    if(QKD_BACKEND STREQUAL "simulated")
        list(APPEND API_SOURCES 
            src/etsi014/backends/simulated.c
        )
    elseif(QKD_BACKEND STREQUAL "cerberis_xgr" OR QKD_BACKEND STREQUAL "qukaydee")
        list(APPEND API_SOURCES 
            src/etsi014/backends/qkd_etsi014_backend.c
        )
        list(APPEND COMMON_INCLUDES
            ${CURL_INCLUDE_DIRS}
            ${JANSSON_INCLUDE_DIRS}
        )
    elseif(QKD_BACKEND STREQUAL "python_client")
        # If you need Python client for ETSI014 as well, add the source here
    endif()
endif()

# Create unified library
add_library(qkd-etsi-api-c-wrapper SHARED ${API_SOURCES})

target_include_directories(qkd-etsi-api-c-wrapper
    PUBLIC 
        ${COMMON_INCLUDES}
)

# Create the link libraries list
set(LINK_LIBRARIES
    OpenSSL::Crypto
    OpenSSL::SSL
)

# Add Python libraries if needed
if(QKD_BACKEND STREQUAL "python_client")
    # Get the library directory and add python library directly
    execute_process(
        COMMAND ${PYTHON3_CONFIG} --embed --ldflags
        OUTPUT_VARIABLE Python3_EMBED_LDFLAGS
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
    # Add the embed flags which include the proper library linking
    string(REPLACE " " ";" Python3_EMBED_FLAGS_LIST "${Python3_EMBED_LDFLAGS}")
    list(APPEND LINK_LIBRARIES ${Python3_EMBED_FLAGS_LIST})
    message(STATUS "Added Python embed libraries: ${Python3_EMBED_FLAGS_LIST}")
endif()

# Add CURL and Jansson if needed
if(ENABLE_ETSI014 AND ENABLE_ETSI014_BACKEND)
    list(APPEND LINK_LIBRARIES ${CURL_LIBRARIES} ${JANSSON_LIBRARIES})
endif()

target_link_libraries(qkd-etsi-api-c-wrapper PUBLIC ${LINK_LIBRARIES})

if(QKD_BACKEND STREQUAL "python_client")
    message(STATUS "Final LINK_LIBRARIES for qkd-etsi-api-c-wrapper: ${LINK_LIBRARIES}")
endif()

if(WIN32)
  # On Windows, adjust if needed.
else()
  find_library(UUID_LIB uuid)
  if(UUID_LIB)
    target_link_libraries(qkd-etsi-api-c-wrapper PUBLIC ${UUID_LIB})
  else()
    message(FATAL_ERROR "UUID library not found!")
  endif()
endif()

target_compile_definitions(qkd-etsi-api-c-wrapper
    PRIVATE
        $<$<BOOL:${QKD_DEBUG_LEVEL}>:QKD_DEBUG_LEVEL=${QKD_DEBUG_LEVEL}>
        $<$<BOOL:${ENABLE_ETSI004}>:ENABLE_ETSI004>
        $<$<BOOL:${ENABLE_ETSI014}>:ENABLE_ETSI014>
        $<$<STREQUAL:${QKD_BACKEND},simulated>:QKD_USE_SIMULATED>
        $<$<STREQUAL:${QKD_BACKEND},python_client>:QKD_USE_PYTHON_CLIENT>
)

if(BUILD_TESTS)
    add_compile_definitions(USE_TEST)
    
    # ETSI004 tests - only build if ETSI004 is enabled
    if(ENABLE_ETSI004)
        add_executable(etsi004_test
            tests/etsi004/api_test.c
        )
        target_link_libraries(etsi004_test
            PRIVATE
            qkd-etsi-api-c-wrapper
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
            qkd-etsi-api-c-wrapper
        )
        add_test(NAME etsi014_test COMMAND etsi014_test)
        
        if(NOT QKD_BACKEND STREQUAL "simulated")
            # Full test only for ETSI014 with non-simulated backends
            add_executable(etsi014_full_test
                tests/etsi014/api_full_test.c
            )
            target_link_libraries(etsi014_full_test
                PRIVATE
                qkd-etsi-api-c-wrapper
            )
            add_test(NAME etsi014_full_test COMMAND etsi014_full_test)
        endif()
    endif()
endif()

# Installation
install(TARGETS qkd-etsi-api-c-wrapper
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