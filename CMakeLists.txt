cmake_minimum_required(VERSION 3.10)

project(qkd-etsi-api 
        VERSION 1.0
        LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(OpenSSL REQUIRED)

option(QKD_DEBUG_LEVEL "Set debug verbosity (1-4)" 0)
option(BUILD_TESTS "Build test programs" OFF)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")

# QKD backend selection
set(QKD_BACKEND "simulated" CACHE STRING "Select QKD backend (simulated, cerberis_xgr)")
set_property(CACHE QKD_BACKEND PROPERTY STRINGS simulated cerberis_xgr)

# Common source files
set(COMMON_SOURCES
    src/api.c)

# backend-specific sources
if(QKD_BACKEND STREQUAL "simulated")
    list(APPEND COMMON_SOURCES src/simulated.c)
    add_compile_definitions(QKD_USE_SIMULATED)
elseif(QKD_BACKEND STREQUAL "cerberis_xgr")
    list(APPEND COMMON_SOURCES src/cerberis_xgr.c)
    add_compile_definitions(QKD_USE_CERBERIS_XGR)
endif()

# Create library with all sources
add_library(qkd-etsi-api ${COMMON_SOURCES})

target_include_directories(qkd-etsi-api
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(qkd-etsi-api
    PRIVATE
        OpenSSL::Crypto
)

target_compile_definitions(qkd-etsi-api
    PRIVATE
        $<$<BOOL:${QKD_DEBUG_LEVEL}>:QKD_DEBUG_LEVEL=${QKD_DEBUG_LEVEL}>
        $<$<BOOL:${USE_SIMULATED_QKD}>:QKD_SIMULATED>
)

# Tests configuration
if(BUILD_TESTS)
    enable_testing()
    
    # Basic API test
    add_executable(api_test
        tests/api_test.c
    )
    
    target_link_libraries(api_test
        PRIVATE
            qkd-etsi-api
    )
    
    add_test(NAME api_test COMMAND api_test)
endif()


install(TARGETS qkd-etsi-api
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES
    include/api.h
    include/debug.h
    include/simulated.h
    DESTINATION include/qkd-etsi-api
)