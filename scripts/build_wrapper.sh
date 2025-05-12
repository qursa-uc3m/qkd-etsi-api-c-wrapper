#!/bin/bash
# Copyright (C) 2024 QURSA Project
# SPDX-License-Identifier: MIT
#
# Authors:
# - Javier Blanco-Romero (@fj-blanco) - UC3M

# Default values
ETSI_MODE=""
QKD_BACKEND=""
DEBUG_LEVEL=0
BUILD_TESTS="OFF"
INSTALL=false

# Display help message
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Build the QKD ETSI API C Wrapper with specified parameters"
    echo
    echo "Options:"
    echo "  -m, --mode MODE       Set ETSI mode (required): 004 or 014"
    echo "  -b, --backend BACKEND Set QKD backend (required)"
    echo "                        Valid backends for ETSI004: simulated, python_client"
    echo "                        Valid backends for ETSI014: simulated, cerberis_xgr, qukaydee"
    echo "  -d, --debug LEVEL     Set debug level (0-4) (default: 0)"
    echo "  -t, --tests           Enable building test programs"
    echo "  -i, --install         Run 'sudo make install' after building"
    echo "  -h, --help            Display this help message and exit"
    echo
    echo "Example:"
    echo "  $0 --mode 004 --backend python_client --debug 4 --tests"
    echo "  $0 --mode 014 --backend simulated --install"
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--mode)
            ETSI_MODE="$2"
            shift 2
            ;;
        -b|--backend)
            QKD_BACKEND="$2"
            shift 2
            ;;
        -d|--debug)
            DEBUG_LEVEL="$2"
            shift 2
            ;;
        -t|--tests)
            BUILD_TESTS="ON"
            shift
            ;;
        -i|--install)
            INSTALL=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Error: Unknown option $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$ETSI_MODE" ]]; then
    echo "Error: ETSI mode (-m, --mode) is required"
    echo "Use --help for usage information"
    exit 1
fi

if [[ -z "$QKD_BACKEND" ]]; then
    echo "Error: QKD backend (-b, --backend) is required"
    echo "Use --help for usage information"
    exit 1
fi

# Validate ETSI mode
if [[ "$ETSI_MODE" != "004" && "$ETSI_MODE" != "014" ]]; then
    echo "Error: Invalid ETSI mode. Must be either '004' or '014'"
    exit 1
fi

# Validate backend based on ETSI mode
if [[ "$ETSI_MODE" == "004" ]]; then
    if [[ "$QKD_BACKEND" != "simulated" && "$QKD_BACKEND" != "python_client" ]]; then
        echo "Error: Invalid backend for ETSI004. Valid options: simulated, python_client"
        exit 1
    fi
elif [[ "$ETSI_MODE" == "014" ]]; then
    if [[ "$QKD_BACKEND" != "simulated" && "$QKD_BACKEND" != "cerberis_xgr" && "$QKD_BACKEND" != "qukaydee" ]]; then
        echo "Error: Invalid backend for ETSI014. Valid options: simulated, cerberis_xgr, qukaydee"
        exit 1
    fi
fi

# Validate debug level
if ! [[ "$DEBUG_LEVEL" =~ ^[0-4]$ ]]; then
    echo "Error: Debug level must be between 0 and 4"
    exit 1
fi

# Set CMake options based on ETSI mode
if [[ "$ETSI_MODE" == "004" ]]; then
    ENABLE_ETSI004="ON"
    ENABLE_ETSI014="OFF"
else
    ENABLE_ETSI004="OFF"
    ENABLE_ETSI014="ON"
fi

# Clean and recreate build directory
rm -rf build
mkdir build
cd build || {
    echo "Error: Could not change to build directory"
    exit 1
}

# Get Python paths if using python_client backend
if [[ "$QKD_BACKEND" == "python_client" ]]; then
    python_exe=$(which python3)
    
    # Detect Python version and paths dynamically
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    python_include_dir=$(python3 -c "import sysconfig; print(sysconfig.get_path('include'))")
    
    # Find Python library
    if [[ -f "/usr/lib/x86_64-linux-gnu/libpython${python_version}.so" ]]; then
        python_lib="/usr/lib/x86_64-linux-gnu/libpython${python_version}.so"
    else
        # Try to find library using ldconfig
        python_lib=$(ldconfig -p | grep -m 1 "libpython${python_version}" | awk '{print $4}')
        
        if [[ -z "$python_lib" ]]; then
            echo "Warning: Could not find Python library. CMake will attempt to find it automatically."
        fi
    fi
    
    echo "Using Python $python_version"
    echo "Python executable: $python_exe"
    echo "Python include directory: $python_include_dir"
    echo "Python library: $python_lib"
    
    # Build with specific Python paths
    cmake_command="cmake -DENABLE_ETSI004=$ENABLE_ETSI004 -DENABLE_ETSI014=$ENABLE_ETSI014 -DQKD_BACKEND=$QKD_BACKEND \
      -DPYTHON_EXECUTABLE=$python_exe"
    
    if [[ -n "$python_include_dir" ]]; then
        cmake_command+=" -DPYTHON_INCLUDE_DIR=$python_include_dir"
    fi
    
    if [[ -n "$python_lib" ]]; then
        cmake_command+=" -DPython3_LIBRARY=$python_lib"
    fi
    
    cmake_command+=" -DQKD_DEBUG_LEVEL=$DEBUG_LEVEL -DBUILD_TESTS=$BUILD_TESTS .."
else
    # Regular build command for non-Python backends
    cmake_command="cmake -DENABLE_ETSI004=$ENABLE_ETSI004 -DENABLE_ETSI014=$ENABLE_ETSI014 -DQKD_BACKEND=$QKD_BACKEND \
      -DQKD_DEBUG_LEVEL=$DEBUG_LEVEL -DBUILD_TESTS=$BUILD_TESTS .."
fi

# Display and execute the cmake command
echo "Executing: $cmake_command"
eval "$cmake_command"

# Build
echo "Building with make..."
make

# Install if requested
if [[ "$INSTALL" == true ]]; then
    echo "Installing with sudo make install..."
    sudo make install
fi

echo "Build completed successfully."

# Show summary
echo
echo "Build Summary:"
echo "-------------"
echo "ETSI Mode: $ETSI_MODE (ETSI004=$ENABLE_ETSI004, ETSI014=$ENABLE_ETSI014)"
echo "QKD Backend: $QKD_BACKEND"
echo "Debug Level: $DEBUG_LEVEL"
echo "Build Tests: $BUILD_TESTS"
echo "Installed: $INSTALL"