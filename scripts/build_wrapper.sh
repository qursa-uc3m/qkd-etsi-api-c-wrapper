#!/bin/bash
# Copyright (C) 2024 QURSA Project
# SPDX-License-Identifier: MIT
#
# Authors:
# - Javier Blanco-Romero (@fj-blanco) - UC3M

cd ~/Documents/apps/QURSA/qkd-etsi-api-c-wrapper
rm -rf build
mkdir build
cd build

# Get exact Python paths
python3_version=3.10
python_exe=$(which python3)
python_include_dir=/usr/include/python3.10
python_lib=/usr/lib/x86_64-linux-gnu/libpython3.10.so

# Build with specific Python paths
cmake -DENABLE_ETSI004=ON -DENABLE_ETSI014=OFF -DQKD_BACKEND=python_client \
      -DPYTHON_EXECUTABLE=$python_exe \
      -DPYTHON_INCLUDE_DIR=$python_include_dir \
      -DPython3_LIBRARY=$python_lib \
      -DQKD_DEBUG_LEVEL=4 -DBUILD_TESTS=ON ..

make
sudo make install