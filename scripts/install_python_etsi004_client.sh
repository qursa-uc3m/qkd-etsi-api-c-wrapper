#!/bin/bash
# Copyright (C) 2024 QURSA Project
# SPDX-License-Identifier: MIT
#
# Authors:
# - Javier Blanco-Romero (@fj-blanco) - UC3M

# Install Python ETSI-004 QKD client module
# This script checks for a local version of the client first,
# and falls back to downloading from GitHub if not available

set -e

# Script configuration
GITHUB_REPO="https://raw.githubusercontent.com/QUBIP/etsi-qkd-004/ksid_sync/client/client.py"
MODULE_NAME="qkd_client.py"
DEST_DIR="${HOME}/.local/lib/qkd"

echo "Installing ETSI-004 Python Client..."

# Create destination directory
mkdir -p "${DEST_DIR}"

# Check if the local file exists
if [ -f "${LOCAL_FILE_PATH}" ]; then
    echo "Using local file: ${LOCAL_FILE_PATH}"
    cp "${LOCAL_FILE_PATH}" "${DEST_DIR}/${MODULE_NAME}"
else
    # Download the client if local file doesn't exist
    echo "Local file not found at ${LOCAL_FILE_PATH}. Downloading from ${GITHUB_REPO}..."
    if command -v curl &> /dev/null; then
        curl -s -o "${DEST_DIR}/${MODULE_NAME}" "${GITHUB_REPO}"
    elif command -v wget &> /dev/null; then
        wget -q -O "${DEST_DIR}/${MODULE_NAME}" "${GITHUB_REPO}"
    else
        echo "Error: Neither curl nor wget is installed."
        exit 1
    fi
fi

# Create .pth file to add the directory to Python's module search path
USER_SITE=$(python3 -m site --user-site)
mkdir -p "${USER_SITE}"
echo "${DEST_DIR}" > "${USER_SITE}/qkd_etsi004.pth"

echo "Python client installed to: ${DEST_DIR}/${MODULE_NAME}"
echo "Created path file at: ${USER_SITE}/qkd_etsi004.pth"

# Test the installation
echo "Testing installation..."
if python3 -c "import qkd_client; print('Success: qkd_client module can be imported')" &> /dev/null; then
    echo "Installation successful! Module can be imported."
else
    echo "Warning: Module installation test failed."
    echo "Try manually running: python3 -c \"import sys; print(sys.path)\""
    echo "to check your Python path includes ${DEST_DIR}"
fi

echo "Done."