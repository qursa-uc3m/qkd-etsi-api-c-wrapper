#!/bin/bash

# Run this script from the repo's root directory

# Certificate configuration
export QKD_MASTER_CERT_PATH="$(pwd)/certs/sae-1.crt"
export QKD_MASTER_KEY_PATH="$(pwd)/certs/sae-1.key"
export QKD_MASTER_CA_CERT_PATH="$(pwd)/certs/account-2507-server-ca-qukaydee-com.crt"

export QKD_SLAVE_CERT_PATH="$(pwd)/certs/sae-2.crt"
export QKD_SLAVE_KEY_PATH="$(pwd)/certs/sae-2.key"
export QKD_SLAVE_CA_CERT_PATH="$(pwd)/certs/account-2507-server-ca-qukaydee-com.crt"

# Test configuration
export QKD_MASTER_KME_HOSTNAME="https://kme-1.acct-${ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
export QKD_SLAVE_KME_HOSTNAME="https://kme-2.acct-${ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
export QKD_MASTER_SAE="sae-1"
export QKD_SLAVE_SAE="sae-2"

# Verification
echo "====================== Environment variables set ======================"
echo "QKD_MASTER_KME_HOSTNAME: $QKD_MASTER_KME_HOSTNAME"
echo "QKD_SLAVE_KME_HOSTNAME: $QKD_SLAVE_KME_HOSTNAME"
echo ""

echo "QKD_MASTER_SAE: $QKD_MASTER_SAE"
echo "QKD_SLAVE_SAE: $QKD_SLAVE_SAE"
echo ""

echo "QKD_MASTER_CERT_PATH: $QKD_MASTER_CERT_PATH"
echo "QKD_MASTER_KEY_PATH: $QKD_MASTER_KEY_PATH"
echo "QKD_MASTER_CA_CERT_PATH: $QKD_MASTER_CA_CERT_PATH"
echo ""

echo "QKD_SLAVE_CERT_PATH: $QKD_SLAVE_CERT_PATH"
echo "QKD_SLAVE_KEY_PATH: $QKD_SLAVE_KEY_PATH"
echo "QKD_SLAVE_CA_CERT_PATH: $QKD_SLAVE_CA_CERT_PATH"
echo ""
