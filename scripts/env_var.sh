#!/bin/bash

# Certificate configuration
export QKD_MASTER_CERT_PATH=/path/to/cert.crt
export QKD_MASTER_KEY_PATH=/path/to/key.key
export QKD_MASTER_CA_CERT_PATH=/path/to/ca.pem

export QKD_SLAVE_CERT_PATH=/path/to/cert.crt
export QKD_SLAVE_KEY_PATH=/path/to/key.key
export QKD_SLAVE_CA_CERT_PATH=/path/to/ca.pem

# Test configuration
export QKD_MASTER_KME_HOSTNAME="https://master-kme-hostname"
export QKD_SLAVE_KME_HOSTNAME="https://slave-kme-hostname"
export QKD_MASTER_SAE="master-sae-id"
export QKD_SLAVE_SAE="slave-sae-id"