
#!/bin/bash
# QKD client environment variables based on Docker configuration

# Server connection settings
export SERVER_ADDRESS="localhost"
export SERVER_PORT=25576  # Using the qkd_server_bob port
export CLIENT_ADDRESS="localhost"

# Get the path to the etsi-qkd-004 repository
# This assumes the script is run from where etsi-qkd-004 is cloned
# If this is not the case, set QKD_REPO_PATH manually
QKD_REPO_PATH="${QKD_REPO_PATH:-$(pwd)/etsi-qkd-004}"

# Certificate paths - assuming etsi-qkd-004 repo structure
export CLIENT_CERT_PEM="${QKD_REPO_PATH}/certs/client_cert_localhost.pem"
export CLIENT_CERT_KEY="${QKD_REPO_PATH}/certs/client_key_localhost.pem"
export SERVER_CERT_PEM="${QKD_REPO_PATH}/certs/server_cert_localhost.pem"

# QKD specific parameters
export KEY_INDEX=0
export METADATA_SIZE=1024

# QoS parameters
export QOS_KEY_CHUNK_SIZE=32
export QOS_MAX_BPS=40000
export QOS_MIN_BPS=5000
export QOS_JITTER=10
export QOS_PRIORITY=0
export QOS_TIMEOUT=5000
export QOS_TTL=3600

# Check if certificate files exist
if [ ! -f "$CLIENT_CERT_PEM" ] || [ ! -f "$CLIENT_CERT_KEY" ] || [ ! -f "$SERVER_CERT_PEM" ]; then
    echo "WARNING: Some certificate files were not found at the expected paths:"
    echo "  CLIENT_CERT_PEM: $CLIENT_CERT_PEM"
    echo "  CLIENT_CERT_KEY: $CLIENT_CERT_KEY"
    echo "  SERVER_CERT_PEM: $SERVER_CERT_PEM"
    echo ""
    echo "If you've placed certificates elsewhere, please set these variables manually:"
    echo "  export CLIENT_CERT_PEM=/your/path/to/client_cert.pem"
    echo "  export CLIENT_CERT_KEY=/your/path/to/client_key.pem"
    echo "  export SERVER_CERT_PEM=/your/path/to/server_cert.pem"
else
    echo "Certificate paths set successfully."
fi

echo "QKD environment variables set for connecting to $SERVER_ADDRESS:$SERVER_PORT"