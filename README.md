# QKD ETSI API C Wrapper

A C library implementing a wrapper of both ETSI QKD API specifications:

- [ETSI GS QKD 004 V2.1.1 (2020-08) - Application Interface](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/004/02.01.01_60/gs_qkd004v020101p.pdf)
- [ETSI GS QKD 014 V1.1.1 (2019-02) - Protocol and data format of REST-based key delivery API](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf)

This wrapper is meant for integrating different backends into a single C library compliant with the specifications.

## About the Project

This work is part of the QURSA (Quantum-based Resistant Architectures and Techniques) project, developed through collaboration between:

- Information and Computing Laboratory (I&CLab), Department of Telematic Engineering, Universidade de Vigo (UVigo)
- Pervasive Computing Laboratory, Department of Telematic Engineering, Universidad Carlos III de Madrid (UC3M)

## Project Context

This API implementation has been developed for integrating Quantum Key Distribution into various security protocols and frameworks. It is primarily used in:

1. **IPSec Integration**: QKD key management for [strongSwan IPSec](https://github.com/qursa-uc3m/strongswan)
2. **Post-Quantum Cryptography Hybridization**: Integration with our [QKD-KEM Provider](https://github.com/qursa-uc3m/qkd-kem-provider), a fork of the [Open Quantum Safe Provider](https://github.com/open-quantum-safe/oqs-provider)

## Dependencies

### Required for all builds

- OpenSSL development files (`libssl-dev` on Ubuntu/Debian)

### Additional requirements for QKD ETSI 014 backends

Ubuntu/Debian:

```bash
sudo apt-get install libcurl4-openssl-dev libjansson-dev
```

## Installation

The build system supports the following configuration parameters:

### API Selection

- `ENABLE_ETSI004`: Enable ETSI 004 API support (ON/OFF). Default: ON
- `ENABLE_ETSI014`: Enable ETSI 014 API support (ON/OFF). Default: ON

### Backend Selection

- `QKD_BACKEND`: Select QKD backend (simulated/cerberis_xgr/qukaydee). Default: simulated
  - simulated: Available for ETSI 004 and ETSI 014
  - cerberis_xgr: Available for ETSI 014
  - qukaydee: Available for ETSI 014

### Cerberis XGR Configuration

When using the QKD ETSI 014 backend, the following environment variables must be set:

- `QKD_CERT_PATH`: Path to the public certificate
- `QKD_KEY_PATH`: Path to the private key
- `QKD_CA_CERT_PATH`: Path to the CA certificate

Example:

```bash
export QKD_CERT_PATH=/path/to/cert.pem
export QKD_KEY_PATH=/path/to/key.pem
export QKD_CA_CERT_PATH=/path/to/ca.pem
```

### Other Options

- `QKD_DEBUG_LEVEL`: Set debug verbosity from 0 (disabled) to 4 (maximum). Default: 0
- `BUILD_TESTS`: Enable building of test programs (ON/OFF). Default: OFF

For example, to build both APIs with the simulated backend for ETSI 004, tests and debug level 4:

```bash
mkdir build
cd build
cmake -DENABLE_ETSI004=ON -DENABLE_ETSI014=ON -DQKD_BACKEND=simulated -DQKD_DEBUG_LEVEL=4 -DBUILD_TESTS=ON ..
make
```

Or to build only ETSI 014 with cerberis_xgr backend:

```bash
mkdir build
cd build
cmake -DENABLE_ETSI004=OFF -DENABLE_ETSI014=ON -DQKD_BACKEND=cerberis_xgr ..
make
```

## Running the tests

### Testing ETSI014 with cerberis_xgr

When testing the ETSI014 API with the `cerberis_xgr` backend, the following environment variables must be set:

```bash
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
```

The script `scripts/env_var.sh` can help to set the enviroment variables:

```bash
source ./scripts/env_var.sh
```

> 🛈 `source` command  ensures that the exported variables are available in your current session.

Then run the tests:

```bash
./etsi014_test
```

For ETSI 014 full test (only available with hardware backends)

```bash
./etsi014_full_test
```

### Use alternative emulator for ETSI_014

In case real nodes are not available for real tests, it can be used  emulators that implement the ETSI_014. For example, [QuKayDee](https://qukaydee.com/pages/about) is a QKD network simulator in the cloud. According to their page:

> _"Its main goal is to allow users to test integration of their classical systems with the QKD network without needing physical QKD hardware. For example, network equipment vendors or service providers can test wether their encryptor devices are interoperable with the key delivery interface provided by QKD devices."_

By following the tutorial on its web page it can be generated the necessary certificates to make the requests to the nodes in the cloud. To test them together with this project, the paths to the certificates simply have to be specified as environment variables as explained in the previous section.

### Testing ETSI 004 with QUBIP's ETSI 004 simulated backend

[QUBIP's etsi-qkd-004](https://github.com/QUBIP/etsi-qkd-004/tree/ksid_sync) contains a simulated key generator and a KMS that allows you to test the ETSI 004 API.

#### Python Client Integration

This Python client integration:

- Uses the original QUBIP Python client code for ETSI-004
- Our C wrapper imports this as a Python module through the Python C API
- Creates a `.pth` file in your user's site-packages directory to make the module importable without environment variable changes

#### Setting up the Environment

Install the Python client module:

```bash
./scripts/install_python_etsi004_client.sh
```

This script:

- Downloads the Python client from the QUBIP repository
- Installs it to `~/.local/lib/qkd/qkd_client.py`
- Creates a `.pth` file in your user's site-packages directory to make the module importable

Clone and set up the QUBIP server (required for tests):

```bash
git clone https://github.com/QUBIP/etsi-qkd-004.git
cd etsi-qkd-004
```

#### Generate certificates for the server

```bash
sudo chmod +x ./certs/generate_certs.sh
./certs/generate_certs.sh qkd_server_alice
./certs/generate_certs.sh qkd_server_bob
# Generate certificates for localhost (required for client-server communication)
./certs/generate_certs.sh localhost
```

#### Modify Docker configuration to use localhost certificates

Edit the docker-compose.yml file to use the localhost certificates instead of the server-specific ones:

```bash
nano docker-compose.yml
```

Update the certificate paths for both server containers. For example, for qkd_server_bob:

```yaml
qkd_server_bob:
  build: ./server
  container_name: qkd_server_bob
  environment:
    - SERVER_CERT_PEM=/certs/server_cert_localhost.pem  # Server public key
    - SERVER_CERT_KEY=/certs/server_key_localhost.pem  # Server private key
    - CLIENT_CERT_PEM=/certs/client_cert_localhost.pem  # Client public key
    # Keep the rest of the settings unchanged
```

Do the same for qkd_server_alice. Then start the servers:

#### Run the servers

```bash
docker compose up --build -d qkd_server_alice qkd_server_bob generate_key_alice generate_key_bob
```

#### Configure the client to connect to the server:

Source this environment variables

```bash
source ./scripts/etsi004_env.sh
```

Building the Project

```bash
mkdir build
cd build
cmake -DQKD_BACKEND=python_client -DENABLE_ETSI014=OFF -DENABLE_ETSI004=ON -DQKD_DEBUG_LEVEL=4 -DBUILD_TESTS=ON ..
make
```

#### Testing

Run the ETSI 004 test with the Python client backend:

```bash
cd build
./etsi004_test
```

The tests will connect to the running QUBIP server and perform QKD operations through the standardized ETSI 004 API.

Finally put the server down:

```bash
docker-compose down && sudo docker system prune -a --volumes
```