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

## Installation

The build system supports the following configuration parameters:

### API Selection

- `ENABLE_ETSI004`: Enable ETSI 004 API support (ON/OFF). Default: ON
- `ENABLE_ETSI014`: Enable ETSI 014 API support (ON/OFF). Default: ON

### Backend Selection

- `QKD_BACKEND`: Select QKD backend (simulated/cerberis_xgr). Default: simulated
  - simulated: Available for ETSI 004
  - cerberis_xgr: Available for ETSI 014

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

After building the project with `-DBUILD_TESTS=ON`, you can run the tests with:

```bash
ctest
```

or

```bash
# For ETSI 004
./etsi004_test

# For ETSI 014
./etsi014_test
```