# ETSI GS QKD 004 API implementation

A C library implementing the [ETSI GS QKD 004 V2.1.1 (2020-08) Quantum Key Distribution (QKD) API specification](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/004/02.01.01_60/gs_qkd004v020101p.pdf), providing a standardized interface for quantum key distribution systems.

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

- `QKD_BACKEND`: Select QKD backend (simulated/cerberis_xgr). Default: simulated
- `QKD_DEBUG_LEVEL`: Set debug verbosity from 0 (disabled) to 4 (maximum). Default: 0
- `BUILD_TESTS`: Enable building of test programs (ON/OFF). Default: OFF

For example, to build the project with the simulated QKD backend, tests and debug level 4, run:

```bash
mkdir build
cd build
cmake -DQKD_BACKEND=simulated -DQKD_DEBUG_LEVEL=4 -DBUILD_TESTS=ON ..
make
```

## Running the tests

After building the project with `-DBUILD_TESTS=ON`, you can run the tests with:

```bash
ctest
```

or

```bash
./api_test
```