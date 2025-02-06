/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 *
 */

/*
 * include/etsi014/backends/qkd_etsi014_backend.h
 */

#ifndef QKD_ETSI_014_BACKEND_H_
#define QKD_ETSI_014_BACKEND_H_

#include "qkd_etsi_api.h"

#ifdef QKD_USE_ETSI014_BACKEND
typedef struct {
    const char *cert_path;      // Path to public certificate
    const char *key_path;       // Path to private key
    const char *ca_cert_path;   // Path to CA certificate
} etsi014_cert_config_t;

int init_cert_config(int role, etsi014_cert_config_t *config);

extern const struct qkd_014_backend qkd_etsi014_backend;
#endif /* QKD_USE_ETSI014_BACKEND */

#endif /* QKD_ETSI_014_BACKEND_H_ */