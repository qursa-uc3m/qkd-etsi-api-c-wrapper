/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 *
 */

/*
 * include/etsi014/backends/cerberis_xgr.h
 */

#ifndef QKD_ETSI_CERBERIS_XGR_H_
#define QKD_ETSI_CERBERIS_XGR_H_

#ifdef QKD_USE_CERBERIS_XGR
typedef struct {
    const char *cert_path;      // Path to public certificate
    const char *key_path;       // Path to private key
    const char *ca_cert_path;   // Path to CA certificate
} cerberis_cert_config_t;

extern const struct qkd_014_backend cerberis_xgr_backend;
#endif

#endif /* QKD_ETSI_CERBERIS_XGR_H_ */