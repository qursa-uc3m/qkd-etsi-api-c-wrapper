/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 *
 */

/*
 * include/etsi004/backends/simulated.h
 */

#ifndef QKD_ETSI004_SIMULATED_H_
#define QKD_ETSI004_SIMULATED_H_

#include "qkd_etsi_api.h"

#ifdef QKD_USE_SIMULATED

extern const struct qkd_004_backend simulated_backend;

#endif /* QKD_ETSI004_SIMULATED_H_ */

#endif /* QKD_USE_SIMULATED */