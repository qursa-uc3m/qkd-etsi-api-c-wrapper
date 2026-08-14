/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 */

#ifndef QKD_ETSI014_BACKEND_INTERNAL_H
#define QKD_ETSI014_BACKEND_INTERNAL_H

#include "etsi014/api.h"

int parse_response_to_qkd_keys(const char *response,
                               qkd_key_container_t *container);

#endif /* QKD_ETSI014_BACKEND_INTERNAL_H */
