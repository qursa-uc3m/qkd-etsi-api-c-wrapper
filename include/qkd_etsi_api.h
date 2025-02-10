/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 * - Daniel Sobral Blanco (@dasobral) - UC3M
 */

/*
 * qkd_etsi_api.h
 */

#ifndef QKD_ETSI_API_H
#define QKD_ETSI_API_H

#include "qkd_config.h"

#if defined(QKD_DEBUG_LEVEL) && (QKD_DEBUG_LEVEL > 0)
#ifdef QKD_USE_QUKAYDEE
#pragma message "QKD_USE_QUKAYDEE is defined"
#else
#pragma message "QKD_USE_QUKAYDEE is not defined"
#endif
#endif /* QKD_DEBUG_LEVEL */

#ifdef QKD_USE_QUKAYDEE
#define QKD_KEY_SIZE 32     /* Size of key buffer in bytes */ /* TODO: Check if this is always as in QuKayDee simulator (expect size in bites)*/
#else
#define QKD_KEY_SIZE 32      /* Size of key buffer in bytes */
#endif /* QKD_USE_QUKAYDEE */

#define QKD_KSID_SIZE 16    /* UUID_v4 16 bytes (128 bits) */
#define QKD_MAX_URI_LEN 256 /* Maximum length for URIs */

#endif /* QKD_ETSI_API_H */
