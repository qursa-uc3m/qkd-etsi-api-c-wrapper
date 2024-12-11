/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 */

/*
 * include/etsi014/api.h
 */

#ifndef ETSI014_API_H
#define ETSI014_API_H

#include <stdint.h>

/* Response codes as per section 5 */
#define QKD_STATUS_OK 200
#define QKD_STATUS_BAD_REQUEST 400
#define QKD_STATUS_UNAUTHORIZED 401
#define QKD_STATUS_SERVER_ERROR 503
#define QKD_STATUS_INVALID_PARAM 400

/* Status data format (section 6.1) */
typedef struct qkd_status {
    char *source_KME_ID;
    char *target_KME_ID;
    char *master_SAE_ID;
    char *slave_SAE_ID;
    int32_t key_size;
    int32_t stored_key_count;
    int32_t max_key_count;
    int32_t max_key_per_request;
    int32_t max_key_size;
    int32_t min_key_size;
    int32_t max_SAE_ID_count;
    void *status_extension; /* Optional extension object */
} qkd_status_t;

/* Key request format (section 6.2) */
typedef struct qkd_key_request {
    int32_t number;                  /* Optional, default 1 */
    int32_t size;                    /* Optional, default from Status */
    char **additional_slave_SAE_IDs; /* Optional array */
    int32_t additional_SAE_count;    /* Number of additional SAEs */
    void *extension_mandatory;       /* Optional array of extension objects */
    void *extension_optional;        /* Optional array of extension objects */
} qkd_key_request_t;

/* Key container format (section 6.3) */
typedef struct qkd_key {
    char *key_ID;           /* UUID format string */
    void *key_ID_extension; /* Optional extension object */
    char *key;              /* Base64 encoded key data */
    void *key_extension;    /* Optional extension object */
} qkd_key_t;

typedef struct qkd_key_container {
    qkd_key_t *keys;               /* Array of keys */
    int32_t key_count;             /* Number of keys in array */
    void *key_container_extension; /* Optional extension object */
} qkd_key_container_t;

/* Key IDs format (section 6.4) */
typedef struct qkd_key_id {
    char *key_ID;           /* UUID format string */
    void *key_ID_extension; /* Optional extension object */
} qkd_key_id_t;

typedef struct qkd_key_ids {
    qkd_key_id_t *key_IDs;   /* Array of key IDs */
    int32_t key_ID_count;    /* Number of key IDs */
    void *key_IDs_extension; /* Optional extension object */
} qkd_key_ids_t;

/* ETSI 014 Backend Interface */
struct qkd_014_backend {
    const char *name;

    uint32_t (*get_status)(const char *kme_hostname, const char *slave_sae_id,
                           qkd_status_t *status);

    uint32_t (*get_key)(const char *kme_hostname, const char *slave_sae_id,
                        qkd_key_request_t *request,
                        qkd_key_container_t *container);

    uint32_t (*get_key_with_ids)(const char *kme_hostname,
                                 const char *master_sae_id,
                                 qkd_key_ids_t *key_ids,
                                 qkd_key_container_t *container);
};

/* Backend Management Functions */
void register_qkd_014_backend(const struct qkd_014_backend *backend);
const struct qkd_014_backend *get_active_014_backend(void);

/* ETSI GS QKD 014 API functions (section 5) */
uint32_t GET_STATUS(const char *kme_hostname, const char *slave_sae_id,
                    qkd_status_t *status);

uint32_t GET_KEY(const char *kme_hostname, const char *slave_sae_id,
                 qkd_key_request_t *request, qkd_key_container_t *container);

uint32_t GET_KEY_WITH_IDS(const char *kme_hostname, const char *master_sae_id,
                          qkd_key_ids_t *key_ids,
                          qkd_key_container_t *container);

#endif /* ETSI014_API_H */