/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 * - Pedro Otero-García (@pedrotega) - UVigo
 *
 */

/*
 * src/etsi014/api.c
 */

#include "etsi014/api.h"
#include "debug.h"
#include <stdlib.h>
#include <string.h>

#ifdef QKD_USE_SIMULATED
#include "etsi014/backends/simulated.h"
static const struct qkd_014_backend *active_backend = &simulated_backend;
#elif defined(QKD_USE_ETSI014_BACKEND)
#include "etsi014/backends/qkd_etsi014_backend.h"
static const struct qkd_014_backend *active_backend = &qkd_etsi014_backend;
#else
static const struct qkd_014_backend *active_backend = NULL;
#endif

void register_qkd_014_backend(const struct qkd_014_backend *backend) {
    active_backend = backend;
}

const struct qkd_014_backend *get_active_014_backend(void) {
    return active_backend;
}

uint32_t GET_STATUS(const char *kme_hostname, const char *slave_sae_id,
                    qkd_status_t *status) {
    if (!kme_hostname || !slave_sae_id || !status) {
        QKD_DBG_ERR("Invalid parameters in GET_STATUS");
        return QKD_STATUS_BAD_REQUEST;
    }

    if (!active_backend || !active_backend->get_status) {
        QKD_DBG_ERR("No REST backend available");
        return QKD_STATUS_SERVER_ERROR;
    }

    return active_backend->get_status(kme_hostname, slave_sae_id, status);
}

uint32_t GET_KEY(const char *kme_hostname, const char *slave_sae_id,
                 qkd_key_request_t *request, qkd_key_container_t *container) {
    if (!kme_hostname || !slave_sae_id || !container) {
        QKD_DBG_ERR("Invalid parameters in GET_KEY");
        return QKD_STATUS_BAD_REQUEST;
    }

    if (!active_backend || !active_backend->get_key) {
        QKD_DBG_ERR("No REST backend available");
        return QKD_STATUS_SERVER_ERROR;
    }

    QKD_DBG_INFO("GET_KEY(): Active backend name: %s", active_backend->name);

    return active_backend->get_key(kme_hostname, slave_sae_id, request,
                                   container);
}

uint32_t GET_KEY_WITH_IDS(const char *kme_hostname, const char *master_sae_id,
                          qkd_key_ids_t *key_ids,
                          qkd_key_container_t *container) {
    if (!kme_hostname || !master_sae_id || !key_ids || !container) {
        QKD_DBG_ERR("Invalid parameters in GET_KEY_WITH_IDS");
        return QKD_STATUS_BAD_REQUEST;
    }

    if (!active_backend || !active_backend->get_key_with_ids) {
        QKD_DBG_ERR("No REST backend available");
        return QKD_STATUS_SERVER_ERROR;
    }

    return active_backend->get_key_with_ids(kme_hostname, master_sae_id,
                                            key_ids, container);
}

void qkd_status_free(qkd_status_t *status) {
    if (!status)
        return;

    free(status->source_KME_ID);
    free(status->target_KME_ID);
    free(status->master_SAE_ID);
    free(status->slave_SAE_ID);
    memset(status, 0, sizeof(*status));
}

void qkd_key_container_free(qkd_key_container_t *container) {
    if (!container)
        return;

    for (int32_t i = 0; container->keys && i < container->key_count; i++) {
        free(container->keys[i].key_ID);
        free(container->keys[i].key);
    }
    free(container->keys);
    memset(container, 0, sizeof(*container));
}
