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

#ifdef QKD_USE_SIMULATED
#include "etsi014/backends/simulated.h"
static const struct qkd_014_backend *active_backend = &simulated_backend;
#elif defined(QKD_USE_CERBERIS_XGR)
#include "etsi014/cerberis_xgr.h"
static const struct qkd_014_backend *active_backend = &cerberis_xgr_backend;
#else
static const struct qkd_014_backend *active_backend = NULL;
#endif

uint32_t GET_STATUS(const char *kme_hostname, 
                    const char *pub_key, 
                    const char *priv_key, 
                    const char *root_ca,
                    const char *slave_sae_id,
                    qkd_status_t *status) {
    if (!kme_hostname || !slave_sae_id || !status) {
        QKD_DBG_ERR("Invalid parameters in GET_STATUS");
        return QKD_STATUS_BAD_REQUEST;
    }

    if (!active_backend || !active_backend->get_status) {
        QKD_DBG_ERR("No REST backend available");
        return QKD_STATUS_SERVER_ERROR;
    }

    return active_backend->get_status(kme_hostname, pub_key, priv_key, root_ca, slave_sae_id, status);
}

uint32_t GET_KEY(const char *kme_hostname, 
                 const char *pub_key, const char *priv_key, const char *root_ca,
                 const char *slave_sae_id,
                 qkd_key_request_t *request, qkd_key_container_t *container) {
    // print the active backend name
    QKD_DBG_INFO("GET_KEY(): Active backend name: %s\n", active_backend->name);
    if (!kme_hostname || !slave_sae_id || !container) {
        QKD_DBG_ERR("Invalid parameters in GET_KEY");
        return QKD_STATUS_BAD_REQUEST;
    }

    if (!active_backend || !active_backend->get_key) {
        QKD_DBG_ERR("No REST backend available");
        return QKD_STATUS_SERVER_ERROR;
    }

    return active_backend->get_key(kme_hostname, pub_key, priv_key, root_ca,
                                   slave_sae_id, request, container);
}

uint32_t GET_KEY_WITH_IDS(const char *kme_hostname,                           
                          const char *pub_key, 
                          const char *priv_key, 
                          const char *root_ca,
                          const char *master_sae_id,
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
                                            pub_key, priv_key, root_ca,
                                            key_ids, container);
}