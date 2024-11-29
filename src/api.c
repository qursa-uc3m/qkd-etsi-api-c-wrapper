/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 * 
 */

/*
 * src/api.c
 */

#include "api.h"
#include "debug.h"

static const struct qkd_backend *active_backend = NULL;

void register_qkd_backend(const struct qkd_backend *backend) {
    active_backend = backend;
}

const struct qkd_backend* get_active_backend(void) {
    return active_backend;
}

uint32_t OPEN_CONNECT(const char* source, const char* destination,
                     struct qkd_qos_s* qos,
                     unsigned char* key_stream_id,
                     uint32_t* status) {
    if (!active_backend) {
        QKD_DBG_ERR("No QKD backend registered");
        if (status) *status = QKD_STATUS_NO_CONNECTION;
        return QKD_STATUS_NO_CONNECTION;
    }
    return active_backend->open_connect(source, destination, qos, key_stream_id, status);
}

uint32_t GET_KEY(const unsigned char* key_stream_id,
                 uint32_t* index,
                 unsigned char* key_buffer,
                 struct qkd_metadata_s* metadata,
                 uint32_t* status) {
    if (!active_backend) {
        QKD_DBG_ERR("No QKD backend registered");
        if (status) *status = QKD_STATUS_NO_CONNECTION;
        return QKD_STATUS_NO_CONNECTION;
    }
    return active_backend->get_key(key_stream_id, index, key_buffer, metadata, status);
}

uint32_t CLOSE(const unsigned char* key_stream_id,
               uint32_t* status) {
    if (!active_backend) {
        QKD_DBG_ERR("No QKD backend registered");
        if (status) *status = QKD_STATUS_NO_CONNECTION;
        return QKD_STATUS_NO_CONNECTION;
    }
    return active_backend->close(key_stream_id, status);
}