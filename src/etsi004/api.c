/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 *
 */

/*
 * src/etsi004/api.c (modified with Python client backend support)
 */

 #include "etsi004/api.h"
 #include "debug.h"
 
 #ifdef QKD_USE_SIMULATED
 #include "etsi004/backends/simulated.h"
 static const struct qkd_004_backend *active_backend = &simulated_backend;
 #elif defined(QKD_USE_ETSI014_BACKEND)
 #include "etsi004/backends/qkd_etsi014_backend.h"
 static const struct qkd_004_backend *active_backend = &qkd_etsi014_backend;
 #elif defined(QKD_USE_PYTHON_CLIENT)
 #include "etsi004/backends/python_client.h"
 static const struct qkd_004_backend *active_backend = &python_client_backend;
 #else
 static const struct qkd_004_backend *active_backend = NULL;
 #endif
 
 /* API function implementations remain the same */
 uint32_t OPEN_CONNECT(const char *source, const char *destination,
                       struct qkd_qos_s *qos, unsigned char *key_stream_id,
                       uint32_t *status) {
     if (!active_backend) {
         QKD_DBG_ERR("No QKD backend registered");
         if (status)
             *status = QKD_STATUS_NO_CONNECTION;
         return QKD_STATUS_NO_CONNECTION;
     }
     return active_backend->open_connect(source, destination, qos, key_stream_id,
                                         status);
 }
 
 uint32_t GET_KEY(const unsigned char *key_stream_id, uint32_t *index,
                  unsigned char *key_buffer, struct qkd_metadata_s *metadata,
                  uint32_t *status) {
     if (!active_backend) {
         QKD_DBG_ERR("No QKD backend registered");
         if (status)
             *status = QKD_STATUS_NO_CONNECTION;
         return QKD_STATUS_NO_CONNECTION;
     }
     return active_backend->get_key(key_stream_id, index, key_buffer, metadata,
                                    status);
 }
 
 uint32_t CLOSE(const unsigned char *key_stream_id, uint32_t *status) {
     if (!active_backend) {
         QKD_DBG_ERR("No QKD backend registered");
         if (status)
             *status = QKD_STATUS_NO_CONNECTION;
         return QKD_STATUS_NO_CONNECTION;
     }
     return active_backend->close(key_stream_id, status);
 }