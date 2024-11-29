/*
* Copyright (C) 2024 QURSA Project
* SPDX-License-Identifier: MIT
*
* Authors:
* - Javier Blanco-Romero (@fj-blanco) - UC3M
*/

/*
* src/cerberis_xgr.c
*/

#include <string.h>
#include <openssl/evp.h>

#include "debug.h"
#include "api.h"

static bool connection_established = false;

static uint32_t cerberis_xgr_open_connect(const char* source, 
                                  const char* destination,
                                  struct qkd_qos_s* qos,
                                  unsigned char* key_stream_id,
                                  uint32_t* status) {
   if (!source || !destination || !qos || !key_stream_id || !status) {
       QKD_DBG_ERR("invalid parameters in open_connect");
       *status = QKD_STATUS_NO_CONNECTION;
       return QKD_STATUS_NO_CONNECTION;
   }

   // TODO: backend would connect to Cerberis XGR hardware here
   connection_established = false;
   QKD_DBG_ERR("Cerberis XGR backend not available");
   *status = QKD_STATUS_NO_CONNECTION;
   return QKD_STATUS_NO_CONNECTION;
}

static uint32_t cerberis_xgr_get_key(const unsigned char* key_stream_id,
                              uint32_t* index,
                              unsigned char* key_buffer,
                              struct qkd_metadata_s* metadata,
                              uint32_t* status) {
   if (!key_stream_id || !index || !key_buffer || !status) {
       QKD_DBG_ERR("invalid parameters in get_key");
       *status = QKD_STATUS_NO_CONNECTION;
       return QKD_STATUS_NO_CONNECTION;
   }

   if (!connection_established) {
       QKD_DBG_ERR("connection not established");
       *status = QKD_STATUS_NO_CONNECTION;
       return QKD_STATUS_NO_CONNECTION;
   }

   // TODO: Real backend would get key from Cerberis XGR hardware
   QKD_DBG_ERR("Cerberis XGR backend not available");
   *status = QKD_STATUS_NO_CONNECTION;
   return QKD_STATUS_NO_CONNECTION;
}

static uint32_t cerberis_xgr_close(const unsigned char* key_stream_id,
                            uint32_t* status) {
   if (!key_stream_id || !status) {
       QKD_DBG_ERR("invalid parameters in close");
       *status = QKD_STATUS_NO_CONNECTION;
       return QKD_STATUS_NO_CONNECTION;
   }

   connection_established = false;
   QKD_DBG_INFO("connection closed");
   *status = QKD_STATUS_SUCCESS;
   return QKD_STATUS_SUCCESS;
}

/* REgistering Cerberis XGR QKD */
static const struct qkd_backend cerberis_xgr_backend = {
   .name = "cerberis_xgr",
   .open_connect = cerberis_xgr_open_connect,
   .get_key = cerberis_xgr_get_key,
   .close = cerberis_xgr_close
};

void register_cerberis_xgr_qkd(void) {
   register_qkd_backend(&cerberis_xgr_backend);
}