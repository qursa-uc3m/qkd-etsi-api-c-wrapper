/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 */

/*
 * include/etsi004/api.h
 */

 #ifndef QKD_ETSI004_API_H_
 #define QKD_ETSI004_API_H_
 
 /* Required standard headers */
 #include <openssl/evp.h>
 #include <stdbool.h>
 #include <stdint.h>
 
 /* Size definitions */
 #define QKD_KSID_SIZE 16  /* Key stream ID size in bytes (128 bits) */
 #define QKD_METADATA_MAX_SIZE 1024 /* Default maximum metadata buffer size */
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
 /* Status codes as defined in ETSI spec */
 #define QKD_STATUS_SUCCESS 0 /* Successful */
 #define QKD_STATUS_PEER_NOT_CONNECTED 1 /* Successful connection, peer not connected */
 #define QKD_STATUS_INSUFFICIENT_KEY 2 /* GET_KEY failed: insufficient key */
 #define QKD_STATUS_PEER_NOT_CONNECTED_GET_KEY 3 /* GET_KEY failed: peer not connected */
 #define QKD_STATUS_NO_CONNECTION 4 /* No QKD connection available */
 #define QKD_STATUS_KSID_IN_USE 5 /* OPEN_CONNECT failed because the KSID is already in use */
 #define QKD_STATUS_TIMEOUT 6 /* TIMEOUT_ERROR */
 #define QKD_STATUS_QOS_NOT_MET 7 /* OPEN failed because requested QoS settings could not be met */
 #define QKD_STATUS_METADATA_SIZE_INSUFFICIENT 8 /* GET_KEY failed: metadata field size insufficient */
 
 /* QoS parameters structure - exactly as per ETSI GS QKD 004 */
 struct qkd_qos_s {
     uint32_t Key_chunk_size;        /* Length of key buffer in bytes */
     uint32_t Max_bps;               /* Maximum bit rate */
     uint32_t Min_bps;               /* Minimum bit rate */
     uint32_t Jitter;                /* Maximum deviation for key delivery */
     uint32_t Priority;              /* Priority level */
     uint32_t Timeout;               /* Timeout in milliseconds */
     uint32_t TTL;                   /* Time-to-live in seconds */
     char Metadata_mimetype[256];    /* Metadata format */
 };
 
 /* Metadata structure - as per ETSI GS QKD 004 */
 struct qkd_metadata_s {
     uint32_t Metadata_size;          /* Size of metadata buffer in characters */
     unsigned char *Metadata_buffer;  /* Buffer for returned metadata */
 };
 
 /* ETSI 004 Backend Interface */
 struct qkd_004_backend {
     const char *name; /* Backend identifier */
 
     uint32_t (*open_connect)(const char *source, const char *destination,
                              struct qkd_qos_s *qos,
                              unsigned char *key_stream_id, uint32_t *status);
 
     uint32_t (*get_key)(const unsigned char *key_stream_id, uint32_t *index,
                         unsigned char *key_buffer,
                         struct qkd_metadata_s *metadata, uint32_t *status);
 
     uint32_t (*close)(const unsigned char *key_stream_id, uint32_t *status);
 };
 
 /* Backend Management Functions */
 void register_qkd_004_backend(const struct qkd_004_backend *backend);
 const struct qkd_004_backend *get_active_004_backend(void);
 
 /* ETSI GS QKD 004 API functions */
 uint32_t OPEN_CONNECT(const char *source, const char *destination,
                       struct qkd_qos_s *qos, unsigned char *key_stream_id,
                       uint32_t *status);
 
 uint32_t GET_KEY(const unsigned char *key_stream_id, uint32_t *index,
                  unsigned char *key_buffer, struct qkd_metadata_s *metadata,
                  uint32_t *status);
 
 uint32_t CLOSE(const unsigned char *key_stream_id, uint32_t *status);
 
 #ifdef __cplusplus
 }
 #endif
 
 #endif /* QKD_ETSI004_API_H_ */