/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 */

/*
 * include/api.h
 */

#ifndef QKD_ETSI_API_H_
#define QKD_ETSI_API_H_

/* Required standard headers */
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hardcoded QKD constants */
#define QKD_KEY_SIZE 32     /* Size of key buffer in bytes */
#define QKD_KSID_SIZE 16    /* UUID_v4 16 bytes (128 bits) */
#define QKD_MAX_URI_LEN 256 /* Maximum length for URIs */

/* Status codes as defined in ETSI spec */
#define QKD_STATUS_SUCCESS 0 /* Successful */
#define QKD_STATUS_PEER_DISCONNECTED                                           \
    1 /* Successful connection, peer not connected */
#define QKD_STATUS_INSUFFICIENT_KEY 2   /* GET_KEY failed: insufficient key */
#define QKD_STATUS_PEER_NOT_CONNECTED 3 /* GET_KEY failed: peer not connected  \
                                         */
#define QKD_STATUS_NO_CONNECTION 4      /* No QKD connection available */
#define QKD_STATUS_KSID_IN_USE 5 /* OPEN_CONNECT failed: QKD_KEY_SIZE in use   \
                                  */
#define QKD_STATUS_TIMEOUT 6     /* TIMEOUT_ERROR */
#define QKD_STATUS_QOS_NOT_MET 7 /* OPEN failed: QoS not met */
#define QKD_STATUS_METADATA_SIZE_ERROR                                         \
    8 /* GET_KEY failed: metadata size insufficient */

/* QoS parameters structure */
struct qkd_qos_s {
    uint32_t Key_chunk_size; /* Length of key buffer in bytes */
    uint32_t Max_bps;        /* Maximum bit rate */
    uint32_t Min_bps;        /* Minimum bit rate */
    uint32_t jitter;         /* Maximum deviation for key delivery */
    uint32_t priority;       /* Priority level */
    uint32_t timeout;        /* Timeout in milliseconds */
    uint32_t TTL;            /* Time-to-live in seconds */
};

/* Metadata structure */
struct qkd_metadata_s {
    char *Metadata_mimetype; /* Metadata format (e.g. "application/json") */
    uint32_t Metadata_size;  /* Size of metadata buffer */
    unsigned char *Metadata_buffer; /* Metadata buffer */
};

/* QKD Backend Interface */
struct qkd_backend {
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
void register_qkd_backend(const struct qkd_backend *backend);
const struct qkd_backend *get_active_backend(void);

/* ETSI API Functions */
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

#endif /* QKD_ETSI_API_H_ */