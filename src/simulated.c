/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 */

/*
 * src/simulated.c
 */

#include <openssl/evp.h>
#include <string.h>

#include "api.h"
#include "debug.h"
#include "simulated.h"

#ifdef QKD_USE_SIMULATED

#define MAX_STREAMS 16
#define MAX_KEYS_PER_STREAM 1024

/* Test key and ID structures */
static const unsigned char test_key_uuid[QKD_KSID_SIZE] = {
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x47, 0x58,
    0x59, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0};

static const unsigned char test_key[QKD_KEY_SIZE] = {
    0x8f, 0x40, 0xc5, 0xad, 0xb6, 0x8f, 0x25, 0x62, 0x4a, 0xe5, 0xb2,
    0x14, 0xea, 0x76, 0x7a, 0x6e, 0xc9, 0x4d, 0x82, 0x9d, 0x3d, 0x7b,
    0x5e, 0x1a, 0xd1, 0xba, 0x6f, 0x3e, 0x21, 0x38, 0x28, 0x5f};

struct key_block {
    unsigned char key[QKD_KEY_SIZE];
    uint32_t index;
    uint64_t timestamp;
    bool used;
};

struct stream_state {
    unsigned char key_id[QKD_KSID_SIZE];
    struct qkd_qos_s qos;
    bool in_use;
    bool is_initiator;
    uint32_t last_index;
    uint64_t creation_time;
    bool pending_close;
    struct key_block keys[MAX_KEYS_PER_STREAM];
    uint32_t num_keys;
};

static struct stream_state streams[MAX_STREAMS];

/* Find stream by ID, returns -1 if not found */
static int find_stream(const unsigned char *key_id) {
    if (!key_id)
        return -1;

    for (int i = 0; i < MAX_STREAMS; i++) {
        if (streams[i].in_use &&
            memcmp(streams[i].key_id, key_id, QKD_KSID_SIZE) == 0) {
            return i;
        }
    }
    return -1;
}

/* Allocate new stream slot */
static int allocate_stream(void) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (!streams[i].in_use) {
            return i;
        }
    }
    return -1;
}

/* Get current time in milliseconds */
static uint64_t get_current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Generate deterministic simulated key based on index */
static void generate_key(unsigned char *key, uint32_t index) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, &index, sizeof(index));
    EVP_DigestFinal_ex(ctx, key, NULL);
    EVP_MD_CTX_free(ctx);
}

static bool can_generate_key(struct stream_state *stream,
                             uint32_t requested_index) {
    uint64_t current_time = get_current_time_ms();
    uint64_t elapsed_ms = current_time - stream->creation_time;

    // Calculate maximum possible keys based on Max_bps
    uint64_t max_possible_keys = (elapsed_ms * stream->qos.Max_bps) /
                                 (8000 * stream->qos.Key_chunk_size);

    // Check if requested index is within bounds
    return requested_index < max_possible_keys;
}

/* Implementation of core functions */
static uint32_t sim_open_connect(const char *source, const char *destination,
                                 struct qkd_qos_s *qos,
                                 unsigned char *key_stream_id,
                                 uint32_t *status) {
    if (!source || !destination || !qos || !key_stream_id || !status) {
        *status = QKD_STATUS_NO_CONNECTION;
        return QKD_STATUS_NO_CONNECTION;
    }

    bool is_initiator = (key_stream_id[0] == '\0');
    if (is_initiator) {
        memcpy(key_stream_id, test_key_uuid, QKD_KSID_SIZE);
    }

    *status = QKD_STATUS_SUCCESS;
    return QKD_STATUS_SUCCESS;
}

static uint32_t sim_get_key(const unsigned char *key_stream_id, uint32_t *index,
                            unsigned char *key_buffer,
                            struct qkd_metadata_s *metadata, uint32_t *status) {
    if (!key_stream_id || !index || !key_buffer || !status) {
        *status = QKD_STATUS_NO_CONNECTION;
        return QKD_STATUS_NO_CONNECTION;
    }

    generate_key(key_buffer, *index);
    *status = QKD_STATUS_SUCCESS;
    return QKD_STATUS_SUCCESS;
}

static uint32_t sim_close(const unsigned char *key_stream_id,
                          uint32_t *status) {
    *status = QKD_STATUS_SUCCESS;
    return QKD_STATUS_SUCCESS;
}

/* Registering simulation */
const struct qkd_backend simulated_backend = {.name = "simulated",
                                              .open_connect = sim_open_connect,
                                              .get_key = sim_get_key,
                                              .close = sim_close};

#endif /* QKD_USE_SIMULATED */