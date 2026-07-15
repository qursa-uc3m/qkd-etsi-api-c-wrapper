/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 */

/*
 * src/etsi004/backends/simulated.c
 */

#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "debug.h"
#include "etsi004/api.h"
#include "etsi004/backends/simulated.h"
#include "qkd_etsi_api.h"

#ifdef QKD_USE_SIMULATED

#define MAX_STREAMS 16
#define MAX_KEYS_PER_STREAM 1024

struct stream_state {
    unsigned char key_id[QKD_KSID_SIZE];
    struct qkd_qos_s qos;
    bool in_use;
    bool peer_connected;
    uint64_t creation_time;
};

static const unsigned char test_key_uuid[QKD_KSID_SIZE] = {
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x47, 0x58,
    0x59, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0};

static struct stream_state streams[MAX_STREAMS];
static unsigned char closed_streams[MAX_STREAMS][QKD_KSID_SIZE];
static bool closed_stream_in_use[MAX_STREAMS];
static size_t next_closed_stream;

static uint32_t set_status(uint32_t *status, uint32_t value) {
    if (status)
        *status = value;
    return value;
}

static int find_stream(const unsigned char *key_id) {
    if (!key_id)
        return -1;

    for (int i = 0; i < MAX_STREAMS; i++) {
        if (streams[i].in_use &&
            memcmp(streams[i].key_id, key_id, QKD_KSID_SIZE) == 0)
            return i;
    }
    return -1;
}

static int allocate_stream(void) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (!streams[i].in_use)
            return i;
    }
    return -1;
}

static bool generate_stream_id(unsigned char *key_stream_id) {
    if (find_stream(test_key_uuid) < 0) {
        memcpy(key_stream_id, test_key_uuid, QKD_KSID_SIZE);
        return true;
    }

    for (int attempts = 0; attempts < MAX_STREAMS; attempts++) {
        if (RAND_bytes(key_stream_id, QKD_KSID_SIZE) != 1)
            return false;
        key_stream_id[6] = (key_stream_id[6] & 0x0fU) | 0x40U;
        key_stream_id[8] = (key_stream_id[8] & 0x3fU) | 0x80U;
        if (find_stream(key_stream_id) < 0)
            return true;
    }
    return false;
}

static bool was_closed(const unsigned char *key_stream_id) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (closed_stream_in_use[i] &&
            memcmp(closed_streams[i], key_stream_id, QKD_KSID_SIZE) == 0)
            return true;
    }
    return false;
}

static void remember_closed(const unsigned char *key_stream_id) {
    memcpy(closed_streams[next_closed_stream], key_stream_id, QKD_KSID_SIZE);
    closed_stream_in_use[next_closed_stream] = true;
    next_closed_stream = (next_closed_stream + 1U) % MAX_STREAMS;
}

static uint64_t get_current_time_ms(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static bool qos_is_supported(const struct qkd_qos_s *qos) {
    return qos->Key_chunk_size == QKD_KEY_SIZE && qos->Max_bps > 0 &&
           qos->Min_bps <= qos->Max_bps;
}

static bool generate_key(const struct stream_state *stream, unsigned char *key,
                         uint32_t index) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int key_size = 0;
    bool success = false;

    if (!ctx)
        return false;

    bool digest_ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
                     EVP_DigestUpdate(ctx, &index, sizeof(index)) == 1;
    if (digest_ok && memcmp(stream->key_id, test_key_uuid, QKD_KSID_SIZE) != 0)
        digest_ok = EVP_DigestUpdate(ctx, stream->key_id, QKD_KSID_SIZE) == 1;
    if (digest_ok && EVP_DigestFinal_ex(ctx, key, &key_size) == 1 &&
        key_size == QKD_KEY_SIZE)
        success = true;

    EVP_MD_CTX_free(ctx);
    return success;
}

static bool can_generate_key(const struct stream_state *stream,
                             uint32_t requested_index) {
    uint64_t elapsed_ms = get_current_time_ms() - stream->creation_time;
    uint64_t generated_keys = 1U + (elapsed_ms * stream->qos.Max_bps) /
                                       (8000U * stream->qos.Key_chunk_size);

    return requested_index < MAX_KEYS_PER_STREAM &&
           requested_index < generated_keys;
}

static uint32_t generate_metadata(const struct stream_state *stream,
                                  struct qkd_metadata_s *metadata) {
    char value[64];
    uint64_t age_ms = get_current_time_ms() - stream->creation_time;
    int written = snprintf(value, sizeof(value),
                           "{\"age\": %" PRIu64 ", \"hops\": 0}", age_ms);

    if (written < 0 || (size_t)written >= sizeof(value))
        return QKD_STATUS_NO_CONNECTION;

    uint32_t required_size = (uint32_t)written + 1U;
    if (!metadata->Metadata_buffer || metadata->Metadata_size < required_size) {
        metadata->Metadata_size = required_size;
        return QKD_STATUS_METADATA_SIZE_INSUFFICIENT;
    }

    memcpy(metadata->Metadata_buffer, value, required_size);
    metadata->Metadata_size = (uint32_t)written;
    return QKD_STATUS_SUCCESS;
}

static uint32_t sim_open_connect(const char *source, const char *destination,
                                 struct qkd_qos_s *qos,
                                 unsigned char *key_stream_id,
                                 uint32_t *status) {
    if (!source || !destination || !qos || !key_stream_id || !status)
        return set_status(status, QKD_STATUS_NO_CONNECTION);

    if (!qos_is_supported(qos))
        return set_status(status, QKD_STATUS_QOS_NOT_MET);

    bool is_initiator = key_stream_id[0] == '\0';
    if (is_initiator) {
        int stream_idx = allocate_stream();
        if (stream_idx < 0)
            return set_status(status, QKD_STATUS_NO_CONNECTION);

        if (!generate_stream_id(key_stream_id))
            return set_status(status, QKD_STATUS_NO_CONNECTION);
        struct stream_state *stream = &streams[stream_idx];
        memset(stream, 0, sizeof(*stream));
        memcpy(stream->key_id, key_stream_id, QKD_KSID_SIZE);
        stream->qos = *qos;
        stream->in_use = true;
        stream->creation_time = get_current_time_ms();
        return set_status(status, QKD_STATUS_PEER_NOT_CONNECTED);
    }

    int stream_idx = find_stream(key_stream_id);
    if (stream_idx < 0)
        return set_status(status, QKD_STATUS_NO_CONNECTION);
    if (streams[stream_idx].peer_connected)
        return set_status(status, QKD_STATUS_KSID_IN_USE);

    streams[stream_idx].peer_connected = true;
    return set_status(status, QKD_STATUS_SUCCESS);
}

static uint32_t sim_get_key(const unsigned char *key_stream_id, uint32_t *index,
                            unsigned char *key_buffer,
                            struct qkd_metadata_s *metadata, uint32_t *status) {
    if (!key_stream_id || !index || !key_buffer || !status)
        return set_status(status, QKD_STATUS_NO_CONNECTION);

    int stream_idx = find_stream(key_stream_id);
    if (stream_idx < 0 || !streams[stream_idx].peer_connected)
        return set_status(status, QKD_STATUS_PEER_NOT_CONNECTED_GET_KEY);

    struct stream_state *stream = &streams[stream_idx];
    if (!can_generate_key(stream, *index))
        return set_status(status, QKD_STATUS_INSUFFICIENT_KEY);
    if (!generate_key(stream, key_buffer, *index))
        return set_status(status, QKD_STATUS_NO_CONNECTION);

    if (metadata) {
        uint32_t metadata_status = generate_metadata(stream, metadata);
        if (metadata_status != QKD_STATUS_SUCCESS)
            return set_status(status, metadata_status);
    }

    return set_status(status, QKD_STATUS_SUCCESS);
}

static uint32_t sim_close(const unsigned char *key_stream_id,
                          uint32_t *status) {
    if (!key_stream_id || !status)
        return set_status(status, QKD_STATUS_NO_CONNECTION);

    int stream_idx = find_stream(key_stream_id);
    if (stream_idx < 0) {
        if (was_closed(key_stream_id))
            return set_status(status, QKD_STATUS_SUCCESS);
        return set_status(status, QKD_STATUS_PEER_NOT_CONNECTED_GET_KEY);
    }

    struct stream_state *stream = &streams[stream_idx];
    remember_closed(stream->key_id);
    memset(stream, 0, sizeof(*stream));

    return set_status(status, QKD_STATUS_SUCCESS);
}

const struct qkd_004_backend simulated_backend = {.name = "simulated",
                                                  .open_connect =
                                                      sim_open_connect,
                                                  .get_key = sim_get_key,
                                                  .close = sim_close};

#endif /* QKD_USE_SIMULATED */
