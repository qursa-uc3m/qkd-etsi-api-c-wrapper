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

#if defined(QKD_USE_SIMULATED) && QKD_USE_SIMULATED

#define MAX_STREAMS 16
#define MAX_KEYS_PER_STREAM 1024

struct stream_state {
    unsigned char key_id[QKD_KSID_SIZE];
    unsigned char key_secret[QKD_KEY_SIZE];
    struct qkd_qos_s qos;
    bool in_use;
    bool peer_connected;
    bool uses_legacy_key;
    uint64_t creation_time;
};

static const unsigned char test_key_uuid[QKD_KSID_SIZE] = {
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x47, 0x58,
    0x59, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0};

static struct stream_state streams[MAX_STREAMS];
static unsigned char closed_streams[MAX_STREAMS][QKD_KSID_SIZE];
static bool closed_stream_in_use[MAX_STREAMS];
static size_t next_closed_stream;
static bool legacy_stream_id_issued;

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

static bool is_null_stream_id(const unsigned char *key_stream_id) {
    static const unsigned char null_id[QKD_KSID_SIZE];

    return memcmp(key_stream_id, null_id, sizeof(null_id)) == 0;
}

static bool was_closed(const unsigned char *key_stream_id);

static bool generate_stream_id(unsigned char *key_stream_id,
                               bool *uses_legacy_id) {
    if (!legacy_stream_id_issued && find_stream(test_key_uuid) < 0 &&
        !was_closed(test_key_uuid)) {
        memcpy(key_stream_id, test_key_uuid, QKD_KSID_SIZE);
        *uses_legacy_id = true;
        return true;
    }
    legacy_stream_id_issued = true;

    for (int attempts = 0; attempts < MAX_STREAMS; attempts++) {
        if (RAND_bytes(key_stream_id, QKD_KSID_SIZE) != 1)
            return false;
        key_stream_id[6] = (key_stream_id[6] & 0x0fU) | 0x40U;
        key_stream_id[8] = (key_stream_id[8] & 0x3fU) | 0x80U;
        if (find_stream(key_stream_id) < 0 && !was_closed(key_stream_id)) {
            *uses_legacy_id = false;
            return true;
        }
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

static bool normalize_qos(struct qkd_qos_s *qos) {
    static const char json_mimetype[] = "application/json";
    bool supported = true;

    if (qos->Key_chunk_size == 0)
        qos->Key_chunk_size = QKD_KEY_SIZE;
    else if (qos->Key_chunk_size != QKD_KEY_SIZE) {
        qos->Key_chunk_size = QKD_KEY_SIZE;
        supported = false;
    }

    if (qos->Max_bps == 0)
        qos->Max_bps = 1000000;
    if (qos->Min_bps > qos->Max_bps) {
        qos->Min_bps = qos->Max_bps;
        supported = false;
    }

    if (!memchr(qos->Metadata_mimetype, '\0', sizeof(qos->Metadata_mimetype)) ||
        (qos->Metadata_mimetype[0] != '\0' &&
         strcmp(qos->Metadata_mimetype, json_mimetype) != 0)) {
        memset(qos->Metadata_mimetype, 0, sizeof(qos->Metadata_mimetype));
        memcpy(qos->Metadata_mimetype, json_mimetype, sizeof(json_mimetype));
        supported = false;
    }

    return supported;
}

static bool generate_key(const struct stream_state *stream, unsigned char *key,
                         uint32_t index) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int key_size = 0;
    bool success = false;

    if (!ctx)
        return false;

    bool digest_ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    if (digest_ok && !stream->uses_legacy_key)
        digest_ok = EVP_DigestUpdate(ctx, stream->key_secret,
                                     sizeof(stream->key_secret)) == 1;
    if (digest_ok)
        digest_ok = EVP_DigestUpdate(ctx, &index, sizeof(index)) == 1;
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

static uint32_t prepare_metadata(const struct stream_state *stream,
                                 struct qkd_metadata_s *metadata, char *value,
                                 uint32_t *value_size) {
    if (!metadata || metadata->Metadata_size == 0 ||
        stream->qos.Metadata_mimetype[0] == '\0') {
        if (metadata && stream->qos.Metadata_mimetype[0] == '\0')
            metadata->Metadata_size = 0;
        *value_size = 0;
        return QKD_STATUS_SUCCESS;
    }

    uint64_t age_ms = get_current_time_ms() - stream->creation_time;
    int written =
        snprintf(value, 64, "{\"age\": %" PRIu64 ", \"hops\": 0}", age_ms);

    if (written < 0 || written >= 64)
        return QKD_STATUS_NO_CONNECTION;

    uint32_t required_size = (uint32_t)written + 1U;
    if (!metadata->Metadata_buffer || metadata->Metadata_size < required_size) {
        metadata->Metadata_size = required_size;
        return QKD_STATUS_METADATA_SIZE_INSUFFICIENT;
    }

    *value_size = required_size;
    return QKD_STATUS_SUCCESS;
}

static bool stream_has_expired(const struct stream_state *stream) {
    if (stream->qos.TTL == 0)
        return false;

    uint64_t lifetime_ms = (uint64_t)stream->qos.TTL * 1000U;
    return get_current_time_ms() - stream->creation_time >= lifetime_ms;
}

static uint32_t sim_open_connect(const char *source, const char *destination,
                                 struct qkd_qos_s *qos,
                                 unsigned char *key_stream_id,
                                 uint32_t *status) {
    if (!source || !destination || !qos || !key_stream_id || !status)
        return set_status(status, QKD_STATUS_NO_CONNECTION);

    bool needs_generated_id = is_null_stream_id(key_stream_id);
    int stream_idx = needs_generated_id ? -1 : find_stream(key_stream_id);
    if (stream_idx >= 0) {
        if (streams[stream_idx].peer_connected)
            return set_status(status, QKD_STATUS_KSID_IN_USE);

        *qos = streams[stream_idx].qos;
        streams[stream_idx].peer_connected = true;
        return set_status(status, QKD_STATUS_SUCCESS);
    }

    if (!normalize_qos(qos))
        return set_status(status, QKD_STATUS_QOS_NOT_MET);

    if (!needs_generated_id && was_closed(key_stream_id))
        return set_status(status, QKD_STATUS_KSID_IN_USE);

    {
        int new_stream_idx = allocate_stream();
        if (new_stream_idx < 0)
            return set_status(status, QKD_STATUS_NO_CONNECTION);

        bool uses_legacy_id = false;
        if (needs_generated_id &&
            !generate_stream_id(key_stream_id, &uses_legacy_id))
            return set_status(status, QKD_STATUS_NO_CONNECTION);
        if (!needs_generated_id && !legacy_stream_id_issued &&
            memcmp(key_stream_id, test_key_uuid, QKD_KSID_SIZE) == 0)
            uses_legacy_id = true;

        struct stream_state *stream = &streams[new_stream_idx];
        memset(stream, 0, sizeof(*stream));
        memcpy(stream->key_id, key_stream_id, QKD_KSID_SIZE);
        stream->uses_legacy_key = uses_legacy_id;
        if (!stream->uses_legacy_key &&
            RAND_bytes(stream->key_secret, sizeof(stream->key_secret)) != 1) {
            OPENSSL_cleanse(stream, sizeof(*stream));
            return set_status(status, QKD_STATUS_NO_CONNECTION);
        }
        stream->qos = *qos;
        stream->in_use = true;
        stream->creation_time = get_current_time_ms();
        if (uses_legacy_id)
            legacy_stream_id_issued = true;
        return set_status(status, QKD_STATUS_PEER_NOT_CONNECTED);
    }
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
    if (stream_has_expired(stream)) {
        remember_closed(stream->key_id);
        OPENSSL_cleanse(stream, sizeof(*stream));
        return set_status(status, QKD_STATUS_INSUFFICIENT_KEY);
    }

    char metadata_value[64];
    uint32_t metadata_size = 0;
    uint32_t metadata_status =
        prepare_metadata(stream, metadata, metadata_value, &metadata_size);
    if (metadata_status != QKD_STATUS_SUCCESS)
        return set_status(status, metadata_status);

    if (!can_generate_key(stream, *index))
        return set_status(status, QKD_STATUS_INSUFFICIENT_KEY);
    if (!generate_key(stream, key_buffer, *index))
        return set_status(status, QKD_STATUS_NO_CONNECTION);

    if (metadata_size > 0) {
        memcpy(metadata->Metadata_buffer, metadata_value, metadata_size);
        metadata->Metadata_size = metadata_size - 1U;
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
    OPENSSL_cleanse(stream, sizeof(*stream));

    return set_status(status, QKD_STATUS_SUCCESS);
}

const struct qkd_004_backend simulated_backend = {.name = "simulated",
                                                  .open_connect =
                                                      sim_open_connect,
                                                  .get_key = sim_get_key,
                                                  .close = sim_close};

#endif /* QKD_USE_SIMULATED */
