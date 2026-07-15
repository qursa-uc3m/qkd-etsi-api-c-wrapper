/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "etsi004/api.h"
#include "qkd_etsi_api.h"

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                    #condition);                                               \
            exit(EXIT_FAILURE);                                                \
        }                                                                      \
    } while (0)

static struct qkd_qos_s supported_qos(void) {
    struct qkd_qos_s qos = {
        .Key_chunk_size = QKD_KEY_SIZE,
        .Max_bps = 1000000,
        .Min_bps = 100,
        .Jitter = 10,
        .Priority = 1,
        .Timeout = 1000,
        .TTL = 1,
    };
    memcpy(qos.Metadata_mimetype, "application/json",
           sizeof("application/json"));
    return qos;
}

static void test_backend_registration(void) {
    const struct qkd_004_backend *backend = get_active_004_backend();

    CHECK(backend != NULL);
    register_qkd_004_backend(NULL);
    CHECK(get_active_004_backend() == NULL);
    CHECK(OPEN_CONNECT(NULL, NULL, NULL, NULL, NULL) ==
          QKD_STATUS_NO_CONNECTION);
    register_qkd_004_backend(backend);
    CHECK(get_active_004_backend() == backend);
}

static void test_connection_lifecycle(void) {
    struct qkd_qos_s qos = supported_qos();
    unsigned char key_stream_id[QKD_KSID_SIZE] = {0};
    uint32_t status = UINT32_MAX;

    CHECK(OPEN_CONNECT("alice", "bob", &qos, key_stream_id, NULL) ==
          QKD_STATUS_NO_CONNECTION);

    struct qkd_qos_s invalid_qos = qos;
    invalid_qos.Min_bps = invalid_qos.Max_bps + 1U;
    CHECK(OPEN_CONNECT("alice", "bob", &invalid_qos, key_stream_id, &status) ==
          QKD_STATUS_QOS_NOT_MET);
    CHECK(status == QKD_STATUS_QOS_NOT_MET);

    CHECK(OPEN_CONNECT("alice", "bob", &qos, key_stream_id, &status) ==
          QKD_STATUS_PEER_NOT_CONNECTED);
    CHECK(status == QKD_STATUS_PEER_DISCONNECTED);

    unsigned char second_stream_id[QKD_KSID_SIZE] = {0};
    CHECK(OPEN_CONNECT("alice", "bob", &qos, second_stream_id, &status) ==
          QKD_STATUS_PEER_NOT_CONNECTED);
    CHECK(memcmp(key_stream_id, second_stream_id, QKD_KSID_SIZE) != 0);
    CHECK(CLOSE(second_stream_id, &status) == QKD_STATUS_SUCCESS);

    unsigned char key[QKD_KEY_SIZE];
    uint32_t index = 0;
    CHECK(GET_KEY(key_stream_id, &index, key, NULL, &status) ==
          QKD_STATUS_PEER_NOT_CONNECTED_GET_KEY);

    CHECK(OPEN_CONNECT("bob", "alice", &qos, key_stream_id, &status) ==
          QKD_STATUS_SUCCESS);
    CHECK(OPEN_CONNECT("bob", "alice", &qos, key_stream_id, &status) ==
          QKD_STATUS_KSID_IN_USE);

    CHECK(CLOSE(key_stream_id, &status) == QKD_STATUS_SUCCESS);
    CHECK(GET_KEY(key_stream_id, &index, key, NULL, &status) ==
          QKD_STATUS_PEER_NOT_CONNECTED_GET_KEY);
    CHECK(CLOSE(key_stream_id, &status) == QKD_STATUS_SUCCESS);
    CHECK(CLOSE(key_stream_id, &status) == QKD_STATUS_SUCCESS);
}

static void test_key_and_metadata(void) {
    struct qkd_qos_s qos = supported_qos();
    unsigned char key_stream_id[QKD_KSID_SIZE] = {0};
    unsigned char first_key[QKD_KEY_SIZE];
    unsigned char repeated_key[QKD_KEY_SIZE];
    uint32_t index = 0;
    uint32_t status;

    CHECK(OPEN_CONNECT("alice", "bob", &qos, key_stream_id, &status) ==
          QKD_STATUS_PEER_NOT_CONNECTED);
    CHECK(OPEN_CONNECT("bob", "alice", &qos, key_stream_id, &status) ==
          QKD_STATUS_SUCCESS);

    CHECK(GET_KEY(key_stream_id, &index, first_key, NULL, &status) ==
          QKD_STATUS_SUCCESS);
    CHECK(GET_KEY(key_stream_id, &index, repeated_key, NULL, &status) ==
          QKD_STATUS_SUCCESS);
    CHECK(memcmp(first_key, repeated_key, sizeof(first_key)) == 0);

    unsigned char second_stream_id[QKD_KSID_SIZE] = {0};
    unsigned char second_stream_key[QKD_KEY_SIZE];
    CHECK(OPEN_CONNECT("alice", "bob", &qos, second_stream_id, &status) ==
          QKD_STATUS_PEER_NOT_CONNECTED);
    CHECK(OPEN_CONNECT("bob", "alice", &qos, second_stream_id, &status) ==
          QKD_STATUS_SUCCESS);
    CHECK(GET_KEY(second_stream_id, &index, second_stream_key, NULL, &status) ==
          QKD_STATUS_SUCCESS);
    CHECK(memcmp(first_key, second_stream_key, sizeof(first_key)) != 0);
    CHECK(CLOSE(second_stream_id, &status) == QKD_STATUS_SUCCESS);

    index = 1000000;
    CHECK(GET_KEY(key_stream_id, &index, repeated_key, NULL, &status) ==
          QKD_STATUS_INSUFFICIENT_KEY);

    struct qkd_metadata_s metadata = {0};
    index = 0;
    CHECK(GET_KEY(key_stream_id, &index, repeated_key, &metadata, &status) ==
          QKD_STATUS_METADATA_SIZE_INSUFFICIENT);
    CHECK(metadata.Metadata_size > 1);

    unsigned char metadata_buffer[QKD_METADATA_MAX_SIZE];
    metadata.Metadata_buffer = metadata_buffer;
    metadata.Metadata_size = sizeof(metadata_buffer);
    CHECK(GET_KEY(key_stream_id, &index, repeated_key, &metadata, &status) ==
          QKD_STATUS_SUCCESS);
    CHECK(metadata.Metadata_size > 0);
    CHECK(metadata_buffer[metadata.Metadata_size] == '\0');

    CHECK(CLOSE(key_stream_id, &status) == QKD_STATUS_SUCCESS);
    CHECK(CLOSE(key_stream_id, &status) == QKD_STATUS_SUCCESS);
}

int main(void) {
    test_backend_registration();
    test_connection_lifecycle();
    test_key_and_metadata();
    puts("ETSI 004 simulated backend tests passed");
    return 0;
}
