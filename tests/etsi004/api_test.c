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
        .TTL = 60,
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

static void test_legacy_fixture(void) {
    static const unsigned char expected_id[QKD_KSID_SIZE] = {
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x47, 0x58,
        0x59, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0};
    static const unsigned char expected_key[QKD_KEY_SIZE] = {
        0xdf, 0x3f, 0x61, 0x98, 0x04, 0xa9, 0x2f, 0xdb, 0x40, 0x57, 0x19,
        0x2d, 0xc4, 0x3d, 0xd7, 0x48, 0xea, 0x77, 0x8a, 0xdc, 0x52, 0xbc,
        0x49, 0x8c, 0xe8, 0x05, 0x24, 0xc0, 0x14, 0xb8, 0x11, 0x19};
    struct qkd_qos_s qos = supported_qos();
    unsigned char key_stream_id[QKD_KSID_SIZE] = {0};
    unsigned char key[QKD_KEY_SIZE];
    uint32_t index = 0;
    uint32_t status;

    CHECK(OPEN_CONNECT("alice", "bob", &qos, key_stream_id, &status) ==
          QKD_STATUS_PEER_NOT_CONNECTED);
    CHECK(memcmp(key_stream_id, expected_id, sizeof(expected_id)) == 0);
    CHECK(OPEN_CONNECT("bob", "alice", &qos, key_stream_id, &status) ==
          QKD_STATUS_SUCCESS);
    CHECK(GET_KEY(key_stream_id, &index, key, NULL, &status) ==
          QKD_STATUS_SUCCESS);
    CHECK(memcmp(key, expected_key, sizeof(expected_key)) == 0);
    CHECK(CLOSE(key_stream_id, &status) == QKD_STATUS_SUCCESS);
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
    CHECK(invalid_qos.Min_bps == invalid_qos.Max_bps);

    CHECK(OPEN_CONNECT("alice", "bob", &qos, key_stream_id, &status) ==
          QKD_STATUS_PEER_NOT_CONNECTED);
    CHECK(status == QKD_STATUS_PEER_DISCONNECTED);

    unsigned char second_stream_id[QKD_KSID_SIZE] = {0};
    CHECK(OPEN_CONNECT("alice", "bob", &qos, second_stream_id, &status) ==
          QKD_STATUS_PEER_NOT_CONNECTED);
    CHECK(memcmp(key_stream_id, second_stream_id, QKD_KSID_SIZE) != 0);
    CHECK((second_stream_id[6] & 0xf0U) == 0x40U);
    CHECK((second_stream_id[8] & 0xc0U) == 0x80U);
    CHECK(CLOSE(second_stream_id, &status) == QKD_STATUS_SUCCESS);

    unsigned char third_stream_id[QKD_KSID_SIZE] = {0};
    CHECK(OPEN_CONNECT("alice", "bob", &qos, third_stream_id, &status) ==
          QKD_STATUS_PEER_NOT_CONNECTED);
    CHECK(memcmp(second_stream_id, third_stream_id, QKD_KSID_SIZE) != 0);
    CHECK(CLOSE(third_stream_id, &status) == QKD_STATUS_SUCCESS);

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

static void test_predefined_stream_and_qos(void) {
    struct qkd_qos_s initiator_qos = supported_qos();
    initiator_qos.Max_bps = 424242;
    initiator_qos.Min_bps = 42;
    struct qkd_qos_s responder_qos = supported_qos();
    responder_qos.Max_bps = 1;
    responder_qos.Min_bps = 1;
    responder_qos.Key_chunk_size = 1;
    unsigned char predefined_id[QKD_KSID_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint32_t status;

    CHECK(OPEN_CONNECT("alice", "bob", &initiator_qos, predefined_id,
                       &status) == QKD_STATUS_PEER_NOT_CONNECTED);
    CHECK(OPEN_CONNECT("bob", "alice", &responder_qos, predefined_id,
                       &status) == QKD_STATUS_SUCCESS);
    CHECK(responder_qos.Key_chunk_size == initiator_qos.Key_chunk_size);
    CHECK(responder_qos.Max_bps == initiator_qos.Max_bps);
    CHECK(responder_qos.Min_bps == initiator_qos.Min_bps);
    CHECK(memcmp(responder_qos.Metadata_mimetype,
                 initiator_qos.Metadata_mimetype,
                 sizeof(responder_qos.Metadata_mimetype)) == 0);
    CHECK(CLOSE(predefined_id, &status) == QKD_STATUS_SUCCESS);
    CHECK(OPEN_CONNECT("alice", "bob", &initiator_qos, predefined_id,
                       &status) == QKD_STATUS_KSID_IN_USE);
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

    struct qkd_metadata_s no_metadata = {0};
    index = 0;
    CHECK(GET_KEY(key_stream_id, &index, repeated_key, &no_metadata, &status) ==
          QKD_STATUS_SUCCESS);

    unsigned char key_sentinel[QKD_KEY_SIZE];
    memset(key_sentinel, 0xa5, sizeof(key_sentinel));
    unsigned char tiny_metadata_buffer[1] = {0};
    struct qkd_metadata_s metadata = {.Metadata_size = 1,
                                      .Metadata_buffer = tiny_metadata_buffer};
    CHECK(GET_KEY(key_stream_id, &index, key_sentinel, &metadata, &status) ==
          QKD_STATUS_METADATA_SIZE_INSUFFICIENT);
    CHECK(metadata.Metadata_size > 1);
    for (size_t i = 0; i < sizeof(key_sentinel); i++)
        CHECK(key_sentinel[i] == 0xa5);

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

static void test_metadata_mimetype_negotiation(void) {
    struct qkd_qos_s qos = supported_qos();
    memcpy(qos.Metadata_mimetype, "text/plain", sizeof("text/plain"));
    unsigned char key_stream_id[QKD_KSID_SIZE] = {0};
    uint32_t status;

    CHECK(OPEN_CONNECT("alice", "bob", &qos, key_stream_id, &status) ==
          QKD_STATUS_QOS_NOT_MET);
    CHECK(strcmp(qos.Metadata_mimetype, "application/json") == 0);
    for (size_t i = 0; i < sizeof(key_stream_id); i++)
        CHECK(key_stream_id[i] == 0);

    qos = supported_qos();
    memset(qos.Metadata_mimetype, 0, sizeof(qos.Metadata_mimetype));
    CHECK(OPEN_CONNECT("alice", "bob", &qos, key_stream_id, &status) ==
          QKD_STATUS_PEER_NOT_CONNECTED);
    CHECK(OPEN_CONNECT("bob", "alice", &qos, key_stream_id, &status) ==
          QKD_STATUS_SUCCESS);

    unsigned char key[QKD_KEY_SIZE];
    unsigned char metadata_buffer[32];
    memset(metadata_buffer, 0xa5, sizeof(metadata_buffer));
    struct qkd_metadata_s metadata = {
        .Metadata_size = sizeof(metadata_buffer),
        .Metadata_buffer = metadata_buffer,
    };
    uint32_t index = 0;
    CHECK(GET_KEY(key_stream_id, &index, key, &metadata, &status) ==
          QKD_STATUS_SUCCESS);
    CHECK(metadata.Metadata_size == 0);
    for (size_t i = 0; i < sizeof(metadata_buffer); i++)
        CHECK(metadata_buffer[i] == 0xa5);
    CHECK(CLOSE(key_stream_id, &status) == QKD_STATUS_SUCCESS);
}

int main(void) {
    test_backend_registration();
    test_legacy_fixture();
    test_connection_lifecycle();
    test_predefined_stream_and_qos();
    test_key_and_metadata();
    test_metadata_mimetype_negotiation();
    puts("ETSI 004 simulated backend tests passed");
    return 0;
}
