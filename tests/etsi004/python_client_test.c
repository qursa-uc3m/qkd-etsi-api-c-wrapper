/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 */

/*
 * Integration test for the python_client backend. It needs a running QUBIP
 * ETSI 004 server; source scripts/etsi004_env.sh before running it.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "etsi004/api.h"
#include "qkd_etsi_api.h"

#define TEST_SKIPPED 77

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                    #condition);                                               \
            exit(EXIT_FAILURE);                                                \
        }                                                                      \
    } while (0)

static struct qkd_qos_s client_qos(void) {
    struct qkd_qos_s qos = {
        .Key_chunk_size = QKD_KEY_SIZE,
        .Max_bps = 40000,
        .Min_bps = 5000,
        .Jitter = 10,
        .Priority = 0,
        .Timeout = 5000,
        .TTL = 3600,
    };
    memcpy(qos.Metadata_mimetype, "application/json",
           sizeof("application/json"));
    return qos;
}

static void get_key(const unsigned char *key_stream_id, uint32_t index,
                    unsigned char *key) {
    unsigned char metadata_buffer[QKD_METADATA_MAX_SIZE];
    struct qkd_metadata_s metadata = {sizeof(metadata_buffer), metadata_buffer};
    uint32_t status = UINT32_MAX;

    CHECK(GET_KEY(key_stream_id, &index, key, &metadata, &status) ==
          QKD_STATUS_SUCCESS);
    CHECK(status == QKD_STATUS_SUCCESS);
}

int main(void) {
    const char *address = getenv("SERVER_ADDRESS");
    const char *port = getenv("SERVER_PORT");
    if (!address || !port) {
        fprintf(stderr, "SERVER_ADDRESS and SERVER_PORT are not set, "
                        "skipping (see scripts/etsi004_env.sh)\n");
        return TEST_SKIPPED;
    }

    char destination[QKD_MAX_URI_LEN];
    CHECK(snprintf(destination, sizeof(destination), "server://%s:%s", address,
                   port) < (int)sizeof(destination));

    struct qkd_qos_s qos = client_qos();
    unsigned char key_stream_id[QKD_KSID_SIZE] = {0};
    static const unsigned char null_id[QKD_KSID_SIZE];
    uint32_t status = UINT32_MAX;

    uint32_t result = OPEN_CONNECT("client://localhost", destination, &qos,
                                   key_stream_id, &status);
    CHECK(result == status);
    CHECK(status == QKD_STATUS_SUCCESS || status == QKD_STATUS_QOS_NOT_MET);
    CHECK(memcmp(key_stream_id, null_id, sizeof(null_id)) != 0);

    unsigned char first_key[QKD_KEY_SIZE];
    unsigned char second_key[QKD_KEY_SIZE];
    unsigned char repeated_key[QKD_KEY_SIZE];
    get_key(key_stream_id, 0, first_key);
    get_key(key_stream_id, 1, second_key);
    get_key(key_stream_id, 0, repeated_key);
    CHECK(memcmp(first_key, second_key, QKD_KEY_SIZE) != 0);
    CHECK(memcmp(first_key, repeated_key, QKD_KEY_SIZE) == 0);

    CHECK(CLOSE(key_stream_id, &status) == QKD_STATUS_SUCCESS);

    /* Nothing listens on port 1: this must not look like a reservation. */
    unsigned char unused_id[QKD_KSID_SIZE] = {0};
    qos = client_qos();
    CHECK(OPEN_CONNECT("client://localhost", "server://127.0.0.1:1", &qos,
                       unused_id, &status) == QKD_STATUS_NO_CONNECTION);
    CHECK(status == QKD_STATUS_NO_CONNECTION);

    printf("python_client backend: all checks passed\n");
    return EXIT_SUCCESS;
}
