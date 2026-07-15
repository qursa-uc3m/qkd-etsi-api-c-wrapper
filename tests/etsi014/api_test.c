/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 * - Pedro Otero-García (@pedrotega) - UVigo
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "etsi014/api.h"

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                    #condition);                                               \
            exit(EXIT_FAILURE);                                                \
        }                                                                      \
    } while (0)

#ifdef QKD_USE_ETSI014_BACKEND

static const char *get_required_env(const char *name) {
    const char *value = getenv(name);
    if (!value) {
        fprintf(stderr, "Required environment variable %s is not set\n", name);
        exit(EXIT_FAILURE);
    }
    return value;
}

static const char *master_kme_hostname;
static const char *slave_kme_hostname;
static const char *master_sae;
static const char *slave_sae;

static void init_test_config(void) {
    master_kme_hostname = get_required_env("QKD_MASTER_KME_HOSTNAME");
    slave_kme_hostname = get_required_env("QKD_SLAVE_KME_HOSTNAME");
    master_sae = get_required_env("QKD_MASTER_SAE");
    slave_sae = get_required_env("QKD_SLAVE_SAE");
}

#else

static const char *master_kme_hostname = "master.example";
static const char *slave_kme_hostname = "slave.example";
static const char *master_sae = "SAE_TEST_MASTER";
static const char *slave_sae = "SAE_TEST_SLAVE";

static void init_test_config(void) {}

#endif

static void cleanup_status(qkd_status_t *status) {
    free(status->source_KME_ID);
    free(status->target_KME_ID);
    free(status->master_SAE_ID);
    free(status->slave_SAE_ID);
    memset(status, 0, sizeof(*status));
}

static void cleanup_container(qkd_key_container_t *container) {
    for (int32_t i = 0; i < container->key_count; i++) {
        free(container->keys[i].key_ID);
        free(container->keys[i].key);
    }
    free(container->keys);
    memset(container, 0, sizeof(*container));
}

static void test_backend_registration(void) {
    const struct qkd_014_backend *backend = get_active_014_backend();

    CHECK(backend != NULL);
    register_qkd_014_backend(NULL);
    CHECK(GET_KEY(master_kme_hostname, slave_sae, NULL, NULL) ==
          QKD_STATUS_BAD_REQUEST);
    qkd_key_container_t container = {0};
    CHECK(GET_KEY(master_kme_hostname, slave_sae, NULL, &container) ==
          QKD_STATUS_SERVER_ERROR);
    register_qkd_014_backend(backend);
}

static void test_get_status(void) {
    qkd_status_t status = {0};

    CHECK(GET_STATUS(master_kme_hostname, slave_sae, &status) == QKD_STATUS_OK);
    CHECK(status.source_KME_ID && status.target_KME_ID &&
          status.master_SAE_ID && status.slave_SAE_ID);
    CHECK(status.key_size == 256);
    CHECK(status.min_key_size == 256);
    CHECK(status.max_key_size == 256);
    CHECK(status.max_key_per_request >= 2);
    cleanup_status(&status);

    CHECK(GET_STATUS(NULL, slave_sae, &status) == QKD_STATUS_BAD_REQUEST);
}

#ifndef QKD_USE_ETSI014_BACKEND
static void test_simulated_key_exchange(void) {
    qkd_key_request_t request = {.number = 2, .size = 256};
    qkd_key_container_t issued = {0};

    CHECK(GET_KEY(master_kme_hostname, slave_sae, &request, &issued) ==
          QKD_STATUS_OK);
    CHECK(issued.key_count == 2);
    CHECK(issued.keys[0].key_ID && issued.keys[0].key);
    CHECK(issued.keys[1].key_ID && issued.keys[1].key);
    CHECK(strcmp(issued.keys[0].key_ID, issued.keys[1].key_ID) != 0);
    CHECK(strcmp(issued.keys[0].key, issued.keys[1].key) != 0);

    qkd_key_id_t requested_ids[2] = {
        {.key_ID = issued.keys[0].key_ID},
        {.key_ID = issued.keys[1].key_ID},
    };
    qkd_key_ids_t key_ids = {.key_IDs = requested_ids, .key_ID_count = 2};
    qkd_key_container_t retrieved = {0};

    char *second_key_id = requested_ids[1].key_ID;
    requested_ids[1].key_ID = requested_ids[0].key_ID;
    CHECK(GET_KEY_WITH_IDS(slave_kme_hostname, master_sae, &key_ids,
                           &retrieved) == QKD_STATUS_BAD_REQUEST);
    requested_ids[1].key_ID = second_key_id;

    CHECK(GET_KEY_WITH_IDS(slave_kme_hostname, master_sae, &key_ids,
                           &retrieved) == QKD_STATUS_OK);
    CHECK(retrieved.key_count == issued.key_count);
    for (int32_t i = 0; i < retrieved.key_count; i++) {
        CHECK(strcmp(retrieved.keys[i].key_ID, issued.keys[i].key_ID) == 0);
        CHECK(strcmp(retrieved.keys[i].key, issued.keys[i].key) == 0);
    }
    cleanup_container(&retrieved);

    CHECK(GET_KEY_WITH_IDS(slave_kme_hostname, master_sae, &key_ids,
                           &retrieved) == QKD_STATUS_BAD_REQUEST);

    cleanup_container(&issued);

    CHECK(GET_KEY(master_kme_hostname, slave_sae, NULL, &issued) ==
          QKD_STATUS_OK);
    CHECK(issued.key_count == 1);
    requested_ids[0].key_ID = issued.keys[0].key_ID;
    key_ids.key_ID_count = 1;
    CHECK(GET_KEY_WITH_IDS(slave_kme_hostname, master_sae, &key_ids,
                           &retrieved) == QKD_STATUS_OK);
    cleanup_container(&retrieved);
    cleanup_container(&issued);

    request.number = 17;
    CHECK(GET_KEY(master_kme_hostname, slave_sae, &request, &issued) ==
          QKD_STATUS_BAD_REQUEST);
    request.number = -1;
    CHECK(GET_KEY(master_kme_hostname, slave_sae, &request, &issued) ==
          QKD_STATUS_BAD_REQUEST);
}
#endif

int main(void) {
    init_test_config();
    test_backend_registration();
    test_get_status();
#ifndef QKD_USE_ETSI014_BACKEND
    test_simulated_key_exchange();
#endif
    puts("ETSI 014 API tests passed");
    return 0;
}
