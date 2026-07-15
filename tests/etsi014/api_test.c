/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 * - Pedro Otero-García (@pedrotega) - UVigo
 */

#include <ctype.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "etsi014/api.h"
#include "qkd_etsi_api.h"

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

static void check_key_format(const qkd_key_t *key) {
    unsigned char decoded[64];
    size_t encoded_length = strlen(key->key);

    CHECK(strlen(key->key_ID) == 36);
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23)
            CHECK(key->key_ID[i] == '-');
        else
            CHECK(isxdigit((unsigned char)key->key_ID[i]));
    }
    CHECK(encoded_length <= INT32_MAX);
    int decoded_length = EVP_DecodeBlock(
        decoded, (const unsigned char *)key->key, (int)encoded_length);
    CHECK(decoded_length >= 0);
    while (encoded_length > 0 && key->key[encoded_length - 1U] == '=') {
        decoded_length--;
        encoded_length--;
    }
    CHECK(decoded_length == 32);
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

    const struct qkd_014_backend incomplete_backend = {.name = "incomplete"};
    register_qkd_014_backend(&incomplete_backend);
    qkd_status_t status = {0};
    qkd_key_ids_t ids = {0};
    CHECK(GET_STATUS(master_kme_hostname, slave_sae, &status) ==
          QKD_STATUS_SERVER_ERROR);
    CHECK(GET_KEY_WITH_IDS(slave_kme_hostname, master_sae, &ids, &container) ==
          QKD_STATUS_SERVER_ERROR);

    register_qkd_014_backend(backend);
}

static void test_get_status(void) {
    qkd_status_t status = {0};

    CHECK(GET_STATUS(master_kme_hostname, slave_sae, &status) == QKD_STATUS_OK);
    CHECK(status.source_KME_ID && status.target_KME_ID &&
          status.master_SAE_ID && status.slave_SAE_ID);
    CHECK(status.key_size > 0);
    CHECK(status.min_key_size > 0);
    CHECK(status.min_key_size <= status.key_size);
    CHECK(status.key_size <= status.max_key_size);
    CHECK(status.stored_key_count >= 0);
    CHECK(status.stored_key_count <= status.max_key_count);
    CHECK(status.max_key_per_request > 0);
    CHECK(status.max_SAE_ID_count >= 0);
#ifndef QKD_USE_ETSI014_BACKEND
    CHECK(status.key_size == QKD_KEY_SIZE_BITS);
    CHECK(status.min_key_size == QKD_KEY_SIZE_BITS);
    CHECK(status.max_key_size == QKD_KEY_SIZE_BITS);
    CHECK(status.max_key_per_request >= 2);
    CHECK(status.max_SAE_ID_count == 0);
    CHECK(status.stored_key_count == status.max_key_count);
#endif
    qkd_status_free(&status);
    qkd_status_free(&status);

    CHECK(GET_STATUS(NULL, slave_sae, &status) == QKD_STATUS_BAD_REQUEST);
}

static void test_unsupported_request_features(void) {
    qkd_key_container_t container = {0};
    qkd_key_request_t request = {
        .number = 1, .size = QKD_KEY_SIZE_BITS, .additional_SAE_count = 1};

    CHECK(GET_KEY(master_kme_hostname, slave_sae, &request, &container) ==
          QKD_STATUS_BAD_REQUEST);
    request.additional_SAE_count = 0;
    request.extension_mandatory = &request;
    CHECK(GET_KEY(master_kme_hostname, slave_sae, &request, &container) ==
          QKD_STATUS_BAD_REQUEST);

    qkd_key_id_t id = {.key_ID = "00000000-0000-4000-8000-000000000000",
                       .key_ID_extension = &request};
    qkd_key_ids_t ids = {.key_IDs = &id, .key_ID_count = 1};
    CHECK(GET_KEY_WITH_IDS(slave_kme_hostname, master_sae, &ids, &container) ==
          QKD_STATUS_BAD_REQUEST);
    id.key_ID_extension = NULL;
    ids.key_IDs_extension = &request;
    CHECK(GET_KEY_WITH_IDS(slave_kme_hostname, master_sae, &ids, &container) ==
          QKD_STATUS_BAD_REQUEST);
}

#ifndef QKD_USE_ETSI014_BACKEND
static void test_simulated_key_exchange(void) {
    qkd_key_request_t request = {.number = 2, .size = QKD_KEY_SIZE_BITS};
    qkd_key_container_t issued = {0};

    request.additional_SAE_count = 1;
    CHECK(GET_KEY(master_kme_hostname, slave_sae, &request, &issued) ==
          QKD_STATUS_BAD_REQUEST);
    request.additional_SAE_count = 0;
    request.extension_mandatory = &request;
    CHECK(GET_KEY(master_kme_hostname, slave_sae, &request, &issued) ==
          QKD_STATUS_BAD_REQUEST);
    request.extension_mandatory = NULL;
    request.extension_optional = &request;

    CHECK(GET_KEY(master_kme_hostname, slave_sae, &request, &issued) ==
          QKD_STATUS_OK);
    CHECK(issued.key_count == 2);
    CHECK(issued.keys[0].key_ID && issued.keys[0].key);
    CHECK(issued.keys[1].key_ID && issued.keys[1].key);
    CHECK(strcmp(issued.keys[0].key_ID, issued.keys[1].key_ID) != 0);
    CHECK(strcmp(issued.keys[0].key, issued.keys[1].key) != 0);
    check_key_format(&issued.keys[0]);
    check_key_format(&issued.keys[1]);

    qkd_status_t status = {0};
    CHECK(GET_STATUS(master_kme_hostname, slave_sae, &status) == QKD_STATUS_OK);
    CHECK(status.stored_key_count == status.max_key_count - 2);
    qkd_status_free(&status);

    qkd_key_id_t requested_ids[2] = {
        {.key_ID = issued.keys[0].key_ID},
        {.key_ID = issued.keys[1].key_ID},
    };
    qkd_key_ids_t key_ids = {.key_IDs = requested_ids, .key_ID_count = 2};
    qkd_key_container_t retrieved = {0};

    key_ids.key_IDs_extension = &key_ids;
    CHECK(GET_KEY_WITH_IDS(slave_kme_hostname, master_sae, &key_ids,
                           &retrieved) == QKD_STATUS_BAD_REQUEST);
    key_ids.key_IDs_extension = NULL;
    requested_ids[0].key_ID_extension = &key_ids;
    CHECK(GET_KEY_WITH_IDS(slave_kme_hostname, master_sae, &key_ids,
                           &retrieved) == QKD_STATUS_BAD_REQUEST);
    requested_ids[0].key_ID_extension = NULL;

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
    qkd_key_container_free(&retrieved);

    CHECK(GET_KEY_WITH_IDS(slave_kme_hostname, master_sae, &key_ids,
                           &retrieved) == QKD_STATUS_BAD_REQUEST);

    qkd_key_container_free(&issued);

    CHECK(GET_KEY(master_kme_hostname, slave_sae, NULL, &issued) ==
          QKD_STATUS_OK);
    CHECK(issued.key_count == 1);
    requested_ids[0].key_ID = issued.keys[0].key_ID;
    key_ids.key_ID_count = 1;
    CHECK(GET_KEY_WITH_IDS(slave_kme_hostname, master_sae, &key_ids,
                           &retrieved) == QKD_STATUS_OK);
    qkd_key_container_free(&retrieved);
    qkd_key_container_free(&issued);
    qkd_key_container_free(&issued);

    CHECK(GET_STATUS(master_kme_hostname, slave_sae, &status) == QKD_STATUS_OK);
    CHECK(status.stored_key_count == status.max_key_count);
    qkd_status_free(&status);

    request.number = 17;
    CHECK(GET_KEY(master_kme_hostname, slave_sae, &request, &issued) ==
          QKD_STATUS_BAD_REQUEST);
    request.number = -1;
    CHECK(GET_KEY(master_kme_hostname, slave_sae, &request, &issued) ==
          QKD_STATUS_BAD_REQUEST);
    request.number = 1;
    request.size = 128;
    CHECK(GET_KEY(master_kme_hostname, slave_sae, &request, &issued) ==
          QKD_STATUS_BAD_REQUEST);
}

static void test_simulated_capacity(void) {
    qkd_key_request_t request = {.number = 16, .size = QKD_KEY_SIZE_BITS};
    qkd_key_container_t issued = {0};
    qkd_key_container_t retrieved = {0};

    CHECK(GET_KEY(master_kme_hostname, slave_sae, &request, &issued) ==
          QKD_STATUS_OK);
    CHECK(issued.key_count == 16);

    qkd_key_container_t extra = {0};
    CHECK(GET_KEY(master_kme_hostname, slave_sae, NULL, &extra) ==
          QKD_STATUS_SERVER_ERROR);
    CHECK(extra.keys == NULL);

    qkd_key_id_t requested_ids[16] = {0};
    for (int32_t i = 0; i < issued.key_count; i++)
        requested_ids[i].key_ID = issued.keys[i].key_ID;
    qkd_key_ids_t ids = {.key_IDs = requested_ids, .key_ID_count = 16};
    CHECK(GET_KEY_WITH_IDS(slave_kme_hostname, master_sae, &ids, &retrieved) ==
          QKD_STATUS_OK);
    CHECK(retrieved.key_count == issued.key_count);

    qkd_key_container_free(&retrieved);
    qkd_key_container_free(&issued);
}
#endif

int main(void) {
    init_test_config();
    test_backend_registration();
    test_get_status();
    test_unsupported_request_features();
#ifndef QKD_USE_ETSI014_BACKEND
    test_simulated_key_exchange();
    test_simulated_capacity();
#endif
    puts("ETSI 014 API tests passed");
    return 0;
}
