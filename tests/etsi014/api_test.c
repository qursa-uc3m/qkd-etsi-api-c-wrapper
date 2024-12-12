/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 * - Pedro Otero-García (@pedrotega) - UVigo
 */

/*
 * tests/etsi014/api_test.c
 */

#include "etsi014/api.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test configuration */
#ifdef QKD_USE_CERBERIS_XGR
static const char *TEST_KME_HOSTNAME = "https://castor.det.uvigo.es:444";
static const char *TEST_MASTER_SAE = "CONSA";
static const char *TEST_SLAVE_SAE = "CONSB";

static const char *TEST_PUB_KEY = "../certs/ETSIA.pem";
static const char *TEST_PRIV_KEY = "../certs/ETSIA-key.pem";
static const char *TEST_ROOT_KEY = "../certs/ChrisCA.pem";
#else
static const char *TEST_KME_HOSTNAME = "localhost:8080";
static const char *TEST_MASTER_SAE = "SAE_TEST_MASTER";
static const char *TEST_SLAVE_SAE = "SAE_TEST_SLAVE";
#endif /* QKD_USE_CERBERIS_XGR */

static void test_get_status(void) {
    qkd_status_t status = {0};
    uint32_t result;

    printf("Testing GET_STATUS...\n");

    // Test 1: Basic status retrieval
    result = GET_STATUS(TEST_KME_HOSTNAME, TEST_SLAVE_SAE, &status);
    assert(result == QKD_STATUS_OK);
    assert(status.source_KME_ID != NULL);
    assert(status.target_KME_ID != NULL);
    assert(status.key_size > 0);
    printf("  Basic status retrieval: PASS\n");

    // Test 2: Invalid parameters
    result = GET_STATUS(NULL, TEST_SLAVE_SAE, &status);
    assert(result == QKD_STATUS_BAD_REQUEST);
    printf("  NULL parameter handling: PASS\n");

    // Cleanup
    free(status.source_KME_ID);
    free(status.target_KME_ID);
    free(status.slave_SAE_ID);
}

static void test_get_key(void) {
    qkd_key_request_t request = {.number = 1, // Nodes are not prepared for multiple key retrivals
                                 .size = 256,
                                 .additional_slave_SAE_IDs = NULL,
                                 .additional_SAE_count = 0,
                                 .extension_mandatory = NULL,
                                 .extension_optional = NULL};
    qkd_key_container_t container = {0};
    uint32_t result;

    printf("\nTesting GET_KEY...\n");

    // Test 1: Request keys
    result = GET_KEY(TEST_KME_HOSTNAME, TEST_SLAVE_SAE, &request, &container);
    
    assert(result == QKD_STATUS_OK);
    assert(container.key_count == request.number);
    assert(container.keys != NULL);
    printf("  Basic key retrieval: PASS\n");

    // Test 2: Verify key format
    for (int i = 0; i < container.key_count; i++) {
        assert(container.keys[i].key_ID != NULL);
        assert(container.keys[i].key != NULL);
    }
    printf("  Key format validation: PASS\n");

    // Store first key ID for next test
    char *saved_key_id = strdup(container.keys[0].key_ID);

    // Cleanup container
    for (int i = 0; i < container.key_count; i++) {
        free(container.keys[i].key_ID);
        free(container.keys[i].key);
    }
    free(container.keys);

    // Test 3: Test key retrieval with ID
    qkd_key_id_t key_id = {.key_ID = saved_key_id, .key_ID_extension = NULL};
    qkd_key_ids_t key_ids = {
        .key_IDs = &key_id, .key_ID_count = 1, .key_IDs_extension = NULL};

    result = GET_KEY_WITH_IDS(TEST_KME_HOSTNAME, TEST_MASTER_SAE, &key_ids,
                              &container);
    assert(result == QKD_STATUS_OK);
    assert(container.key_count == 1);
    printf("  Key retrieval by ID: PASS\n");

    // Cleanup
    free(saved_key_id);
    for (int i = 0; i < container.key_count; i++) {
        free(container.keys[i].key_ID);
        free(container.keys[i].key);
    }
    free(container.keys);
}

int main(void) {
    printf("Running QKD ETSI 014 API tests...\n\n");

    // Run basic tests
    test_get_status();
    test_get_key();

    printf("\nAll tests passed!\n");
    return 0;
}