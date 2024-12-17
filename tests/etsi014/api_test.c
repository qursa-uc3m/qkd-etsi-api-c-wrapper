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
static const char *get_required_env(const char *name) {
    const char *value = getenv(name);
    if (value == NULL) {
        fprintf(stderr, "Required environment variable %s is not set\n", name);
        exit(1);
    }
    return value;
}

static const char *TEST_MKME_HOSTNAME;
static const char *TEST_SKME_HOSTNAME;
static const char *TEST_MASTER_SAE;
static const char *TEST_SLAVE_SAE;

static const char *MASTER_CERT_PATH;
static const char *MASTER_KEY_PATH;
static const char *MASTER_CA_CERT_PATH;

static const char *SLAVE_CERT_PATH;
static const char *SLAVE_KEY_PATH;
static const char *SLAVE_CA_CERT_PATH;

static void init_test_config(void) {
    TEST_MKME_HOSTNAME = get_required_env("QKD_MASTER_KME_HOSTNAME");
    TEST_SKME_HOSTNAME = get_required_env("QKD_SLAVE_KME_HOSTNAME");
    TEST_MASTER_SAE = get_required_env("QKD_MASTER_SAE");
    TEST_SLAVE_SAE = get_required_env("QKD_SLAVE_SAE");
    
    printf("Using configuration:\n");
    printf("  Master KME Hostname: %s\n", TEST_MKME_HOSTNAME);
    printf("  Slave KME Hostname: %s\n", TEST_SKME_HOSTNAME);
    printf("  Master SAE: %s\n", TEST_MASTER_SAE);
    printf("  Slave SAE: %s\n", TEST_SLAVE_SAE);
    printf("\n");
}

#else
static const char *TEST_MKME_HOSTNAME = "localhost:8080";
static const char *TEST_SKME_HOSTNAME = "localhost:8080";
static const char *TEST_MASTER_SAE = "SAE_TEST_MASTER";
static const char *TEST_SLAVE_SAE = "SAE_TEST_SLAVE";

static void init_test_config(void) {
    // Nothing to initialize for simulated backend
}
#endif /* QKD_USE_CERBERIS_XGR */

static void test_get_status(void) {
    qkd_status_t status = {0};
    uint32_t result;

    printf("Testing GET_STATUS...\n");

    // Test 1: Basic status retrieval
    result = GET_STATUS(TEST_MKME_HOSTNAME, TEST_SLAVE_SAE, &status);
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
    free(status.master_SAE_ID);
    free(status.slave_SAE_ID);
}

static void test_get_key(void) {
    qkd_key_request_t request = {
        .number = 2, 
        .size = 256,
        .additional_slave_SAE_IDs = NULL,
        .additional_SAE_count = 0,
        .extension_mandatory = NULL,
        .extension_optional = NULL
    };
    qkd_key_container_t container = {0};
    uint32_t result;

    printf("\nTesting GET_KEY...\n");

    // Test 1: Request keys
    result = GET_KEY(TEST_MKME_HOSTNAME, TEST_SLAVE_SAE, &request, &container);    
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
    char *saved_key = strdup(container.keys[0].key);
    
    // Cleanup container
    // for (int i = 0; i < container.key_count; i++) {
    //     free(container.keys[i].key_ID);
    //     free(container.keys[i].key);
    // }
    // free(container.keys);

    // Test 3: Test key retrieval with ID
    qkd_key_id_t key_id = {.key_ID = saved_key_id, .key_ID_extension = NULL};
    qkd_key_ids_t key_ids = {
        .key_IDs = &key_id, 
        .key_ID_count = 1, 
        .key_IDs_extension = NULL
    };

    // Test: Request a key that was already retrived
    result = GET_KEY_WITH_IDS(TEST_SKME_HOSTNAME, TEST_MASTER_SAE, &key_ids,
                               &container);
    #ifndef QKD_USE_CERBERIS_XGR
    assert(result == QKD_STATUS_OK);
    assert(container.key_count == 1);
    #else
    assert(result == QKD_STATUS_SERVER_ERROR);
    printf("  Old key retrieval by ID : PASS\n");

    // Store current values of master certificates
    MASTER_CERT_PATH = getenv("QKD_MASTER_CERT_PATH");
    MASTER_KEY_PATH = getenv("QKD_MASTER_KEY_PATH");
    MASTER_CA_CERT_PATH = getenv("QKD_MASTER_CA_CERT_PATH");

    // Store values of slave certificates
    SLAVE_CERT_PATH = getenv("QKD_SLAVE_CERT_PATH");
    SLAVE_KEY_PATH = getenv("QKD_SLAVE_KEY_PATH");
    SLAVE_CA_CERT_PATH = getenv("QKD_SLAVE_CA_CERT_PATH");

    if (!SLAVE_CERT_PATH || !SLAVE_KEY_PATH || !SLAVE_CA_CERT_PATH) {
        printf("Required certificate environment variables not set for TEST");
        printf("Please set: QKD_SLAVE_CERT_PATH, QKD_SLAVE_KEY_PATH, QKD_SLAVE_CA_CERT_PATH");
        exit(1);
    }

    setenv("QKD_MASTER_CERT_PATH", SLAVE_CERT_PATH, 1);
    setenv("QKD_MASTER_KEY_PATH", SLAVE_KEY_PATH, 1);
    setenv("QKD_MASTER_CA_CERT_PATH", SLAVE_CA_CERT_PATH, 1);

    // Get a key from the slave node
    result = GET_KEY(TEST_SKME_HOSTNAME, TEST_MASTER_SAE, &request, &container);  

    // Store first key ID for next test
    saved_key_id = strdup(container.keys[0].key_ID);
    saved_key = strdup(container.keys[0].key);

    key_id.key_ID = saved_key_id;
    key_ids.key_IDs = &key_id;
    
    result = GET_KEY_WITH_IDS(TEST_SKME_HOSTNAME, TEST_MASTER_SAE, &key_ids,
                               &container);

    setenv("QKD_MASTER_CERT_PATH", MASTER_CERT_PATH, 1);
    setenv("QKD_MASTER_KEY_PATH", MASTER_KEY_PATH, 1);
    setenv("QKD_MASTER_CA_CERT_PATH", MASTER_CA_CERT_PATH, 1);

    assert(result == QKD_STATUS_OK);
    assert(container.key_count == 1);
    assert(strcmp(saved_key,container.keys[0].key) == 0);
    #endif // not QKD_USE_CERBERIS_XGR
    
    printf("  Key retrieval by ID: PASS\n");

    // Cleanup
    free(saved_key_id);
    free(saved_key);

    for (int i = 0; i < container.key_count; i++) {
        free(container.keys[i].key_ID);
        free(container.keys[i].key);
    }
    free(container.keys);
}

int main(void) {
    printf("Running QKD ETSI 014 API tests...\n\n");

    init_test_config();

    // Run basic tests
    test_get_status();
    test_get_key();

    printf("\nAll tests passed!\n");
    return 0;
}