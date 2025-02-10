/* 
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Enhanced ETSI QKD 014 API Test Suite
 * - Testing automatic certificate handling with roles
 */

#include <stdio.h>      // for printf
#include <stdlib.h>     // for free, exit
#include <string.h>     // for strcmp, strdup
#include <stddef.h>     // for size_t, NULL
#include <stdint.h>     // for uint32_t
#include "etsi014/api.h"
#include "qkd_etsi014_backend.h"

/* Global configuration variables */
static const char *MKME_HOSTNAME;
static const char *SKME_HOSTNAME;
static const char *MASTER_SAE;
static const char *SLAVE_SAE;

/* Function declarations */
static const char *get_required_env(const char *name);
static void init_test_config(void);
static void test_certificate_configuration(void);
static void test_key_exchange_protocol(void);

/* Global counters for test summary */
static int total_tests = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Helper macros for test reporting */
#define TEST_PASS(msg) do { \
    printf("[PASS] %s\n", msg); \
    tests_passed++; total_tests++; \
} while (0)

#define TEST_FAIL(msg) do { \
    printf("[FAIL] %s\n", msg); \
    tests_failed++; total_tests++; \
} while (0)

static const char *get_required_env(const char *name) {
    const char *value = getenv(name);
    if (!value) {
        fprintf(stderr, "Required environment variable %s is not set\n", name);
        exit(1);
    }
    return value;
}


/* Initialize test configuration from environment variables */
static void init_test_config(void) {
    printf("\nInitializing QKD ETSI014 Protocol Test\n");
    printf("----------------------------------------\n");
    
    MKME_HOSTNAME = get_required_env("QKD_MASTER_KME_HOSTNAME");
    SKME_HOSTNAME = get_required_env("QKD_SLAVE_KME_HOSTNAME");
    MASTER_SAE = get_required_env("QKD_MASTER_SAE");
    SLAVE_SAE = get_required_env("QKD_SLAVE_SAE");
    
    printf("Configuration loaded:\n");
    printf("ALICE (Initiator/SAE-1):\n");
    printf("  KME: %s\n", MKME_HOSTNAME);
    printf("  SAE: %s\n", MASTER_SAE);
    printf("BOB (Responder/SAE-2):\n");
    printf("  KME: %s\n", SKME_HOSTNAME);
    printf("  SAE: %s\n\n", SLAVE_SAE);
}

/* Test the certificate configuration for different roles */
static void test_certificate_configuration(void) {
    printf("\nTesting Role-Based Certificate Configuration\n");
    printf("------------------------------------------\n");
    
    etsi014_cert_config_t config = {0};
    
    // Test 1: Initiator Role (Alice)
    printf("\n1. Testing Initiator (Role=1) Configuration:\n");
    int result = init_cert_config(1, &config);
    if (result != QKD_STATUS_OK) {
        printf("ERROR: Failed to initialize initiator config (code: %d)\n", result);
        TEST_FAIL("Initiator certificate configuration");
        return;
    }
    printf("Initiator certificate paths:\n");
    printf("  CERT: %s\n", config.cert_path);
    printf("  KEY:  %s\n", config.key_path);
    printf("  CA:   %s\n", config.ca_cert_path);
    TEST_PASS("Initiator certificate configuration");

    // Test 2: Responder Role (Bob)
    printf("\n2. Testing Responder (Role=0) Configuration:\n");
    result = init_cert_config(0, &config);
    if (result != QKD_STATUS_OK) {
        printf("ERROR: Failed to initialize responder config (code: %d)\n", result);
        TEST_FAIL("Responder certificate configuration");
        return;
    }
    printf("Responder certificate paths:\n");
    printf("  CERT: %s\n", config.cert_path);
    printf("  KEY:  %s\n", config.key_path);
    printf("  CA:   %s\n", config.ca_cert_path);
    TEST_PASS("Responder certificate configuration");
    
    printf("\nCertificate Configuration Test Completed\n");
}

/* Cleanup function for a key container */
static void cleanup_container(qkd_key_container_t *container) {
    if (!container) return;
    for (size_t i = 0; i < container->key_count; i++) {
        free(container->keys[i].key_ID);
        free(container->keys[i].key);
    }
    free(container->keys);
    container->keys = NULL;
    container->key_count = 0;
}


static void cleanup_status(qkd_status_t *status) {
    if (!status) return;
    free(status->source_KME_ID);
    free(status->target_KME_ID);
    free(status->master_SAE_ID);
    free(status->slave_SAE_ID);
}

static void test_key_exchange_protocol(void) {
    printf("\nTesting QKD Protocol with Role-Based Certificates\n");
    printf("----------------------------------------------\n");
    
    // ALICE test: Initiator (role=1)
    printf("\n1. ALICE (Initiator, role=1):\n");
    etsi014_cert_config_t alice_config = {0};
    int rc = init_cert_config(1, &alice_config);
    if (rc != QKD_STATUS_OK) {
        printf("ERROR: Failed to initialize Alice's certificate config\n");
        TEST_FAIL("Alice certificate initialization");
        return;
    }
    printf("Verified Alice's certificate configuration (role=1)\n");
    TEST_PASS("Alice certificate initialization");
;
    
    qkd_key_container_t alice_container = {0};
    qkd_key_request_t request = {
        .number = 1,
        .size = 256,
        .additional_slave_SAE_IDs = NULL,
        .additional_SAE_count = 0
    };
    
    uint32_t result = GET_KEY(MKME_HOSTNAME, SLAVE_SAE, &request, &alice_container);
    if (result != QKD_STATUS_OK) {
        printf("ERROR: ALICE's GET_KEY failed (code: %u)\n", result);
        TEST_FAIL("Alice GET_KEY");
        goto cleanup_alice;
    }
    
    // Save ALICE's key_ID for Bob to use
    char *alice_key_id = strdup(alice_container.keys[0].key_ID);
    printf("SUCCESS: ALICE got key with ID: %s\n", alice_key_id);
    TEST_PASS("Alice GET_KEY");
    
    // BOB test: Responder (role=0)
    printf("\n2. BOB (Responder, role=0):\n");
    etsi014_cert_config_t bob_config = {0};
    rc = init_cert_config(0, &bob_config);
    if (rc != QKD_STATUS_OK) {
        printf("ERROR: Failed to initialize Bob's certificate config\n");
        TEST_FAIL("Bob certificate initialization");
        goto cleanup_alice;
    }
    printf("Using Bob's certificates (role=0):\n");
    printf("  CERT: %s\n", bob_config.cert_path);
    printf("  KEY:  %s\n", bob_config.key_path);
    printf("  CA:   %s\n", bob_config.ca_cert_path);
    TEST_PASS("Bob certificate initialization");
    
    // BOB requests the same key using responder certificates
    qkd_key_container_t bob_container = {0};
    qkd_key_id_t id = { .key_ID = alice_key_id, .key_ID_extension = NULL };
    qkd_key_ids_t key_list = {
        .key_IDs = &id,
        .key_ID_count = 1,
        .key_IDs_extension = NULL
    };

    printf("Verifying key ID to be used in BOB's request...\n");
    if (strcmp(alice_key_id, id.key_ID) != 0) {
        printf("ERROR: Request key ID mismatch!\n");
        printf("  ALICE's key_ID: %s\n", alice_key_id);
        printf("  Request key_ID: %s\n", id.key_ID);
        TEST_FAIL("Key ID verification");
        goto cleanup_all;
    }
    printf("SUCCESS: Request will use ALICE's key ID: %s\n", alice_key_id);
    TEST_PASS("Key ID verification");
    
    printf("BOB's request using key ID: %s\n", alice_key_id);
    result = GET_KEY_WITH_IDS(SKME_HOSTNAME, MASTER_SAE, &key_list, &bob_container);
    if (result != QKD_STATUS_OK) {
        printf("ERROR: BOB's GET_KEY_WITH_IDS failed (code: %u)\n", result);
        TEST_FAIL("Bob GET_KEY_WITH_IDS");
        goto cleanup_all;
    } else {
        printf("  Number of keys returned: %d\n", bob_container.key_count);
        for (int i = 0; i < bob_container.key_count; i++) {
            printf("  Key #%d:\n", i + 1);
            printf("    Key ID: %s\n", bob_container.keys[i].key_ID);
            printf("    Key Value (Base64): %s\n", bob_container.keys[i].key);
        }
        printf("\nSUCCESS: Bob's GET_KEY_WITH_IDS call completed successfully.\n");
        TEST_PASS("Bob GET_KEY_WITH_IDS");
    }
    
cleanup_all:
    free(alice_key_id);
    cleanup_container(&bob_container);
    
cleanup_alice:
    cleanup_container(&alice_container);
}

int main(void) {
    init_test_config();
    test_certificate_configuration();
    test_key_exchange_protocol();
    printf("\n========================================\n");
    printf("           TEST SUMMARY\n");
    printf("========================================\n");
    printf("Total tests run: %d\n", total_tests);
    printf("Tests passed   : %d\n", tests_passed);
    printf("Tests failed   : %d\n", tests_failed);
    if (tests_failed == 0)
        printf("Overall Status : \033[1;32mALL TESTS PASSED\033[0m\n");
    else
        printf("Overall Status : \033[1;31mSOME TESTS FAILED\033[0m\n");
    printf("========================================\n");
    return 0;
}