/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 */

/*
 * src/etsi014/backends/simulated.c
 */

#include <openssl/evp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "etsi014/api.h"
#include "etsi014/backends/simulated.h"

#ifdef QKD_USE_SIMULATED

#define MAX_KEYS 1024
#define DEFAULT_KEY_SIZE 256

/* Simulated KME info */
static const char *LOCAL_KME_ID = "KME_SIM_LOCAL";
static const char *REMOTE_KME_ID = "KME_SIM_REMOTE";

/* Simplified key storage */
static struct {
    char key_id[37];
    unsigned char key[DEFAULT_KEY_SIZE];
} key_store[MAX_KEYS];

static size_t stored_key_count = 0;

/* Helper functions */
static void generate_simulated_key(unsigned char *key) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, &stored_key_count, sizeof(size_t));
    EVP_DigestFinal_ex(ctx, key, NULL);
    EVP_MD_CTX_free(ctx);
}

/* Backend implementation */
static uint32_t sim_get_status(const char *kme_hostname,
                               const char *slave_sae_id, qkd_status_t *status) {
    status->source_KME_ID = strdup(LOCAL_KME_ID);
    status->target_KME_ID = strdup(REMOTE_KME_ID);
    status->slave_SAE_ID = strdup(slave_sae_id);
    status->key_size = DEFAULT_KEY_SIZE;
    status->stored_key_count = stored_key_count;
    status->max_key_count = MAX_KEYS;
    status->max_key_per_request = 128;
    status->max_key_size = DEFAULT_KEY_SIZE;
    status->min_key_size = DEFAULT_KEY_SIZE;
    status->max_SAE_ID_count = 0; // No multicast support in simulation
    status->status_extension = NULL;

    return QKD_STATUS_OK;
}

static uint32_t sim_get_key(const char *kme_hostname, const char *slave_sae_id,
                           qkd_key_request_t *request,
                           qkd_key_container_t *container) {
    QKD_DBG_INFO("Entering sim_get_key with hostname=%s, slave_id=%s",
                 kme_hostname ? kme_hostname : "NULL",
                 slave_sae_id ? slave_sae_id : "NULL");

    if (!kme_hostname || !slave_sae_id || !container) {
        QKD_DBG_ERR("Invalid parameters");
        return QKD_STATUS_BAD_REQUEST;
    }

    int num_keys = (request && request->number > 0) ? request->number : 1;
    size_t key_size = (request && request->size > 0) ? request->size : DEFAULT_KEY_SIZE;

    // Allocate container keys
    container->keys = calloc(num_keys, sizeof(qkd_key_t));
    if (!container->keys) {
        QKD_DBG_ERR("Memory allocation failed for container keys");
        return QKD_STATUS_SERVER_ERROR;
    }
    container->key_count = num_keys;

    // Generate keys
    int i;
    for (i = 0; i < num_keys; i++) {
        QKD_DBG_INFO("Generating key %d of %d", i+1, num_keys);

        // Generate key ID and store it
        snprintf(key_store[stored_key_count].key_id, 37, "KEY_%zu", stored_key_count);
        
        // Generate key material
        generate_simulated_key(key_store[stored_key_count].key);

        // Allocate and store key ID
        container->keys[i].key_ID = strdup(key_store[stored_key_count].key_id);
        if (!container->keys[i].key_ID) {
            QKD_DBG_ERR("Failed to allocate key ID");
            goto cleanup_error;
        }

        // Allocate and store key material
        container->keys[i].key = malloc(key_size);
        if (!container->keys[i].key) {
            QKD_DBG_ERR("Failed to allocate key material");
            free(container->keys[i].key_ID);
            goto cleanup_error;
        }

        memcpy(container->keys[i].key, key_store[stored_key_count].key, key_size);
        stored_key_count++;
        
        QKD_DBG_INFO("Successfully generated key %d", i+1);
    }

    QKD_DBG_INFO("Successfully generated all %d keys", num_keys);
    return QKD_STATUS_OK;

cleanup_error:
    // Clean up any successfully allocated keys
    for (int j = 0; j < i; j++) {
        free(container->keys[j].key_ID);
        free(container->keys[j].key);
    }
    free(container->keys);
    container->keys = NULL;
    container->key_count = 0;
    return QKD_STATUS_SERVER_ERROR;
}

static uint32_t sim_get_key_with_ids(const char *kme_hostname,
                                     const char *master_sae_id,
                                     qkd_key_ids_t *key_ids,
                                     qkd_key_container_t *container) {
    container->keys = calloc(key_ids->key_ID_count, sizeof(qkd_key_t));
    container->key_count = key_ids->key_ID_count;

    for (int i = 0; i < key_ids->key_ID_count; i++) {
        for (size_t j = 0; j < stored_key_count; j++) {
            if (strcmp(key_store[j].key_id, key_ids->key_IDs[i].key_ID) == 0) {
                container->keys[i].key_ID = strdup(key_store[j].key_id);
                container->keys[i].key = malloc(DEFAULT_KEY_SIZE);
                memcpy(container->keys[i].key, key_store[j].key,
                       DEFAULT_KEY_SIZE);
                break;
            }
        }
    }

    return QKD_STATUS_OK;
}

/* Register backend */
const struct qkd_014_backend simulated_backend = {
    .name = "simulated",
    .get_status = sim_get_status,
    .get_key = sim_get_key,
    .get_key_with_ids = sim_get_key_with_ids
    };

#endif /* QKD_USE_SIMULATED */