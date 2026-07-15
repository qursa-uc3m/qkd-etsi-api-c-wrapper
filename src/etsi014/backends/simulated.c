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

#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

#include "debug.h"
#include "etsi014/api.h"
#include "etsi014/backends/simulated.h"
#include "qkd_etsi_api.h"

#if defined(QKD_USE_SIMULATED) && QKD_USE_SIMULATED

#define MAX_KEYS 16
#define KEY_SIZE_BYTES 32
#define BASE64_KEY_SIZE (((KEY_SIZE_BYTES + 2) / 3) * 4 + 1)
#define UUID_STRING_SIZE 37

struct stored_key {
    char key_data[BASE64_KEY_SIZE];
    char key_id[UUID_STRING_SIZE];
    bool in_use;
};

static struct stored_key key_store[MAX_KEYS];
static int32_t stored_keys;

static char *base64_encode(const unsigned char *input, size_t length) {
    if (length > INT_MAX)
        return NULL;

    size_t encoded_size = 4U * ((length + 2U) / 3U);
    char *encoded = malloc(encoded_size + 1U);
    if (!encoded)
        return NULL;

    int result = EVP_EncodeBlock((unsigned char *)encoded, input, (int)length);
    if (result < 0 || (size_t)result != encoded_size) {
        free(encoded);
        return NULL;
    }
    encoded[encoded_size] = '\0';
    return encoded;
}

static char *generate_uuid_string(void) {
    uuid_t uuid;
    char *uuid_string = malloc(UUID_STRING_SIZE);

    if (!uuid_string)
        return NULL;
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, uuid_string);
    return uuid_string;
}

static int find_key(const char *key_id) {
    if (!key_id)
        return -1;

    for (int i = 0; i < MAX_KEYS; i++) {
        if (key_store[i].in_use && strcmp(key_store[i].key_id, key_id) == 0)
            return i;
    }
    return -1;
}

static int store_key(const qkd_key_t *key) {
    for (int i = 0; i < MAX_KEYS; i++) {
        if (!key_store[i].in_use) {
            memcpy(key_store[i].key_id, key->key_ID, UUID_STRING_SIZE);
            memcpy(key_store[i].key_data, key->key, BASE64_KEY_SIZE);
            key_store[i].in_use = true;
            stored_keys++;
            return i;
        }
    }
    return -1;
}

static bool create_key(qkd_key_t *key) {
    unsigned char material[KEY_SIZE_BYTES];

    if (RAND_bytes(material, sizeof(material)) != 1) {
        OPENSSL_cleanse(material, sizeof(material));
        return false;
    }

    key->key = base64_encode(material, sizeof(material));
    OPENSSL_cleanse(material, sizeof(material));
    key->key_ID = generate_uuid_string();
    if (!key->key || !key->key_ID) {
        free(key->key);
        free(key->key_ID);
        memset(key, 0, sizeof(*key));
        return false;
    }
    return true;
}

static uint32_t sim_get_status(const char *kme_hostname,
                               const char *slave_sae_id, qkd_status_t *status) {
    if (!kme_hostname || !slave_sae_id || !status)
        return QKD_STATUS_BAD_REQUEST;

    memset(status, 0, sizeof(*status));
    status->source_KME_ID = strdup(kme_hostname);
    status->target_KME_ID = strdup(kme_hostname);
    status->master_SAE_ID = strdup("SIMULATED_MASTER_SAE");
    status->slave_SAE_ID = strdup(slave_sae_id);
    if (!status->source_KME_ID || !status->target_KME_ID ||
        !status->master_SAE_ID || !status->slave_SAE_ID) {
        free(status->source_KME_ID);
        free(status->target_KME_ID);
        free(status->master_SAE_ID);
        free(status->slave_SAE_ID);
        memset(status, 0, sizeof(*status));
        return QKD_STATUS_SERVER_ERROR;
    }

    status->key_size = QKD_KEY_SIZE_BITS;
    status->stored_key_count = MAX_KEYS - stored_keys;
    status->max_key_count = MAX_KEYS;
    status->max_key_per_request = MAX_KEYS;
    status->max_key_size = QKD_KEY_SIZE_BITS;
    status->min_key_size = QKD_KEY_SIZE_BITS;
    status->max_SAE_ID_count = 0;
    return QKD_STATUS_OK;
}

static uint32_t sim_get_key(const char *kme_hostname, const char *slave_sae_id,
                            qkd_key_request_t *request,
                            qkd_key_container_t *container) {
    if (!kme_hostname || !slave_sae_id || !container)
        return QKD_STATUS_BAD_REQUEST;
    if (request) {
        if (request->number < 0 || request->size < 0 ||
            request->additional_SAE_count < 0 ||
            request->additional_SAE_count > 0 || request->extension_mandatory)
            return QKD_STATUS_BAD_REQUEST;
    }

    int32_t number = request && request->number > 0 ? request->number : 1;
    int32_t size =
        request && request->size > 0 ? request->size : QKD_KEY_SIZE_BITS;
    if (number > MAX_KEYS || size != QKD_KEY_SIZE_BITS)
        return QKD_STATUS_BAD_REQUEST;
    if (number > MAX_KEYS - stored_keys)
        return QKD_STATUS_SERVER_ERROR;

    memset(container, 0, sizeof(*container));
    container->keys = calloc((size_t)number, sizeof(*container->keys));
    if (!container->keys)
        return QKD_STATUS_SERVER_ERROR;
    container->key_count = number;

    int stored_indices[MAX_KEYS];
    for (int32_t i = 0; i < number; i++) {
        if (!create_key(&container->keys[i])) {
            for (int32_t j = 0; j < i; j++) {
                OPENSSL_cleanse(&key_store[stored_indices[j]],
                                sizeof(key_store[stored_indices[j]]));
                stored_keys--;
            }
            qkd_key_container_free(container);
            return QKD_STATUS_SERVER_ERROR;
        }
        stored_indices[i] = store_key(&container->keys[i]);
        if (stored_indices[i] < 0) {
            for (int32_t j = 0; j < i; j++) {
                OPENSSL_cleanse(&key_store[stored_indices[j]],
                                sizeof(key_store[stored_indices[j]]));
                stored_keys--;
            }
            qkd_key_container_free(container);
            return QKD_STATUS_SERVER_ERROR;
        }
    }
    return QKD_STATUS_OK;
}

static uint32_t sim_get_key_with_ids(const char *kme_hostname,
                                     const char *master_sae_id,
                                     qkd_key_ids_t *key_ids,
                                     qkd_key_container_t *container) {
    if (!kme_hostname || !master_sae_id || !key_ids || !container ||
        key_ids->key_ID_count <= 0 || key_ids->key_ID_count > MAX_KEYS ||
        !key_ids->key_IDs || key_ids->key_IDs_extension)
        return QKD_STATUS_BAD_REQUEST;

    int matched_indices[MAX_KEYS];
    for (int32_t i = 0; i < key_ids->key_ID_count; i++) {
        if (key_ids->key_IDs[i].key_ID_extension)
            return QKD_STATUS_BAD_REQUEST;
        matched_indices[i] = find_key(key_ids->key_IDs[i].key_ID);
        if (matched_indices[i] < 0)
            return QKD_STATUS_BAD_REQUEST;
        for (int32_t j = 0; j < i; j++) {
            if (matched_indices[j] == matched_indices[i])
                return QKD_STATUS_BAD_REQUEST;
        }
    }

    memset(container, 0, sizeof(*container));
    container->keys =
        calloc((size_t)key_ids->key_ID_count, sizeof(*container->keys));
    if (!container->keys)
        return QKD_STATUS_SERVER_ERROR;
    container->key_count = key_ids->key_ID_count;

    for (int32_t i = 0; i < container->key_count; i++) {
        struct stored_key *stored = &key_store[matched_indices[i]];
        container->keys[i].key_ID = strdup(stored->key_id);
        container->keys[i].key = strdup(stored->key_data);
        if (!container->keys[i].key_ID || !container->keys[i].key) {
            qkd_key_container_free(container);
            return QKD_STATUS_SERVER_ERROR;
        }
    }

    for (int32_t i = 0; i < container->key_count; i++) {
        OPENSSL_cleanse(&key_store[matched_indices[i]],
                        sizeof(key_store[matched_indices[i]]));
        stored_keys--;
    }
    return QKD_STATUS_OK;
}

const struct qkd_014_backend simulated_backend = {.name = "simulated",
                                                  .get_status = sim_get_status,
                                                  .get_key = sim_get_key,
                                                  .get_key_with_ids =
                                                      sim_get_key_with_ids};

#endif /* QKD_USE_SIMULATED */
