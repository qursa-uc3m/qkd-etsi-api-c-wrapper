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

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <openssl/bio.h>
 #include <openssl/buffer.h>
 #include <openssl/evp.h>
 #include <uuid/uuid.h>
 #include "etsi014/api.h"
 #include "etsi014/backends/simulated.h"
 #include "debug.h"
 
 #ifdef QKD_USE_SIMULATED
 
 #define MAX_KEYS 16
 #define KEY_SIZE 32
 #define API_DELAY_MS 100
 
 static struct {
     char *key_data;      // Base64 encoded
     char *key_id;        // UUID format
 } key_store[MAX_KEYS];
 
 static size_t stored_keys = 0;
 
 static char* base64_encode(const unsigned char* input, int length) {
     BIO *bmem, *b64;
     BUF_MEM *bptr;
     
     b64 = BIO_new(BIO_f_base64());
     bmem = BIO_new(BIO_s_mem());
     b64 = BIO_push(b64, bmem);
     
     BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
     BIO_write(b64, input, length);
     BIO_flush(b64);
     
     BIO_get_mem_ptr(b64, &bptr);
     
     char *buff = malloc(bptr->length + 1);
     if (!buff) {
         BIO_free_all(b64);
         return NULL;
     }
     
     memcpy(buff, bptr->data, bptr->length);
     buff[bptr->length] = 0;
     
     BIO_free_all(b64);
     return buff;
 }
 
 // Generate a valid UUID string
 static char* generate_uuid_string() {
     uuid_t uuid;
     char *uuid_str = malloc(37); // 36 chars + null terminator
     
     if (!uuid_str) {
         return NULL;
     }
     
     uuid_generate(uuid);
     uuid_unparse(uuid, uuid_str);
     
     return uuid_str;
 }
 
 static uint32_t sim_get_status(const char *kme_hostname,
                                const char *slave_sae_id,
                                qkd_status_t *status) {
     usleep(API_DELAY_MS * 1000);
     if (!kme_hostname || !slave_sae_id) {
         QKD_DBG_ERR("sim_get_status: NULL hostname or slave SAE ID");
         return QKD_STATUS_BAD_REQUEST;
     }
     status->key_size = KEY_SIZE;
     status->stored_key_count = stored_keys;
     status->max_key_count = MAX_KEYS;
     status->max_key_per_request = 1;
     
     // Optional: Set source KME ID if needed
     status->source_KME_ID = strdup(kme_hostname);
     
     return QKD_STATUS_OK;
 }
 
 static uint32_t sim_get_key(const char *kme_hostname,
                            const char *slave_sae_id,
                            qkd_key_request_t *request,
                            qkd_key_container_t *container) {
     usleep(API_DELAY_MS * 1000);
     
     // Fixed test key from ETSI 004
     static const unsigned char test_key[KEY_SIZE] = {
         0x8f, 0x40, 0xc5, 0xad, 0xb6, 0x8f, 0x25, 0x62, 0x4a, 0xe5, 0xb2,
         0x14, 0xea, 0x76, 0x7a, 0x6e, 0xc9, 0x4d, 0x82, 0x9d, 0x3d, 0x7b,
         0x5e, 0x1a, 0xd1, 0xba, 0x6f, 0x3e, 0x21, 0x38, 0x28, 0x5f
     };
     
     container->key_count = 1;
     container->keys = calloc(1, sizeof(qkd_key_t));
     if (!container->keys) {
         return QKD_STATUS_BAD_REQUEST;
     }
     
     container->keys[0].key = base64_encode(test_key, KEY_SIZE);
     if (!container->keys[0].key) {
         free(container->keys);
         container->keys = NULL;
         return QKD_STATUS_BAD_REQUEST;
     }
     
     // Only return key ID if request is not NULL (initiator case)
     container->keys[0].key_ID = generate_uuid_string();
     if (!container->keys[0].key_ID) {
         free(container->keys[0].key);
         free(container->keys);
         container->keys = NULL;
         return QKD_STATUS_BAD_REQUEST;
     }

     // For demonstration, store this key in our key_store
     if (stored_keys < MAX_KEYS) {
         key_store[stored_keys].key_data = strdup(container->keys[0].key);
         key_store[stored_keys].key_id = strdup(container->keys[0].key_ID);
         stored_keys++;
     }

     
     return QKD_STATUS_OK;
 }
 
 static uint32_t sim_get_key_with_ids(const char *kme_hostname,
                                      const char *master_sae_id,
                                      qkd_key_ids_t *key_ids,
                                      qkd_key_container_t *container) {
     usleep(API_DELAY_MS * 1000);
     
     if (!key_ids || key_ids->key_ID_count == 0 || !key_ids->key_IDs) {
         return QKD_STATUS_BAD_REQUEST;
     }
     
     // We could search through the key_store for the key ID, but for simplicity
     // in this simulation, we'll just return the same key
     
     // Fixed test key from ETSI 004
     static const unsigned char test_key[KEY_SIZE] = {
         0x8f, 0x40, 0xc5, 0xad, 0xb6, 0x8f, 0x25, 0x62, 0x4a, 0xe5, 0xb2,
         0x14, 0xea, 0x76, 0x7a, 0x6e, 0xc9, 0x4d, 0x82, 0x9d, 0x3d, 0x7b,
         0x5e, 0x1a, 0xd1, 0xba, 0x6f, 0x3e, 0x21, 0x38, 0x28, 0x5f
     };
     
     container->key_count = 1;
     container->keys = calloc(1, sizeof(qkd_key_t));
     if (!container->keys) {
         return QKD_STATUS_BAD_REQUEST;
     }
     
     container->keys[0].key = base64_encode(test_key, KEY_SIZE);
     if (!container->keys[0].key) {
         free(container->keys);
         container->keys = NULL;
         return QKD_STATUS_BAD_REQUEST;
     }
     
     // For completeness, we could include the requested key ID in the response
     // container->keys[0].key_ID = strdup(key_ids->key_IDs[0].key_ID);
     
     return QKD_STATUS_OK;
 }
 
 // Cleanup function for releasing memory - will be called externally
 static void sim_cleanup_resources() {
     for (size_t i = 0; i < stored_keys; i++) {
         free(key_store[i].key_data);
         free(key_store[i].key_id);
     }
     stored_keys = 0;
 }
 
 const struct qkd_014_backend simulated_backend = {
     .name = "simulated",
     .get_status = sim_get_status,
     .get_key = sim_get_key,
     .get_key_with_ids = sim_get_key_with_ids
 };
 
 #endif /* QKD_USE_SIMULATED */