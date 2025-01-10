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

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <string.h>
#include "etsi014/api.h"
#include "etsi014/backends/simulated.h"
#include "debug.h"

#ifdef QKD_USE_SIMULATED

#define MAX_KEYS 16
#define KEY_SIZE 32

static struct {
    char *key_data;      // Base64 encoded
    char *key_id;
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

static uint32_t sim_get_status(const char *kme_hostname, 
                              const char *slave_sae_id,
                              qkd_status_t *status) {
    status->key_size = KEY_SIZE;
    status->stored_key_count = stored_keys;
    status->max_key_count = MAX_KEYS;
    status->max_key_per_request = 1;
    return QKD_STATUS_OK;
}

static uint32_t sim_get_key(const char *kme_hostname,
                           const char *slave_sae_id,
                           qkd_key_request_t *request,
                           qkd_key_container_t *container) {
    // Fixed key ID matching QKD_KSID_SIZE (16 bytes)
    static const unsigned char key_id[QKD_KSID_SIZE] = {
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x47, 0x58,
        0x59, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0
    };

    // Fixed test key from ETSI 004
    static const unsigned char test_key[KEY_SIZE] = {
        0x8f, 0x40, 0xc5, 0xad, 0xb6, 0x8f, 0x25, 0x62, 0x4a, 0xe5, 0xb2,
        0x14, 0xea, 0x76, 0x7a, 0x6e, 0xc9, 0x4d, 0x82, 0x9d, 0x3d, 0x7b,
        0x5e, 0x1a, 0xd1, 0xba, 0x6f, 0x3e, 0x21, 0x38, 0x28, 0x5f
    };

    container->key_count = 1;
    container->keys = calloc(1, sizeof(qkd_key_t));

    container->keys[0].key = base64_encode(test_key, KEY_SIZE);
    
    // Only return key ID if request is not NULL (initiator case)
    if (request != NULL) {
        char *hex_id = malloc(QKD_KSID_SIZE * 2 + 1); 
        for(int i = 0; i < QKD_KSID_SIZE; i++) {
            sprintf(hex_id + (i * 2), "%02x", key_id[i]);
        }
        container->keys[0].key_ID = hex_id;
    }

    return QKD_STATUS_OK;
}
static uint32_t sim_get_key_with_ids(const char *kme_hostname,
                                    const char *master_sae_id,
                                    qkd_key_ids_t *key_ids,
                                    qkd_key_container_t *container) {
    return sim_get_key(kme_hostname, master_sae_id, NULL, container);
}

const struct qkd_014_backend simulated_backend = {
    .name = "simulated",
    .get_status = sim_get_status,
    .get_key = sim_get_key,
    .get_key_with_ids = sim_get_key_with_ids
};

#endif /* QKD_USE_SIMULATED */