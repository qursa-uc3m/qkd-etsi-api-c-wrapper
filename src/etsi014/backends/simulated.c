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
    unsigned char key_bytes[KEY_SIZE];
    if (!RAND_bytes(key_bytes, KEY_SIZE)) {
        return QKD_STATUS_SERVER_ERROR;
    }

    container->key_count = 1;
    container->keys = calloc(1, sizeof(qkd_key_t));
    
    container->keys[0].key = base64_encode(key_bytes, KEY_SIZE);
    container->keys[0].key_ID = strdup("sim-key-001");
    
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