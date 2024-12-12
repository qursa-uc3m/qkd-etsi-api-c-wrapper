/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 * - Pedro Otero-García (@pedrotega) - UVigo
 */

/*
 * src/cerberis_xgr.c
 */

#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <jansson.h>

#include "debug.h"
#include "etsi014/api.h"
#include "etsi014/cerberis_xgr.h"

//#ifdef QKD_USE_CERBERIS_XGR

#define MAX_KEYS 1024
#define DEFAULT_KEY_SIZE 256

// KME IP
const char *KME_IP = "https://castor.det.uvigo.es:444";

// Certificates to do HTTPs requests to the KMS.
const char *C1_PUB_KEY = "/home/pedro/qursa/qkd/qkd-etsi-api/certs/ETSIA.pem";
const char *C1_PRIV_KEY = "/home/pedro/qursa/qkd/qkd-etsi-api/certs/ETSIA-key.pem";
const char *C1_ROOT_CA = "/home/pedro/qursa/qkd/qkd-etsi-api/certs/ChrisCA.pem";

// SAE - Security Application Entity
const char *C2_ENC = "CONSB";

/* Simplified key storage */
static struct {
    char key_id[37];
    unsigned char key[DEFAULT_KEY_SIZE];
} key_store[MAX_KEYS];

static size_t stored_key_count = 0;

// Struct to store responses from cURL
struct MemoryStruct {
    char *memory;
    size_t size;
};

//BORRAAAAR!!!!!!
/* Helper functions */
static void generate_simulated_key(unsigned char *key) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, &stored_key_count, sizeof(size_t));
    EVP_DigestFinal_ex(ctx, key, NULL);
    EVP_MD_CTX_free(ctx);
}

// Callback to write HTTPs responses to memory
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) {
        printf("No hay suficiente memoria\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// Function to commit HTTPs requests
char *request_https(const char *url, const char *cert, const char *key, 
                        const char *ca_cert, const char *post_data, long *http_code) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1); 
    chunk.size = 0;    

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_SSLCERT, cert);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, key);
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_cert);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        
        // No comprueba los nombres en los certificados pero se sigue comprobando que los
        // certificados esten firmados por una CA de confianza.
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        if (post_data != NULL) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        }

        res = curl_easy_perform(curl);

        if(res != CURLE_OK) {
            fprintf(stderr, "Error en curl_easy_perform(): %s\n", curl_easy_strerror(res));
            free(chunk.memory);
            chunk.memory = NULL;
        } else {
            // Obtener el código de estado HTTP
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);
        }

        curl_easy_cleanup(curl);
    }

    return chunk.memory;
}

// Function to parse HTTP ENC_KEYS/DEC_KEYS response to recover keys and key_ids
// void parse_response_to_qkd_keys(const char *json_str, char *key_buffer, 
//                             size_t key_buffer_len, char *key_id_buffer, size_t key_id_buffer_len) {
//     json_t *root;
//     json_error_t error;

//     root = json_loads(json_str, 0, &error);
//     if (!root) {
//         fprintf(stderr, "Error parsing JSON: %s\n", error.text);
//         return;
//     }

//     json_t *keys = json_object_get(root, "keys");
//     if (json_is_array(keys)) {
//         json_t *key_data = json_array_get(keys, 0);
//         json_t *key = json_object_get(key_data, "key");
//         json_t *key_id = json_object_get(key_data, "key_ID");

//         snprintf(key_buffer, key_buffer_len, "%s", json_string_value(key));
//         snprintf(key_id_buffer, key_id_buffer_len, "%s", json_string_value(key_id));
//     }

//     json_decref(root);
// }

/* Implementación para leer todas las claves del JSON */
int parse_response_to_qkd_keys(const char *json_str, qkd_key_container_t *key_container) {
    json_t *root;
    json_error_t error;

    // Cargar el JSON
    root = json_loads(json_str, 0, &error);
    if (!root) {
        fprintf(stderr, "Error parsing JSON: %s\n", error.text);
        return -1;
    }

    // Obtener el array de claves "keys"
    json_t *keys = json_object_get(root, "keys");
    if (!json_is_array(keys)) {
        fprintf(stderr, "Error: 'keys' is not a valid JSON array\n");
        json_decref(root);
        return -1;
    }

    // Obtener la cantidad de claves
    size_t key_count = json_array_size(keys);
    key_container->key_count = key_count;
    key_container->keys = malloc(key_count * sizeof(qkd_key_t));

    if (!key_container->keys) {
        fprintf(stderr, "Error allocating memory for keys\n");
        json_decref(root);
        return -1;
    }

    // Iterar sobre el array y extraer cada clave
    for (size_t i = 0; i < key_count; i++) {
        json_t *key_data = json_array_get(keys, i);
        if (!json_is_object(key_data)) {
            fprintf(stderr, "Error: Invalid key object at index %zu\n", i);
            continue;
        }

        // Obtener key_ID y key
        json_t *key_id = json_object_get(key_data, "key_ID");
        json_t *key = json_object_get(key_data, "key");

        if (!json_is_string(key_id) || !json_is_string(key)) {
            fprintf(stderr, "Error: Invalid key or key_ID at index %zu\n", i);
            continue;
        }

        // Asignar valores al struct qkd_key
        key_container->keys[i].key_ID = strdup(json_string_value(key_id));
        key_container->keys[i].key = strdup(json_string_value(key));
        key_container->keys[i].key_ID_extension = NULL; // Opcional, inicializado a NULL
        key_container->keys[i].key_extension = NULL;    // Opcional, inicializado a NULL
    }

    // Liberar el objeto JSON
    json_decref(root);
    return 0;
}

// Function to parse HTTP STATUS response
int parse_response_to_qkd_status(const char *response, qkd_status_t *status) {
    json_t *root;
    json_error_t error;

    // Load JSON from string
    root = json_loads(response, 0, &error);
    if (!root) {
        fprintf(stderr, "Error parsing JSON: %s\n", error.text);
        return -1;
    }

    // Assign JSON numerical values to struct
    status->key_size = json_integer_value(json_object_get(root, "key_size"));
    status->stored_key_count = json_integer_value(json_object_get(root, "stored_key_count"));
    status->max_key_count = json_integer_value(json_object_get(root, "max_key_count"));
    status->max_key_per_request = json_integer_value(json_object_get(root, "max_key_per_request"));
    status->max_key_size = json_integer_value(json_object_get(root, "max_key_size"));
    status->min_key_size = json_integer_value(json_object_get(root, "min_key_size"));
    status->max_SAE_ID_count = json_integer_value(json_object_get(root, "max_SAE_ID_count"));

    // Assign strings
    const char *source_KME_ID = json_string_value(json_object_get(root, "source_KME_ID"));
    const char *target_KME_ID = json_string_value(json_object_get(root, "target_KME_ID"));
    const char *master_SAE_ID = json_string_value(json_object_get(root, "master_SAE_ID"));
    const char *slave_SAE_ID = json_string_value(json_object_get(root, "slave_SAE_ID"));

    // Copy strings to struct
    status->source_KME_ID = source_KME_ID ? strdup(source_KME_ID) : NULL;
    status->target_KME_ID = target_KME_ID ? strdup(target_KME_ID) : NULL;
    status->master_SAE_ID = master_SAE_ID ? strdup(master_SAE_ID) : NULL;
    status->slave_SAE_ID = slave_SAE_ID ? strdup(slave_SAE_ID) : NULL;

    json_decref(root);
    return 0;
}

// Liberar memoria asignada dinámicamente en el struct
void free_qkd_status(qkd_status_t *status) {
    if (status->source_KME_ID) free(status->source_KME_ID);
    if (status->target_KME_ID) free(status->target_KME_ID);
    if (status->master_SAE_ID) free(status->master_SAE_ID);
    if (status->slave_SAE_ID) free(status->slave_SAE_ID);
}

/* Backend implementation */
static uint32_t get_status(const char *kme_hostname,
                               const char *slave_sae_id, qkd_status_t *status) {
    char url[256];
    char *response;
    long http_code;

    // Request to KME node
    snprintf(url, sizeof(url), "%s/api/v1/keys/%s/status", kme_hostname, slave_sae_id);
    response = request_https(url, C1_PUB_KEY, C1_PRIV_KEY, C1_ROOT_CA, NULL, &http_code);

    QKD_DBG_INFO("[GET_STATUS] - HTTP RSP Code: %ld", http_code);
    if (response && http_code < 400) {
        //puts(response); // Show JSON for debugging. 

        if (parse_response_to_qkd_status(response, status) == 0) {
            QKD_DBG_INFO("[GET_STATUS] - Status JSON parsed.");
        } else {
            QKD_DBG_ERR("[GET_STATUS] - Error parsing Status JSON.");
        }

        free(response); // Free memory response JSON
        return QKD_STATUS_OK;
    }

    // Free response memory in case of error
    if (response) {
        free(response);
    }

    // Manejo de errores según el código HTTP
    if (http_code < 500) {
        return QKD_STATUS_BAD_REQUEST;
    } else {
        return QKD_STATUS_SERVER_ERROR;
    }
}

static uint32_t get_key(const char *kme_hostname, const char *slave_sae_id,
                            qkd_key_request_t *request,
                            qkd_key_container_t *container) {
    int num_keys = request ? request->number : 1;
    int size_keys = request ? request->size : DEFAULT_KEY_SIZE;

    container->keys = calloc(num_keys, sizeof(qkd_key_t));
    container->key_count = num_keys;

    char url[256];
    char *response;
    long http_code;

    // Buffers para almacenar la clave y el ID de la clave obtenidos de la segunda petición
    char key[256] = {0};
    char key_id[256] = {0};

    // Solicitud de clave al nodo maestro (Alice)
    snprintf(url, sizeof(url), "%s/api/v1/keys/%s/enc_keys?number=%d&size=%d", 
                                    kme_hostname, slave_sae_id, num_keys, size_keys);
    response = request_https(url, C1_PUB_KEY, C1_PRIV_KEY, C1_ROOT_CA, NULL, &http_code);
    
    QKD_DBG_INFO("[GET_KEY] HTTP RSP Code: %ld", http_code);
    if (response && http_code < 400) {
        //puts(response); // Show JSON for debugging. 
        
        if (parse_response_to_qkd_keys(response, container) == 0) {
            QKD_DBG_INFO("[GET_KEY] - Status JSON parsed.");
        } else {
            QKD_DBG_ERR("[GET_KEY] - Error parsing Status JSON.");
        }

        free(response); // Free memory response JSON
        return QKD_STATUS_OK;
    }

    // Free response memory in case of error
    if (response) {
        free(response);
    }

    // Manejo de errores según el código HTTP
    if (http_code < 500) {
        return QKD_STATUS_BAD_REQUEST;
    } else {
        return QKD_STATUS_SERVER_ERROR;
    }
}

static uint32_t get_key_with_ids(const char *kme_hostname,
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
const struct qkd_014_backend cerberis_xgr_backend = {.name = "cerberis_xgr",
                                                  .get_status = get_status,
                                                  .get_key = get_key,
                                                  .get_key_with_ids =
                                                      get_key_with_ids};

//#endif /* QKD_USE_CERBERIS_XGR */