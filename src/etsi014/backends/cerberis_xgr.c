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
#include "etsi014/backends/cerberis_xgr.h"

#ifdef QKD_USE_CERBERIS_XGR

#define MAX_KEYS 1024
#define DEFAULT_KEY_SIZE 256

static cerberis_cert_config_t cert_config;
static int cert_config_initialized = 0;

// Struct to store responses from cURL
struct MemoryStruct {
    char *memory;
    size_t size;
};

/* Initialize certificate configuration from environment variables */
static void init_cert_config(void) {
    if (cert_config_initialized) {
        return;
    }

    const char *cert_path = getenv("QKD_CERT_PATH");
    const char *key_path = getenv("QKD_KEY_PATH");
    const char *ca_cert_path = getenv("QKD_CA_CERT_PATH");

    if (!cert_path || !key_path || !ca_cert_path) {
        QKD_DBG_ERR("Required certificate environment variables not set");
        QKD_DBG_ERR("Please set: QKD_CERT_PATH, QKD_KEY_PATH, QKD_CA_CERT_PATH");
        exit(1);
    }

    cert_config.cert_path = cert_path;
    cert_config.key_path = key_path;
    cert_config.ca_cert_path = ca_cert_path;
    
    cert_config_initialized = 1;
    
    QKD_DBG_INFO("Certificate configuration initialized:");
    QKD_DBG_INFO("  Cert path: %s", cert_config.cert_path);
    QKD_DBG_INFO("  Key path: %s", cert_config.key_path);
    QKD_DBG_INFO("  CA cert path: %s", cert_config.ca_cert_path);
}

/**************************************************************************************/
/********************************* - HELPER FUNCTIONS - *******************************/
/**************************************************************************************/
/* Callback to write HTTPs responses to memory */
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

/* Function to parse HTTP STATUS JSON responses */
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

/* Function to parse HTTP GET_KEY & GET_KEY_WITH_IDS JSON responses */
int parse_response_to_qkd_keys(const char *response, qkd_key_container_t *key_container) {
    json_t *root;
    json_error_t error;

    // Load JSON from string
    root = json_loads(response, 0, &error);
    if (!root) {
        fprintf(stderr, "Error parsing JSON: %s\n", error.text);
        return -1;
    }

    // Obtain array with the keys
    json_t *keys = json_object_get(root, "keys");
    if (!json_is_array(keys)) {
        fprintf(stderr, "Error: 'keys' is not a valid JSON array\n");
        json_decref(root);
        return -1;
    }

    // Obtain the count of keys
    size_t key_count = json_array_size(keys);
    key_container->key_count = key_count;
    key_container->keys = malloc(key_count * sizeof(qkd_key_t));

    if (!key_container->keys) {
        fprintf(stderr, "Error allocating memory for keys\n");
        json_decref(root);
        return -1;
    }

    // Extract each key from the array
    for (size_t i = 0; i < key_count; i++) {
        json_t *key_data = json_array_get(keys, i);
        if (!json_is_object(key_data)) {
            fprintf(stderr, "Error: Invalid key object at index %zu\n", i);
            continue;
        }

        // Obtain key_ID and key
        json_t *key_id = json_object_get(key_data, "key_ID");
        json_t *key = json_object_get(key_data, "key");

        if (!json_is_string(key_id) || !json_is_string(key)) {
            fprintf(stderr, "Error: Invalid key or key_ID at index %zu\n", i);
            continue;
        }

        // Assing values to struct qkd_key
        key_container->keys[i].key_ID = strdup(json_string_value(key_id));
        key_container->keys[i].key = strdup(json_string_value(key));
        key_container->keys[i].key_ID_extension = NULL; // Opcional, inicializado a NULL
        key_container->keys[i].key_extension = NULL;    // Opcional, inicializado a NULL
    }

    json_decref(root);
    return 0;
}

/* Handle to commit HTTPs requests */
static char *handle_request_https(const char *url, const char *post_data, long *http_code) {
    if (!cert_config_initialized) {
        init_cert_config();
    }
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1); 
    chunk.size = 0;    

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_SSLCERT, cert_config.cert_path);    // Fixed
        curl_easy_setopt(curl, CURLOPT_SSLKEY, cert_config.key_path);      // Fixed
        curl_easy_setopt(curl, CURLOPT_CAINFO, cert_config.ca_cert_path);  // Fixed
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

/* Handle to manage HTTP responses with keys*/
static uint32_t handle_http_response(const char *response, long http_code, 
                                     qkd_key_container_t *container) {
    if (response && http_code < 400) {
        if (parse_response_to_qkd_keys(response, container) == 0) {
            QKD_DBG_INFO("[HTTP_RESPONSE_HANDLER] - JSON parsed successfully.");
            free((void *)response); 
            return QKD_STATUS_OK;
        } else {
            QKD_DBG_ERR("[HTTP_RESPONSE_HANDLER] - Error parsing JSON.");
            free((void *)response);
            return QKD_STATUS_BAD_REQUEST;
        }
    } else {
        QKD_DBG_ERR("[HTTP_RESPONSE_HANDLER] - HTTP request failed.");
        if (response) {
            free((void *)response);
        }
        return (http_code < 500) ? QKD_STATUS_BAD_REQUEST : QKD_STATUS_SERVER_ERROR;
    }
}

/* Function to create a JSON with multiple keys for POST request */
static char *build_post_data(qkd_key_ids_t *key_ids) {
    size_t buffer_size = 1024;
    char *post_data = calloc(buffer_size, sizeof(char));
    strcat(post_data, "{\"key_IDs\":[");

    for (int i = 0; i < key_ids->key_ID_count; ++i) {
        char key_id_entry[128];
        snprintf(key_id_entry, sizeof(key_id_entry), "{\"key_ID\":\"%s\"}", key_ids->key_IDs[i].key_ID);
        strcat(post_data, key_id_entry);
        if (i < key_ids->key_ID_count - 1) {
            strcat(post_data, ",");
        }
    }

    strcat(post_data, "]}");
    return post_data;
}

/**************************************************************************************/
/****************************** - BACKEND IMPLEMENTATION - ****************************/
/**************************************************************************************/
static uint32_t get_status(const char *kme_hostname, 
                              const char *slave_sae_id,
                              qkd_status_t *status) {
    char url[256];
    char *response;
    long http_code;

    // Request to KME node
    snprintf(url, sizeof(url), "%s/api/v1/keys/%s/status", kme_hostname, slave_sae_id);
    response = handle_request_https(url, NULL, &http_code);

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

static uint32_t get_key(const char *kme_hostname,
                           const char *slave_sae_id,
                           qkd_key_request_t *request,
                           qkd_key_container_t *container) {
    int num_keys = request ? request->number : 1;
    int size_keys = request ? request->size : DEFAULT_KEY_SIZE;

    container->keys = calloc(num_keys, sizeof(qkd_key_t));
    container->key_count = num_keys;

    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/keys/%s/enc_keys?number=%d&size=%d",
             kme_hostname, slave_sae_id, num_keys, size_keys);

    char *response;
    long http_code;
    response = handle_request_https(url, NULL, &http_code);

    return handle_http_response(response, http_code, container);
}

static uint32_t get_key_with_ids(const char *kme_hostname,
                                    const char *master_sae_id,
                                    qkd_key_ids_t *key_ids,
                                    qkd_key_container_t *container) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/keys/%s/dec_keys", kme_hostname, master_sae_id);

    char *post_data = build_post_data(key_ids);

    char *response;
    long http_code;
    response = handle_request_https(url, post_data, &http_code);

    free(post_data);
    return handle_http_response(response, http_code, container);
}


/* Register backend */
const struct qkd_014_backend cerberis_xgr_backend = {.name = "cerberis_xgr",
                                                  .get_status = get_status,
                                                  .get_key = get_key,
                                                  .get_key_with_ids = get_key_with_ids};

#endif /* QKD_USE_CERBERIS_XGR */