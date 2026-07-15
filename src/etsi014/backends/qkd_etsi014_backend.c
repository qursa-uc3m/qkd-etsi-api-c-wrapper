/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 * - Pedro Otero-García (@pedrotega) - UVigo
 * - Daniel Sobral Blanco (@dasobral) - UC3M
 */

#include <ctype.h>
#include <curl/curl.h>
#include <inttypes.h>
#include <jansson.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "etsi014/api.h"
#include "etsi014/backends/qkd_etsi014_backend.h"

#ifdef QKD_USE_ETSI014_BACKEND

#define MAX_KEYS 1024
#define DEFAULT_KEY_SIZE 256
#define CONNECT_TIMEOUT_SECONDS 10L
#define REQUEST_TIMEOUT_SECONDS 30L
#define MAX_RESPONSE_SIZE (16U * 1024U * 1024U)

struct memory_buffer {
    char *data;
    size_t size;
};

int init_cert_config(int role, etsi014_cert_config_t *config) {
    if (!config || (role != 0 && role != 1))
        return QKD_STATUS_BAD_REQUEST;

    const char *cert_path = role == 1 ? getenv("QKD_MASTER_CERT_PATH")
                                      : getenv("QKD_SLAVE_CERT_PATH");
    const char *key_path = role == 1 ? getenv("QKD_MASTER_KEY_PATH")
                                     : getenv("QKD_SLAVE_KEY_PATH");
    const char *ca_cert_path = role == 1 ? getenv("QKD_MASTER_CA_CERT_PATH")
                                         : getenv("QKD_SLAVE_CA_CERT_PATH");

    if (!cert_path || !key_path || !ca_cert_path) {
        QKD_DBG_ERR("Required %s certificate environment variables not set",
                    role == 1 ? "QKD_MASTER" : "QKD_SLAVE");
        return QKD_STATUS_BAD_REQUEST;
    }

    config->cert_path = cert_path;
    config->key_path = key_path;
    config->ca_cert_path = ca_cert_path;
    return QKD_STATUS_OK;
}

static size_t write_memory_callback(void *contents, size_t size, size_t nmemb,
                                    void *user_data) {
    struct memory_buffer *buffer = user_data;

    if (nmemb != 0 && size > SIZE_MAX / nmemb)
        return 0;
    size_t received = size * nmemb;
    if (received > SIZE_MAX - buffer->size - 1U)
        return 0;
    if (received > MAX_RESPONSE_SIZE - buffer->size)
        return 0;

    char *new_data = realloc(buffer->data, buffer->size + received + 1U);
    if (!new_data)
        return 0;

    buffer->data = new_data;
    memcpy(buffer->data + buffer->size, contents, received);
    buffer->size += received;
    buffer->data[buffer->size] = '\0';
    return received;
}

static bool get_json_int32(json_t *root, const char *name, int32_t *value) {
    json_t *field = json_object_get(root, name);
    if (!json_is_integer(field))
        return false;

    json_int_t integer = json_integer_value(field);
    if (integer < INT32_MIN || integer > INT32_MAX)
        return false;
    *value = (int32_t)integer;
    return true;
}

static char *duplicate_json_string(json_t *root, const char *name) {
    json_t *field = json_object_get(root, name);
    return json_is_string(field) ? strdup(json_string_value(field)) : NULL;
}

static bool is_uuid_string(const char *value) {
    if (!value || strlen(value) != 36)
        return false;

    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-')
                return false;
        } else if (!isxdigit((unsigned char)value[i])) {
            return false;
        }
    }
    return true;
}

static bool is_base64_string(const char *value) {
    if (!value)
        return false;

    size_t length = strlen(value);
    if (length == 0 || length % 4U != 0)
        return false;

    size_t padding = 0;
    if (value[length - 1U] == '=')
        padding++;
    if (length > 1U && value[length - 2U] == '=')
        padding++;

    for (size_t i = 0; i < length - padding; i++) {
        unsigned char character = (unsigned char)value[i];
        bool alphanumeric = (character >= 'A' && character <= 'Z') ||
                            (character >= 'a' && character <= 'z') ||
                            (character >= '0' && character <= '9');
        if (!alphanumeric && character != '+' && character != '/')
            return false;
    }
    for (size_t i = length - padding; i < length; i++) {
        if (value[i] != '=')
            return false;
    }
    return true;
}

int parse_response_to_qkd_status(const char *response, qkd_status_t *status) {
    if (!response || !status)
        return -1;

    json_error_t error;
    json_t *root = json_loads(response, JSON_REJECT_DUPLICATES, &error);
    if (!json_is_object(root)) {
        QKD_DBG_ERR("Error parsing status JSON: %s", error.text);
        json_decref(root);
        return -1;
    }

    qkd_status_t parsed = {0};
    bool valid =
        get_json_int32(root, "key_size", &parsed.key_size) &&
        get_json_int32(root, "stored_key_count", &parsed.stored_key_count) &&
        get_json_int32(root, "max_key_count", &parsed.max_key_count) &&
        get_json_int32(root, "max_key_per_request",
                       &parsed.max_key_per_request) &&
        get_json_int32(root, "max_key_size", &parsed.max_key_size) &&
        get_json_int32(root, "min_key_size", &parsed.min_key_size) &&
        get_json_int32(root, "max_SAE_ID_count", &parsed.max_SAE_ID_count);

    parsed.source_KME_ID = duplicate_json_string(root, "source_KME_ID");
    parsed.target_KME_ID = duplicate_json_string(root, "target_KME_ID");
    parsed.master_SAE_ID = duplicate_json_string(root, "master_SAE_ID");
    parsed.slave_SAE_ID = duplicate_json_string(root, "slave_SAE_ID");
    valid = valid && parsed.source_KME_ID && parsed.target_KME_ID &&
            parsed.master_SAE_ID && parsed.slave_SAE_ID;
    valid = valid && parsed.key_size > 0 && parsed.stored_key_count >= 0 &&
            parsed.max_key_count >= parsed.stored_key_count &&
            parsed.max_key_per_request > 0 &&
            parsed.max_key_size >= parsed.key_size && parsed.min_key_size > 0 &&
            parsed.min_key_size <= parsed.key_size &&
            parsed.max_SAE_ID_count >= 0;

    json_decref(root);
    if (!valid) {
        qkd_status_free(&parsed);
        return -1;
    }

    *status = parsed;
    return 0;
}

int parse_response_to_qkd_keys(const char *response,
                               qkd_key_container_t *container) {
    if (!response || !container)
        return -1;

    json_error_t error;
    json_t *root = json_loads(response, JSON_REJECT_DUPLICATES, &error);
    if (!json_is_object(root)) {
        QKD_DBG_ERR("Error parsing keys JSON: %s", error.text);
        json_decref(root);
        return -1;
    }

    json_t *keys = json_object_get(root, "keys");
    size_t key_count = json_is_array(keys) ? json_array_size(keys) : 0;
    if (!json_is_array(keys) || key_count == 0 || key_count > MAX_KEYS ||
        key_count > INT32_MAX) {
        json_decref(root);
        return -1;
    }

    qkd_key_container_t parsed = {0};
    parsed.keys = calloc(key_count, sizeof(*parsed.keys));
    parsed.key_count = (int32_t)key_count;
    if (!parsed.keys) {
        json_decref(root);
        return -1;
    }

    for (size_t i = 0; i < key_count; i++) {
        json_t *key_data = json_array_get(keys, i);
        parsed.keys[i].key_ID = duplicate_json_string(key_data, "key_ID");
        parsed.keys[i].key = duplicate_json_string(key_data, "key");
        if (!is_uuid_string(parsed.keys[i].key_ID) ||
            !is_base64_string(parsed.keys[i].key)) {
            json_decref(root);
            qkd_key_container_free(&parsed);
            return -1;
        }
    }

    json_decref(root);
    *container = parsed;
    return 0;
}

static char *build_post_data(const qkd_key_ids_t *key_ids,
                             const char *master_sae_id) {
    json_t *root = json_object();
    json_t *ids = json_array();
    if (!root || !ids) {
        json_decref(root);
        json_decref(ids);
        return NULL;
    }

    for (int32_t i = 0; i < key_ids->key_ID_count; i++) {
        if (!key_ids->key_IDs[i].key_ID ||
            key_ids->key_IDs[i].key_ID_extension) {
            json_decref(root);
            json_decref(ids);
            return NULL;
        }

        json_t *entry = json_object();
        if (!entry ||
            json_object_set_new(entry, "key_ID",
                                json_string(key_ids->key_IDs[i].key_ID)) != 0) {
            json_decref(entry);
            json_decref(root);
            json_decref(ids);
            return NULL;
        }
#if defined(QKD_USE_QUKAYDEE) && QKD_USE_QUKAYDEE
        if (json_object_set_new(entry, "master_SAE_ID",
                                json_string(master_sae_id)) != 0) {
            json_decref(entry);
            json_decref(root);
            json_decref(ids);
            return NULL;
        }
#else
        (void)master_sae_id;
#endif
        if (json_array_append(ids, entry) != 0) {
            json_decref(entry);
            json_decref(root);
            json_decref(ids);
            return NULL;
        }
        json_decref(entry);
    }

    if (json_object_set(root, "key_IDs", ids) != 0) {
        json_decref(root);
        json_decref(ids);
        return NULL;
    }
    json_decref(ids);

    char *post_data = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    return post_data;
}

static char *build_url(const char *hostname, const char *sae_id,
                       const char *suffix) {
    if (strncmp(hostname, "https://", sizeof("https://") - 1U) != 0)
        return NULL;

    CURL *curl = curl_easy_init();
    if (!curl)
        return NULL;
    char *escaped_id = curl_easy_escape(curl, sae_id, 0);
    if (!escaped_id) {
        curl_easy_cleanup(curl);
        return NULL;
    }

    int length =
        snprintf(NULL, 0, "%s/api/v1/keys/%s/%s", hostname, escaped_id, suffix);
    if (length < 0) {
        curl_free(escaped_id);
        curl_easy_cleanup(curl);
        return NULL;
    }

    char *url = malloc((size_t)length + 1U);
    if (url)
        snprintf(url, (size_t)length + 1U, "%s/api/v1/keys/%s/%s", hostname,
                 escaped_id, suffix);
    curl_free(escaped_id);
    curl_easy_cleanup(curl);
    return url;
}

static char *handle_request_https(const char *url, const char *post_data,
                                  long *http_code,
                                  const etsi014_cert_config_t *cert_config) {
    if (!url || !http_code || !cert_config)
        return NULL;

    *http_code = 0;
    struct memory_buffer response = {.data = malloc(1), .size = 0};
    if (!response.data)
        return NULL;
    response.data[0] = '\0';

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(response.data);
        return NULL;
    }

    struct curl_slist *headers =
        curl_slist_append(NULL, "Accept: application/json");
    struct curl_slist *new_headers =
        curl_slist_append(headers, "Content-Type: application/json");
    if (!headers || !new_headers) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(response.data);
        return NULL;
    }
    headers = new_headers;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(curl, CURLOPT_SSLCERT, cert_config->cert_path);
    curl_easy_setopt(curl, CURLOPT_SSLKEY, cert_config->key_path);
    curl_easy_setopt(curl, CURLOPT_CAINFO, cert_config->ca_cert_path);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT_SECONDS);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, REQUEST_TIMEOUT_SECONDS);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (post_data)
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

    CURLcode result = curl_easy_perform(curl);
    if (result == CURLE_OK)
        result = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (result != CURLE_OK) {
        QKD_DBG_ERR("HTTPS request failed: %s", curl_easy_strerror(result));
        free(response.data);
        return NULL;
    }
    return response.data;
}

static uint32_t map_http_error(long http_code) {
    if (http_code == QKD_STATUS_UNAUTHORIZED)
        return QKD_STATUS_UNAUTHORIZED;
    if (http_code >= 400 && http_code < 500)
        return QKD_STATUS_BAD_REQUEST;
    return QKD_STATUS_SERVER_ERROR;
}

static uint32_t handle_keys_response(char *response, long http_code,
                                     qkd_key_container_t *container) {
    if (!response)
        return QKD_STATUS_SERVER_ERROR;
    if (http_code < 200 || http_code >= 300) {
        free(response);
        return map_http_error(http_code);
    }

    int parsed = parse_response_to_qkd_keys(response, container);
    free(response);
    return parsed == 0 ? QKD_STATUS_OK : QKD_STATUS_SERVER_ERROR;
}

static uint32_t get_status(const char *kme_hostname, const char *slave_sae_id,
                           qkd_status_t *status) {
    etsi014_cert_config_t config;
    if (init_cert_config(1, &config) != QKD_STATUS_OK)
        return QKD_STATUS_BAD_REQUEST;

    char *url = build_url(kme_hostname, slave_sae_id, "status");
    if (!url)
        return QKD_STATUS_SERVER_ERROR;

    long http_code;
    char *response = handle_request_https(url, NULL, &http_code, &config);
    free(url);
    if (!response)
        return QKD_STATUS_SERVER_ERROR;
    if (http_code < 200 || http_code >= 300) {
        free(response);
        return map_http_error(http_code);
    }

    int parsed = parse_response_to_qkd_status(response, status);
    free(response);
    return parsed == 0 ? QKD_STATUS_OK : QKD_STATUS_SERVER_ERROR;
}

static uint32_t get_key(const char *kme_hostname, const char *slave_sae_id,
                        qkd_key_request_t *request,
                        qkd_key_container_t *container) {
    if (request) {
        if (request->number < 0 || request->size < 0 ||
            request->additional_SAE_count < 0 ||
            request->additional_SAE_count > 0 || request->extension_mandatory)
            return QKD_STATUS_BAD_REQUEST;
    }
    int32_t number = request && request->number > 0 ? request->number : 1;
    int32_t size =
        request && request->size > 0 ? request->size : DEFAULT_KEY_SIZE;
    if (number <= 0 || number > MAX_KEYS || size <= 0)
        return QKD_STATUS_BAD_REQUEST;

    char suffix[96];
    int suffix_length =
        snprintf(suffix, sizeof(suffix),
                 "enc_keys?number=%" PRId32 "&size=%" PRId32, number, size);
    if (suffix_length < 0 || (size_t)suffix_length >= sizeof(suffix))
        return QKD_STATUS_BAD_REQUEST;

    char *url = build_url(kme_hostname, slave_sae_id, suffix);
    if (!url)
        return QKD_STATUS_SERVER_ERROR;

    etsi014_cert_config_t config;
    if (init_cert_config(1, &config) != QKD_STATUS_OK) {
        free(url);
        return QKD_STATUS_BAD_REQUEST;
    }

    long http_code;
    char *response = handle_request_https(url, NULL, &http_code, &config);
    free(url);
    return handle_keys_response(response, http_code, container);
}

static uint32_t get_key_with_ids(const char *kme_hostname,
                                 const char *master_sae_id,
                                 qkd_key_ids_t *key_ids,
                                 qkd_key_container_t *container) {
    if (key_ids->key_ID_count <= 0 || key_ids->key_ID_count > MAX_KEYS ||
        !key_ids->key_IDs || key_ids->key_IDs_extension)
        return QKD_STATUS_BAD_REQUEST;

    char *url = build_url(kme_hostname, master_sae_id, "dec_keys");
    char *post_data = build_post_data(key_ids, master_sae_id);
    if (!url || !post_data) {
        free(url);
        free(post_data);
        return QKD_STATUS_BAD_REQUEST;
    }

    etsi014_cert_config_t config;
    if (init_cert_config(0, &config) != QKD_STATUS_OK) {
        free(url);
        free(post_data);
        return QKD_STATUS_BAD_REQUEST;
    }

    long http_code;
    char *response = handle_request_https(url, post_data, &http_code, &config);
    free(url);
    free(post_data);
    return handle_keys_response(response, http_code, container);
}

const struct qkd_014_backend qkd_etsi014_backend = {
    .name = "qkd_etsi014_backend",
    .get_status = get_status,
    .get_key = get_key,
    .get_key_with_ids = get_key_with_ids};

#endif /* QKD_USE_ETSI014_BACKEND */
