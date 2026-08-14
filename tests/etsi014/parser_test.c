/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>

#include "etsi014/api.h"
#include "qkd_etsi014_backend_internal.h"

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                    #condition);                                               \
            exit(EXIT_FAILURE);                                                \
        }                                                                      \
    } while (0)

#define VALID_KEY                                                              \
    "{\"key_ID\":\"b6a2b8ea-cfaf-4f0e-a82f-7c1f51ee8523\","                    \
    "\"key\":\"w99BK6fvDHk8aSIniB9vQ6v8Qr9seSsd6WmuRYgXFoE=\"}"

static void check_accepted(const char *response) {
    qkd_key_container_t container = {0};

    CHECK(parse_response_to_qkd_keys(response, &container) == 0);
    CHECK(container.key_count == 1);
    CHECK(container.keys != NULL);
    qkd_key_container_free(&container);
}

static void check_rejected(const char *response) {
    qkd_key_container_t container = {0};

    CHECK(parse_response_to_qkd_keys(response, &container) == -1);
    CHECK(container.key_count == 0);
    CHECK(container.keys == NULL);
}

int main(void) {
    check_accepted("{\"keys\":[" VALID_KEY "]}");
    check_accepted("{\"Keys\":[" VALID_KEY "]}");
    check_rejected("{\"keys\":[" VALID_KEY "],\"Keys\":[" VALID_KEY "]}");
    check_rejected("{\"KEYS\":[" VALID_KEY "]}");
    check_rejected("{\"keys\":null,\"Keys\":[" VALID_KEY "]}");
    check_rejected("{\"keys\":[" VALID_KEY "],\"keys\":[" VALID_KEY "]}");
    check_rejected("{\"keys\":[{\"key_ID\":\"b6a2b8ea-cfaf-4f0e-a82f-"
                   "7c1f51ee8523\",\"Key\":\"w99BK6fvDHk8aSIniB9vQ6v8Qr9seSsd6W"
                   "muRYgXFoE=\"}]}");

    return EXIT_SUCCESS;
}
