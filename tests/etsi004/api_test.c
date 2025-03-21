/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 */

/*
 * tests/etsi004/api_test.c
 */

 #include "qkd_etsi_api.h"
 #include "etsi004/api.h"
 #include <assert.h>
 #include <stdio.h>
 #include <string.h>
 #include <unistd.h>
 
 /* Helper function to simulate peer connection */
 static void simulate_peer_connection(const unsigned char *ksid) {
     uint32_t status;
     struct qkd_qos_s peer_qos = {.Key_chunk_size = QKD_KEY_SIZE,
                                  .Max_bps = 1000,
                                  .Min_bps = 100,
                                  .Jitter = 10,
                                  .Priority = 1,
                                  .Timeout = 1000,
                                  .TTL = 1};
 
     // Responder connects with existing KSID
     status = OPEN_CONNECT("qkd://localhost/bob", "qkd://localhost/alice",
                           &peer_qos, (unsigned char *)ksid, &status);
     assert(status == QKD_STATUS_SUCCESS);
 }
 
 static void test_open_connect_close(void) {
     uint32_t status;
     struct qkd_qos_s qos = {.Key_chunk_size = QKD_KEY_SIZE,
                             .Max_bps = 1000,
                             .Min_bps = 100,
                             .Jitter = 10,
                             .Priority = 1,
                             .Timeout = 1000,
                             .TTL = 1};
     unsigned char key_stream_id[QKD_KSID_SIZE] = {0};
     const char *source = "qkd://localhost/alice";
     const char *destination = "qkd://localhost/bob";
 
     printf("Testing OPEN_CONNECT/CLOSE...\n");
 
     // Test 1: Initial OPEN_CONNECT as initiator
     status = OPEN_CONNECT(source, destination, &qos, key_stream_id, &status);
     assert(status == QKD_STATUS_PEER_DISCONNECTED);
     printf("  Initiator OPEN_CONNECT: PASS\n");
 
     // Test 2: Simulate peer connection
     simulate_peer_connection(key_stream_id);
     printf("  Peer connection: PASS\n");
 
     // Test 3: Try to reuse same KSID (should fail)
     status = OPEN_CONNECT(source, destination, &qos, key_stream_id, &status);
     assert(status == QKD_STATUS_KSID_IN_USE);
     printf("  KSID reuse prevention: PASS\n");
 
     // Test 4: Test invalid parameters
     status = OPEN_CONNECT(NULL, destination, &qos, key_stream_id, &status);
     assert(status == QKD_STATUS_NO_CONNECTION);
     printf("  NULL parameter handling: PASS\n");
 
     // Test 5: Test QoS validation
     struct qkd_qos_s invalid_qos = qos;
     invalid_qos.Min_bps = 2000; // Higher than Max_bps
     status =
         OPEN_CONNECT(source, destination, &invalid_qos, key_stream_id, &status);
     assert(status == QKD_STATUS_QOS_NOT_MET);
     printf("  QoS validation: PASS\n");
 
     // Test 6: Close connection
     status = CLOSE(key_stream_id, &status);
     assert(status == QKD_STATUS_SUCCESS);
     printf("  CLOSE: PASS\n");
 
     // Test 7: Wait for TTL and try close again
     sleep(1); // In real tests, you might want to make TTL shorter for testing
     status = CLOSE(key_stream_id, &status);
     assert(status == QKD_STATUS_SUCCESS);
     printf("  TTL handling: PASS\n");
 }
 
 static void test_get_key(void) {
     uint32_t status;
     struct qkd_qos_s qos = {.Key_chunk_size = QKD_KEY_SIZE,
                             .Max_bps = 1000,
                             .Min_bps = 100,
                             .Jitter = 10,
                             .Priority = 1,
                             .Timeout = 1000,
                             .TTL = 1};
     unsigned char key_stream_id[QKD_KSID_SIZE] = {0};
     unsigned char key_buffer1[QKD_KEY_SIZE];
     unsigned char key_buffer2[QKD_KEY_SIZE];
     uint32_t index = 0;
     struct qkd_metadata_s metadata = {0};
     const char *source = "qkd://localhost/alice";
     const char *destination = "qkd://localhost/bob";
 
     printf("\nTesting GET_KEY...\n");
 
     // Test 1: Setup connection
     status = OPEN_CONNECT(source, destination, &qos, key_stream_id, &status);
     assert(status == QKD_STATUS_PEER_DISCONNECTED);
     simulate_peer_connection(key_stream_id);
     printf("  Connection setup: PASS\n");
 
     // Test 2: Get first key
     status = GET_KEY(key_stream_id, &index, key_buffer1, &metadata, &status);
     assert(status == QKD_STATUS_SUCCESS);
     printf("  Initial key retrieval: PASS\n");
 
     // Test 3: Get same key again (should be identical due to index)
     status = GET_KEY(key_stream_id, &index, key_buffer2, &metadata, &status);
     assert(status == QKD_STATUS_SUCCESS);
     assert(memcmp(key_buffer1, key_buffer2, QKD_KEY_SIZE) == 0);
     printf("  Key determinism: PASS\n");
 
     // Test 4: Get key with different index
     index = 1;
     status = GET_KEY(key_stream_id, &index, key_buffer2, &metadata, &status);
     assert(status == QKD_STATUS_SUCCESS);
     assert(memcmp(key_buffer1, key_buffer2, QKD_KEY_SIZE) != 0);
     printf("  Index-based key generation: PASS\n");
 
     // Test 5: Test rate limiting
     index = 1000000; // Way beyond what Max_bps allows
     status = GET_KEY(key_stream_id, &index, key_buffer1, &metadata, &status);
     assert(status == QKD_STATUS_INSUFFICIENT_KEY);
     printf("  Rate limiting: PASS\n");
 
     status = CLOSE(key_stream_id, &status);
     assert(status == QKD_STATUS_SUCCESS);
 }
 
 int main(void) {
     printf("Running QKD ETSI API tests...\n\n");
 
     // Run all tests
     test_open_connect_close();
     test_get_key();
 
     printf("\nAll tests passed!\n");
     return 0;
 }