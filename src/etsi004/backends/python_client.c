/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 */

/*
 * src/etsi004/backends/python_client.c
 */

 #include "etsi004/backends/python_client.h"
 #include "debug.h"
 #include <Python.h>
 #include <string.h>
 #include <stdio.h>
 
 // Python module and client instance
 static PyObject *py_qkd_client_module = NULL;
 static PyObject *py_qkd_client_class = NULL;
 static PyObject *py_qkd_client_instance = NULL;
 
 // Helper functions for Python integration
 static bool initialize_python(void);
 static void finalize_python(void);
 static PyObject *convert_qos_to_python_dict(struct qkd_qos_s *qos);
 static bool convert_python_to_qos(PyObject *py_qos, struct qkd_qos_s *qos);
 
 // Backend implementation functions
 static uint32_t python_client_open_connect(const char *source, const char *destination,
                                           struct qkd_qos_s *qos, unsigned char *key_stream_id,
                                           uint32_t *status);
 static uint32_t python_client_get_key(const unsigned char *key_stream_id, uint32_t *index,
                                      unsigned char *key_buffer, struct qkd_metadata_s *metadata,
                                      uint32_t *status);
 static uint32_t python_client_close(const unsigned char *key_stream_id, uint32_t *status);
 
 // Python client source code as a C string
 static const char *python_client_source = R"(
 import socket
 import ssl
 import struct
 import uuid
 import logging
 import os
 
 # Logging configuration
 logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
 
 # Constants
 VERSION = '1.0.1'
 
 # Client Settings (from environment variables)
 CLIENT_CERT_PEM = os.getenv('CLIENT_CERT_PEM')
 CLIENT_CERT_KEY = os.getenv('CLIENT_CERT_KEY')
 SERVER_CERT_PEM = os.getenv('SERVER_CERT_PEM')
 SERVER_ADDRESS = os.getenv('SERVER_ADDRESS', 'qkd_server')
 CLIENT_ADDRESS = os.getenv('CLIENT_ADDRESS', 'localhost')
 SERVER_PORT = int(os.getenv('SERVER_PORT', 25575))
 KEY_INDEX = int(os.getenv('KEY_INDEX', 0))
 METADATA_SIZE = int(os.getenv('METADATA_SIZE', 1024))
 QOS_KEY_CHUNK_SIZE = int(os.getenv('QOS_KEY_CHUNK_SIZE', 512))
 QOS_MAX_BPS = int(os.getenv('QOS_MAX_BPS', 40000))
 QOS_MIN_BPS = int(os.getenv('QOS_MIN_BPS', 5000))
 QOS_JITTER = int(os.getenv('QOS_JITTER', 10))
 QOS_PRIORITY = int(os.getenv('QOS_PRIORITY', 0))
 QOS_TIMEOUT = int(os.getenv('QOS_TIMEOUT', 5000))
 QOS_TTL = int(os.getenv('QOS_TTL', 3600))
 
 # API Function Codes
 QKD_SERVICE_OPEN_CONNECT_REQUEST = 0x02
 QKD_SERVICE_OPEN_CONNECT_RESPONSE = 0x03
 QKD_SERVICE_GET_KEY_REQUEST = 0x04
 QKD_SERVICE_GET_KEY_RESPONSE = 0x05
 QKD_SERVICE_CLOSE_REQUEST = 0x08
 QKD_SERVICE_CLOSE_RESPONSE = 0x09
 
 # QoS Parameter Sizes
 QOS_FIELD_COUNT = 7
 QOS_FIELD_SIZE = 4  # Each QoS field is a 32-bit unsigned integer
 METADATA_MIMETYPE_SIZE = 256  # bytes
 
 # Status Codes
 STATUS_SUCCESS = 0
 STATUS_PEER_NOT_CONNECTED = 1
 STATUS_INSUFFICIENT_KEY = 2
 STATUS_PEER_NOT_CONNECTED_GET_KEY = 3
 STATUS_NO_QKD_CONNECTION = 4
 STATUS_KSID_IN_USE = 5
 STATUS_TIMEOUT = 6
 STATUS_QOS_NOT_MET = 7
 STATUS_METADATA_SIZE_INSUFFICIENT = 8
 
 class KnownException(Exception):
     """Custom exception class for known errors."""
 
 class QKDClient:
     """Client class for interacting with the QKD server."""
 
     def __init__(self):
         """Initialize the QKDClient with default values."""
         self.key_stream_id = uuid.UUID(int=0)
         self.sock = None
         self.qos = {
             'Key_chunk_size': QOS_KEY_CHUNK_SIZE,  # in bytes
             'Max_bps': QOS_MAX_BPS,
             'Min_bps': QOS_MIN_BPS,
             'Jitter': QOS_JITTER,
             'Priority': QOS_PRIORITY,
             'Timeout': QOS_TIMEOUT,  # in milliseconds
             'TTL': QOS_TTL,  # in seconds
             'Metadata_mimetype': 'application/json'
         }
 
     def connect(self, server_ip, server_port):
         """Establish a secure connection to the server."""
         raw_sock = socket.socket(socket.AF_INET)
         raw_sock.settimeout(5)
         if SERVER_CERT_PEM and CLIENT_CERT_KEY and CLIENT_CERT_PEM:
             context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
             context.load_cert_chain(certfile=CLIENT_CERT_PEM, keyfile=CLIENT_CERT_KEY)
             context.load_verify_locations(cafile=SERVER_CERT_PEM)
             self.sock = context.wrap_socket(raw_sock, server_hostname=server_ip)
         else:
             self.sock = raw_sock
 
         try:
             self.sock.connect((server_ip, server_port))
             logging.info(f"Connected to server at {server_ip}:{server_port}")
             return True
         except (TimeoutError, ConnectionRefusedError) as e:
             logging.error(f"OPEN_CONNECT failed with status: {STATUS_PEER_NOT_CONNECTED}, {e}")
             raise KnownException(f"OPEN_CONNECT failed with status: {STATUS_PEER_NOT_CONNECTED}") from e
 
     def recv_full_response(self):
         """Receive the full response from the server."""
         # Read header (8 bytes)
         header = self.recv_full_data(8)
         if not header or len(header) < 8:
             raise KnownException("Incomplete header received.")
         # Parse header
         version_major, version_minor, version_patch, service_type = struct.unpack('!BBBb', header[:4])
         payload_length = struct.unpack('!I', header[4:8])[0]
         # Read payload
         payload = self.recv_full_data(payload_length)
         logging.debug(f"Version {version_major}.{version_minor}.{version_patch}. Received service type: {service_type}")
         if len(payload) < payload_length:
             raise KnownException("Incomplete payload received.")
         return header + payload
 
     def recv_full_data(self, length):
         """Receive exactly 'length' bytes of data from the server."""
         data = b''
         while len(data) < length:
             chunk = self.sock.recv(length - len(data))
             if not chunk:
                 break
             data += chunk
         return data
 
     def open_connect(self, source_uri, dest_uri):
         """Send an OPEN_CONNECT_REQUEST to the server."""
         # Construct payload
         payload = source_uri.encode() + b'\x00'
         payload += dest_uri.encode() + b'\x00'
         payload += self.construct_qos(self.qos)
         # Key_stream_ID set to all zeros (16 bytes)
         payload += self.key_stream_id.bytes
 
         # Logging statements
         logging.debug(f"Source URI sent by client: {source_uri}")
         logging.debug(f"Destination URI sent by client: {dest_uri}")
         logging.debug(f"QoS sent by client: {self.qos}")
 
         # Construct request
         request = self.construct_request(QKD_SERVICE_OPEN_CONNECT_REQUEST, payload)
 
         # Send request and receive response
         try:
             self.sock.sendall(request)
             response = self.recv_full_response()
         except (TimeoutError, ConnectionRefusedError) as e:
             logging.error(f"OPEN_CONNECT failed with status: {STATUS_PEER_NOT_CONNECTED}")
             raise KnownException(f"OPEN_CONNECT failed with status: {STATUS_PEER_NOT_CONNECTED}") from e
 
         # Parse response
         status, key_stream_id = self.parse_open_connect_response(response)
         if status == STATUS_SUCCESS or status == STATUS_QOS_NOT_MET:
             self.key_stream_id = key_stream_id
             logging.info(f"OPEN_CONNECT status: {status}, Key_stream_ID: {self.key_stream_id}")
             return status, self.key_stream_id
         else:
             logging.error(f"OPEN_CONNECT failed with status: {status}")
             raise KnownException(f"OPEN_CONNECT failed with status: {status}")
 
     def get_key(self, index, metadata_size):
         """Send a GET_KEY_REQUEST to the server and receive key material."""
         # Construct payload
         payload = self.key_stream_id.bytes
         payload += struct.pack('!I', index)
         payload += struct.pack('!I', metadata_size)
         logging.debug(f"Metadata size requested by client: {metadata_size}")
 
         # Construct request
         request = self.construct_request(QKD_SERVICE_GET_KEY_REQUEST, payload)
 
         # Send request and receive response
         try:
             self.sock.sendall(request)
             response = self.recv_full_response()
         except (TimeoutError, ConnectionRefusedError) as e:
             logging.error(f"GET_KEY failed with status: {STATUS_PEER_NOT_CONNECTED}")
             raise KnownException(f"GET_KEY failed with status: {STATUS_PEER_NOT_CONNECTED}") from e
 
         # Parse response
         status, key_material, metadata = self.parse_get_key_response(response)
 
         if status == STATUS_SUCCESS:
             logging.info(f"GET_KEY status: {status}, Key_stream_ID: {self.key_stream_id}, Key length: {len(key_material)}, Metadata: {metadata}")
             return status, key_material, metadata
         else:
             logging.error(f"GET_KEY failed with status: {status}")
             raise KnownException(f"GET_KEY failed with status: {status}")
 
     def close(self):
         """Send a CLOSE_REQUEST to the server to close the connection."""
         # Construct payload
         payload = self.key_stream_id.bytes
 
         # Construct request
         request = self.construct_request(QKD_SERVICE_CLOSE_REQUEST, payload)
 
         # Send request and receive response
         try:
             self.sock.sendall(request)
             response = self.recv_full_response()
             self.sock.close()
         except (TimeoutError, ConnectionRefusedError) as e:
             logging.error(f"CLOSE failed with status: {STATUS_PEER_NOT_CONNECTED}")
             raise KnownException(f"CLOSE failed with status: {STATUS_PEER_NOT_CONNECTED}") from e
 
         # Parse response
         status = self.parse_close_response(response)
         if status == STATUS_SUCCESS:
             logging.info(f"CLOSE status: {status}, Key_stream_ID: {self.key_stream_id}")
             return status
         else:
             logging.error(f"CLOSE failed with status: {status}")
             raise KnownException(f"CLOSE failed with status: {status}")
 
     def construct_request(self, service_type, payload):
         """Construct a request packet to send to the server."""
         version_bytes = struct.pack('!BBB', *[int(x) for x in VERSION.split('.')])
         service_type_byte = struct.pack('!b', service_type)
         payload_length = struct.pack('!I', len(payload))
         request = version_bytes + service_type_byte + payload_length + payload
         return request
 
     def construct_qos(self, qos):
         """Construct the QoS bytes to include in the request."""
         qos_fields = struct.pack(
             '!7I',
             qos['Key_chunk_size'],
             qos['Max_bps'],
             qos['Min_bps'],
             qos['Jitter'],
             qos['Priority'],
             qos['Timeout'],
             qos['TTL']
         )
         metadata_mimetype_bytes = qos['Metadata_mimetype'].encode().ljust(METADATA_MIMETYPE_SIZE, b'\x00')
         return qos_fields + metadata_mimetype_bytes
 
     def parse_open_connect_response(self, response):
         """Parse the OPEN_CONNECT_RESPONSE from the server."""
         # Parse header
         payload_length = struct.unpack('!I', response[4:8])[0]
         payload = response[8:8 + payload_length]
 
         # Parse payload
         status = struct.unpack('!I', payload[:4])[0]
 
         if status == STATUS_SUCCESS or status == STATUS_QOS_NOT_MET:
             # Parse QoS parameters from the response
             qos_data = payload[4:4 + (QOS_FIELD_COUNT * QOS_FIELD_SIZE) + METADATA_MIMETYPE_SIZE]
             server_qos = self.parse_qos(qos_data)
 
             # If QoS not met by the server
             if status == STATUS_QOS_NOT_MET:
                 logging.warning(f"QoS not met. Adjusted QoS provided by server: {server_qos}")
 
             # Logging adjusted QoS
             logging.debug(f"QoS received by client: {server_qos}")
 
             # Update client's QoS to use the adjusted QoS from the server
             self.qos = server_qos
 
             # Extract Key_stream_ID
             key_stream_id_bytes_start = 4 + (QOS_FIELD_COUNT * QOS_FIELD_SIZE) + METADATA_MIMETYPE_SIZE
             key_stream_id_bytes_end = key_stream_id_bytes_start + 16
             key_stream_id_bytes = payload[key_stream_id_bytes_start:key_stream_id_bytes_end]
             key_stream_id = uuid.UUID(bytes=key_stream_id_bytes)
 
             return status, key_stream_id
 
         return status, None
 
     def parse_get_key_response(self, response):
         """Parse the GET_KEY_RESPONSE from the server."""
         # Parse header
         payload_length = struct.unpack('!I', response[4:8])[0]
         payload = response[8:8 + payload_length]
 
         # Parse payload
         status = struct.unpack('!I', payload[:4])[0]
 
         if status == STATUS_SUCCESS:
             # Parse index and key_chunk_size
             index = struct.unpack('!I', payload[4:8])[0]
             key_chunk_size = struct.unpack('!I', payload[8:12])[0]
 
             # Extract key material
             key_material_start = 12
             key_material_end = key_material_start + key_chunk_size
             key_material = payload[key_material_start:key_material_end]
 
             # Parse metadata_size
             metadata_size_start = key_material_end
             metadata_size_end = metadata_size_start + 4
             metadata_size = struct.unpack('!I', payload[metadata_size_start:metadata_size_end])[0]
 
             # Extract metadata using metadata_size
             metadata_start = metadata_size_end
             metadata_end = metadata_start + metadata_size
             metadata_bytes = payload[metadata_start:metadata_end]
             metadata = metadata_bytes.decode()
 
             # Logging for index and metadata_size
             logging.debug(f"Index received by client: {index}")
             logging.debug(f"Metadata size received by client: {metadata_size}")
 
             # Logging for key material
             if len(key_material) >= 8:
                 first8 = key_material[:8].hex()
                 last8 = key_material[-8:].hex()
                 logging.debug(f"Key received by client: first 8 bytes {first8}, last 8 bytes {last8}")
             else:
                 logging.debug(f"Key received by client is less than 8 bytes: {key_material.hex()}")
 
             # Logging for metadata
             logging.debug(f"Metadata received by client: {metadata}")
 
             return status, key_material, metadata
 
         return status, b'', ''
 
     def parse_close_response(self, response):
         """Parse the CLOSE_RESPONSE from the server."""
         # Parse header
         payload_length = struct.unpack('!I', response[4:8])[0]
         payload = response[8:8 + payload_length]
 
         # Parse payload
         status = struct.unpack('!I', payload[:4])[0]
 
         return status
 
     def parse_qos(self, qos_data):
         """Parse QoS data from the response into a dictionary."""
         qos_fields = struct.unpack('!7I', qos_data[:QOS_FIELD_COUNT * QOS_FIELD_SIZE])
         metadata_mimetype = qos_data[QOS_FIELD_COUNT * QOS_FIELD_SIZE:].decode().strip('\x00')
         qos = {
             'Key_chunk_size': qos_fields[0],
             'Max_bps': qos_fields[1],
             'Min_bps': qos_fields[2],
             'Jitter': qos_fields[3],
             'Priority': qos_fields[4],
             'Timeout': qos_fields[5],
             'TTL': qos_fields[6],
             'Metadata_mimetype': metadata_mimetype
         }
         return qos
 )";
 
 // Initialize the Python interpreter and the QKD client module
 static bool initialize_python(void) {
     if (Py_IsInitialized()) {
         return true;  // Already initialized
     }
 
     Py_Initialize();
     if (!Py_IsInitialized()) {
         QKD_DBG_ERR("Failed to initialize Python interpreter");
         return false;
     }
 
     // Create a new module for the QKD client
     py_qkd_client_module = PyModule_New("qkd_client");
     if (!py_qkd_client_module) {
         PyErr_Print();
         QKD_DBG_ERR("Failed to create QKD client module");
         Py_Finalize();
         return false;
     }
 
     // Get the module dictionary
     PyObject *module_dict = PyModule_GetDict(py_qkd_client_module);
 
     // Execute the Python code to define the QKDClient class
     PyObject *py_result = PyRun_String(python_client_source, Py_file_input, module_dict, module_dict);
     if (!py_result) {
         PyErr_Print();
         QKD_DBG_ERR("Failed to execute Python client code");
         Py_DECREF(py_qkd_client_module);
         Py_Finalize();
         return false;
     }
     Py_DECREF(py_result);
 
     // Get the QKDClient class from the module
     py_qkd_client_class = PyObject_GetAttrString(py_qkd_client_module, "QKDClient");
     if (!py_qkd_client_class || !PyCallable_Check(py_qkd_client_class)) {
         PyErr_Print();
         QKD_DBG_ERR("Failed to get QKDClient class");
         Py_XDECREF(py_qkd_client_class);
         Py_DECREF(py_qkd_client_module);
         Py_Finalize();
         return false;
     }
 
     // Create an instance of the QKDClient class
     py_qkd_client_instance = PyObject_CallObject(py_qkd_client_class, NULL);
     if (!py_qkd_client_instance) {
         PyErr_Print();
         QKD_DBG_ERR("Failed to create QKDClient instance");
         Py_DECREF(py_qkd_client_class);
         Py_DECREF(py_qkd_client_module);
         Py_Finalize();
         return false;
     }
 
     return true;
 }
 
 // Clean up Python resources
 static void finalize_python(void) {
     Py_XDECREF(py_qkd_client_instance);
     Py_XDECREF(py_qkd_client_class);
     Py_XDECREF(py_qkd_client_module);
     
     if (Py_IsInitialized()) {
         Py_Finalize();
     }
 }
 
 // Convert C QoS structure to Python dictionary
 static PyObject *convert_qos_to_python_dict(struct qkd_qos_s *qos) {
     PyObject *py_qos = PyDict_New();
     if (!py_qos) {
         PyErr_Print();
         return NULL;
     }
 
     // Add QoS fields to the Python dictionary
     PyDict_SetItemString(py_qos, "Key_chunk_size", PyLong_FromLong(qos->Key_chunk_size));
     PyDict_SetItemString(py_qos, "Max_bps", PyLong_FromLong(qos->Max_bps));
     PyDict_SetItemString(py_qos, "Min_bps", PyLong_FromLong(qos->Min_bps));
     PyDict_SetItemString(py_qos, "Jitter", PyLong_FromLong(qos->Jitter));
     PyDict_SetItemString(py_qos, "Priority", PyLong_FromLong(qos->Priority));
     PyDict_SetItemString(py_qos, "Timeout", PyLong_FromLong(qos->Timeout));
     PyDict_SetItemString(py_qos, "TTL", PyLong_FromLong(qos->TTL));
     PyDict_SetItemString(py_qos, "Metadata_mimetype", PyUnicode_FromString(qos->Metadata_mimetype));
 
     return py_qos;
 }
 
 // Convert Python QoS dictionary to C structure
 static bool convert_python_to_qos(PyObject *py_qos, struct qkd_qos_s *qos) {
     PyObject *value;
 
     // Extract each field from the Python dictionary and set it in the C structure
     value = PyDict_GetItemString(py_qos, "Key_chunk_size");
     if (value && PyLong_Check(value)) {
         qos->Key_chunk_size = (uint32_t)PyLong_AsLong(value);
     }
 
     value = PyDict_GetItemString(py_qos, "Max_bps");
     if (value && PyLong_Check(value)) {
         qos->Max_bps = (uint32_t)PyLong_AsLong(value);
     }
 
     value = PyDict_GetItemString(py_qos, "Min_bps");
     if (value && PyLong_Check(value)) {
         qos->Min_bps = (uint32_t)PyLong_AsLong(value);
     }
 
     value = PyDict_GetItemString(py_qos, "Jitter");
     if (value && PyLong_Check(value)) {
         qos->Jitter = (uint32_t)PyLong_AsLong(value);
     }
 
     value = PyDict_GetItemString(py_qos, "Priority");
     if (value && PyLong_Check(value)) {
         qos->Priority = (uint32_t)PyLong_AsLong(value);
     }
 
     value = PyDict_GetItemString(py_qos, "Timeout");
     if (value && PyLong_Check(value)) {
         qos->Timeout = (uint32_t)PyLong_AsLong(value);
     }
 
     value = PyDict_GetItemString(py_qos, "TTL");
     if (value && PyLong_Check(value)) {
         qos->TTL = (uint32_t)PyLong_AsLong(value);
     }
 
     value = PyDict_GetItemString(py_qos, "Metadata_mimetype");
     if (value && PyUnicode_Check(value)) {
         const char *str = PyUnicode_AsUTF8(value);
         if (str) {
             strncpy(qos->Metadata_mimetype, str, sizeof(qos->Metadata_mimetype) - 1);
             qos->Metadata_mimetype[sizeof(qos->Metadata_mimetype) - 1] = '\0';
         }
     }
 
     return true;
 }
 
 // Backend implementation for OPEN_CONNECT
 static uint32_t python_client_open_connect(const char *source, const char *destination,
                                           struct qkd_qos_s *qos, unsigned char *key_stream_id,
                                           uint32_t *status) {
     // Initialize Python and QKD client if not already done
     if (!initialize_python()) {
         if (status) {
             *status = QKD_STATUS_NO_CONNECTION;
         }
         return QKD_STATUS_NO_CONNECTION;
     }
 
     // Convert QoS structure to Python dictionary
     PyObject *py_qos = convert_qos_to_python_dict(qos);
     if (!py_qos) {
         if (status) {
             *status = QKD_STATUS_NO_CONNECTION;
         }
         return QKD_STATUS_NO_CONNECTION;
     }
 
     // Set the QoS on the Python client instance
     if (PyObject_SetAttrString(py_qkd_client_instance, "qos", py_qos) == -1) {
         PyErr_Print();
         Py_DECREF(py_qos);
         if (status) {
             *status = QKD_STATUS_NO_CONNECTION;
         }
         return QKD_STATUS_NO_CONNECTION;
     }
     Py_DECREF(py_qos);
 
     // Extract server host and port from the destination URI
     // Assuming format: "server://hostname:port"
     char server_host[256] = {0};
     int server_port = 25575;  // Default port
     if (sscanf(destination, "server://%255[^:]:%d", server_host, &server_port) < 1) {
         QKD_DBG_ERR("Invalid destination URI format: %s", destination);
         if (status) {
             *status = QKD_STATUS_NO_CONNECTION;
         }
         return QKD_STATUS_NO_CONNECTION;
     }
 
     // Call connect() method on the Python client
     PyObject *py_connect_method = PyObject_GetAttrString(py_qkd_client_instance, "connect");
     if (!py_connect_method || !PyCallable_Check(py_connect_method)) {
         PyErr_Print();
         Py_XDECREF(py_connect_method);
         if (status) {
             *status = QKD_STATUS_NO_CONNECTION;
         }
         return QKD_STATUS_NO_CONNECTION;
     }
 
     PyObject *py_args = PyTuple_New(2);
     PyTuple_SetItem(py_args, 0, PyUnicode_FromString(server_host));
     PyTuple_SetItem(py_args, 1, PyLong_FromLong(server_port));
 
     PyObject *py_connect_result = PyObject_CallObject(py_connect_method, py_args);
     Py_DECREF(py_args);
     Py_DECREF(py_connect_method);
 
     if (!py_connect_result) {
         PyErr_Print();
         if (status) {
             *status = QKD_STATUS_PEER_NOT_CONNECTED;
         }
         return QKD_STATUS_PEER_NOT_CONNECTED;
     }
     Py_DECREF(py_connect_result);
 
     // Call open_connect() method on the Python client
     PyObject *py_open_connect_method = PyObject_GetAttrString(py_qkd_client_instance, "open_connect");
     if (!py_open_connect_method || !PyCallable_Check(py_open_connect_method)) {
         PyErr_Print();
         Py_XDECREF(py_open_connect_method);
         if (status) {
             *status = QKD_STATUS_NO_CONNECTION;
         }
         return QKD_STATUS_NO_CONNECTION;
     }
 
     py_args = PyTuple_New(2);
     PyTuple_SetItem(py_args, 0, PyUnicode_FromString(source));
     PyTuple_SetItem(py_args, 1, PyUnicode_FromString(destination));
 
     PyObject *py_open_connect_result = PyObject_CallObject(py_open_connect_method, py_args);
     Py_DECREF(py_args);
     Py_DECREF(py_open_connect_method);
 
     if (!py_open_connect_result || !PyTuple_Check(py_open_connect_result)) {
         PyErr_Print();
         Py_XDECREF(py_open_connect_result);
         if (status) {
             *status = QKD_STATUS_NO_CONNECTION;
         }
         return QKD_STATUS_NO_CONNECTION;
     }
 
     // Extract status and key_stream_id from the result tuple
     PyObject *py_status = PyTuple_GetItem(py_open_connect_result, 0);
     uint32_t status_value = (uint32_t)PyLong_AsLong(py_status);
 
     if (status_value == QKD_STATUS_SUCCESS || status_value == QKD_STATUS_QOS_NOT_MET) {
         // Get the key_stream_id from the result
         PyObject *py_key_stream_id = PyTuple_GetItem(py_open_connect_result, 1);
         
         // Get the bytes attribute of the UUID
         PyObject *py_bytes = PyObject_GetAttrString(py_key_stream_id, "bytes");
         if (!py_bytes || !PyBytes_Check(py_bytes)) {
             PyErr_Print();
             Py_XDECREF(py_bytes);
             Py_DECREF(py_open_connect_result);
             if (status) {
                 *status = QKD_STATUS_NO_CONNECTION;
             }
             return QKD_STATUS_NO_CONNECTION;
         }
 
         // Copy the UUID bytes to the output buffer
         memcpy(key_stream_id, PyBytes_AsString(py_bytes), QKD_KSID_SIZE);
         Py_DECREF(py_bytes);
 
         // Get the updated QoS from the Python client
         PyObject *py_updated_qos = PyObject_GetAttrString(py_qkd_client_instance, "qos");
         if (py_updated_qos && PyDict_Check(py_updated_qos)) {
             convert_python_to_qos(py_updated_qos, qos);
             Py_DECREF(py_updated_qos);
         }
     }
 
     Py_DECREF(py_open_connect_result);
 
     if (status) {
         *status = status_value;
     }
     return status_value;
 }
 
 // Backend implementation for GET_KEY
 static uint32_t python_client_get_key(const unsigned char *key_stream_id, uint32_t *index,
                                      unsigned char *key_buffer, struct qkd_metadata_s *metadata,
                                      uint32_t *status) {
     if (!py_qkd_client_instance) {
         if (status) {
             *status = QKD_STATUS_NO_CONNECTION;
         }
         return QKD_STATUS_NO_CONNECTION;
     }
 
     // Call get_key() method on the Python client
     PyObject *py_get_key_method = PyObject_GetAttrString(py_qkd_client_instance, "get_key");
     if (!py_get_key_method || !PyCallable_Check(py_get_key_method)) {
         PyErr_Print();
         Py_XDECREF(py_get_key_method);
         if (status) {
             *status = QKD_STATUS_NO_CONNECTION;
         }
         return QKD_STATUS_NO_CONNECTION;
     }
 
     PyObject *py_args = PyTuple_New(2);
     PyTuple_SetItem(py_args, 0, PyLong_FromLong(*index));
     PyTuple_SetItem(py_args, 1, PyLong_FromLong(metadata->Metadata_size));
 
     PyObject *py_get_key_result = PyObject_CallObject(py_get_key_method, py_args);
     Py_DECREF(py_args);
     Py_DECREF(py_get_key_method);
 
     if (!py_get_key_result || !PyTuple_Check(py_get_key_result)) {
         PyErr_Print();
         Py_XDECREF(py_get_key_result);
         if (status) {
             *status = QKD_STATUS_PEER_NOT_CONNECTED_GET_KEY;
         }
         return QKD_STATUS_PEER_NOT_CONNECTED_GET_KEY;
     }
 
     // Extract status, key_material, and metadata from the result tuple
     PyObject *py_status = PyTuple_GetItem(py_get_key_result, 0);
     uint32_t status_value = (uint32_t)PyLong_AsLong(py_status);
 
     if (status_value == QKD_STATUS_SUCCESS) {
         // Get key material from the result
         PyObject *py_key_material = PyTuple_GetItem(py_get_key_result, 1);
         if (py_key_material && PyBytes_Check(py_key_material)) {
             char *key_data = PyBytes_AsString(py_key_material);
             Py_ssize_t key_len = PyBytes_Size(py_key_material);
             
             // Copy key material to the output buffer
             memcpy(key_buffer, key_data, key_len);
         }
 
         // Get metadata from the result
         PyObject *py_metadata = PyTuple_GetItem(py_get_key_result, 2);
         if (py_metadata && PyUnicode_Check(py_metadata)) {
             const char *metadata_str = PyUnicode_AsUTF8(py_metadata);
             if (metadata_str) {
                 size_t metadata_len = strlen(metadata_str);
                 
                 // Check if metadata buffer is large enough
                 if (metadata_len <= metadata->Metadata_size) {
                     memcpy(metadata->Metadata_buffer, metadata_str, metadata_len);
                     metadata->Metadata_buffer[metadata_len] = '\0';
                 } else {
                     // Metadata buffer is too small
                     status_value = QKD_STATUS_METADATA_SIZE_INSUFFICIENT;
                 }
             }
         }
     }
 
     Py_DECREF(py_get_key_result);
 
     if (status) {
         *status = status_value;
     }
     return status_value;
 }
 
 // Backend implementation for CLOSE
 static uint32_t python_client_close(const unsigned char *key_stream_id, uint32_t *status) {
     if (!py_qkd_client_instance) {
         if (status) {
             *status = QKD_STATUS_NO_CONNECTION;
         }
         return QKD_STATUS_NO_CONNECTION;
     }
 
     // Call close() method on the Python client
     PyObject *py_close_method = PyObject_GetAttrString(py_qkd_client_instance, "close");
     if (!py_close_method || !PyCallable_Check(py_close_method)) {
         PyErr_Print();
         Py_XDECREF(py_close_method);
         if (status) {
             *status = QKD_STATUS_NO_CONNECTION;
         }
         return QKD_STATUS_NO_CONNECTION;
     }
 
     PyObject *py_close_result = PyObject_CallObject(py_close_method, NULL);
     Py_DECREF(py_close_method);
 
     if (!py_close_result) {
         PyErr_Print();
         if (status) {
             *status = QKD_STATUS_PEER_NOT_CONNECTED;
         }
         return QKD_STATUS_PEER_NOT_CONNECTED;
     }
 
     uint32_t status_value = QKD_STATUS_SUCCESS;
     if (PyLong_Check(py_close_result)) {
         status_value = (uint32_t)PyLong_AsLong(py_close_result);
     }
     Py_DECREF(py_close_result);
 
     // Cleanup Python resources
     finalize_python();
 
     if (status) {
         *status = status_value;
     }
     return status_value;
 }
 
 // Export the backend interface
 const struct qkd_004_backend python_client_backend = {
     .name = "python_client",
     .open_connect = python_client_open_connect,
     .get_key = python_client_get_key,
     .close = python_client_close
 };