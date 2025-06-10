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

    // Import the sys module to manipulate the path
    PyObject *sys_module = PyImport_ImportModule("sys");
    if (!sys_module) {
        PyErr_Print();
        QKD_DBG_ERR("Failed to import sys module");
        Py_Finalize();
        return false;
    }

    // Add the qkd module directory to the path
    PyObject *sys_path = PyObject_GetAttrString(sys_module, "path");
    PyObject *path_str = PyUnicode_FromString("/usr/local/lib/qkd");
    PyList_Append(sys_path, path_str);
    Py_DECREF(path_str);
    Py_DECREF(sys_path);
    Py_DECREF(sys_module);

    // Import the qkd_client module
    py_qkd_client_module = PyImport_ImportModule("qkd_client");
    if (!py_qkd_client_module) {
        PyErr_Print();
        QKD_DBG_ERR("Failed to import qkd_client module");
        Py_Finalize();
        return false;
    }

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

    Py_ssize_t tuple_size = PyTuple_Size(py_open_connect_result);
    QKD_DBG_INFO("Python open_connect returned tuple of size %zd", tuple_size);
    
    uint32_t status_value = QKD_STATUS_NO_CONNECTION;
    
    if (tuple_size >= 3) {
        PyObject *py_returned_qos = PyTuple_GetItem(py_open_connect_result, 0);
        PyObject *py_key_stream_id = PyTuple_GetItem(py_open_connect_result, 1);
        PyObject *py_status_obj = PyTuple_GetItem(py_open_connect_result, 2);
        
        // Extract status value
        if (py_status_obj && PyLong_Check(py_status_obj)) {
            status_value = (uint32_t)PyLong_AsLong(py_status_obj);
        }
        QKD_DBG_INFO("Status value extracted from tuple: %u", status_value);
        
        // Update QoS from returned values
        if (py_returned_qos && PyDict_Check(py_returned_qos)) {
            convert_python_to_qos(py_returned_qos, qos);
            QKD_DBG_INFO("QoS updated from returned values");
        }
        
        // Process key_stream_id if status is success or QoS_NOT_MET
        if ((status_value == QKD_STATUS_SUCCESS || status_value == QKD_STATUS_QOS_NOT_MET || 
             status_value == QKD_STATUS_PEER_NOT_CONNECTED) && 
            py_key_stream_id && py_key_stream_id != Py_None) {
            
            // Get the bytes attribute of the UUID
            PyObject *py_bytes = PyObject_GetAttrString(py_key_stream_id, "bytes");
            if (py_bytes && PyBytes_Check(py_bytes)) {
                // Copy the UUID bytes to the output buffer
                memcpy(key_stream_id, PyBytes_AsString(py_bytes), QKD_KSID_SIZE);
                QKD_DBG_INFO("Key stream ID extracted successfully");
                Py_DECREF(py_bytes);
            } else {
                PyErr_Clear();
                memset(key_stream_id, 0, QKD_KSID_SIZE);  // Set to zeros if no valid UUID
                QKD_DBG_ERR("Failed to extract key stream ID bytes");
            }
        } else {
            // No valid key stream ID or status not successful
            memset(key_stream_id, 0, QKD_KSID_SIZE);
            QKD_DBG_INFO("Key stream ID not available or status not successful");
        }
    } else {
        // Tuple doesn't have enough elements
        QKD_DBG_ERR("Python open_connect returned tuple with insufficient elements");
        memset(key_stream_id, 0, QKD_KSID_SIZE);
    }

    PyObject *py_updated_qos = PyObject_GetAttrString(py_qkd_client_instance, "qos");
    if (py_updated_qos && PyDict_Check(py_updated_qos)) {
        convert_python_to_qos(py_updated_qos, qos);
        QKD_DBG_INFO("QoS updated from client instance");
        Py_DECREF(py_updated_qos);
    }

    Py_DECREF(py_open_connect_result);

    // Set the status parameter
    if (status) {
        *status = status_value;
        QKD_DBG_INFO("Setting output status parameter to %u", status_value);
    }

    // Special case for QKD_STATUS_QOS_NOT_MET
    if (status_value == QKD_STATUS_QOS_NOT_MET) {
        QKD_DBG_INFO("QoS not met but connection established with adjusted parameters");
        // Return SUCCESS since this is actually a success case with adjusted parameters
        return QKD_STATUS_SUCCESS;
    }

    // Return the status value
    QKD_DBG_INFO("Returning status value %u from open_connect", status_value);
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
    
    // Import uuid module
    PyObject *py_uuid_module = PyImport_ImportModule("uuid");
    if (!py_uuid_module) {
        PyErr_Print();
        Py_XDECREF(py_get_key_method);
        if (status) {
            *status = QKD_STATUS_NO_CONNECTION;
        }
        return QKD_STATUS_NO_CONNECTION;
    }
    
    // Get the UUID class
    PyObject *py_uuid_class = PyObject_GetAttrString(py_uuid_module, "UUID");
    if (!py_uuid_class) {
        Py_DECREF(py_uuid_module);
        Py_XDECREF(py_get_key_method);
        PyErr_Print();
        if (status) {
            *status = QKD_STATUS_NO_CONNECTION;
        }
        return QKD_STATUS_NO_CONNECTION;
    }
    
    // Create a bytes object from the binary key_id
    PyObject *py_key_bytes = PyBytes_FromStringAndSize((const char *)key_stream_id, 16);
    
    // Create keyword arguments dictionary for UUID constructor
    PyObject *py_kwargs = PyDict_New();
    PyDict_SetItemString(py_kwargs, "bytes", py_key_bytes);
    
    // Create a UUID object using UUID(bytes=key_bytes)
    PyObject *py_uuid = PyObject_Call(py_uuid_class, PyTuple_New(0), py_kwargs);
    
    // Clean up UUID-related objects we don't need anymore
    Py_DECREF(py_uuid_module);
    Py_DECREF(py_uuid_class);
    Py_DECREF(py_key_bytes);
    Py_DECREF(py_kwargs);
    
    if (!py_uuid) {
        PyErr_Print();
        Py_XDECREF(py_get_key_method);
        if (status) {
            *status = QKD_STATUS_NO_CONNECTION;
        }
        return QKD_STATUS_NO_CONNECTION;
    }
    
    // Create substantial JSON string for metadata
    const char *json = "{\"format\":\"json\",\"version\":\"1.0\",\"source\":\"qkd_client\"}";
    size_t json_len = strlen(json);
    
    // Make sure it fits in the buffer
    if (json_len < metadata->Metadata_size) {
        // Copy it to the metadata buffer
        memcpy(metadata->Metadata_buffer, json, json_len);
        metadata->Metadata_buffer[json_len] = '\0';
    }
    
    // IMPORTANT: Pass the metadata as BYTES, not a dictionary
    // The client's get_key() method expects a bytes-like object, not a dictionary
    PyObject *py_metadata_bytes = PyBytes_FromStringAndSize(
        (const char *)metadata->Metadata_buffer, 
        metadata->Metadata_size);
    
    // Now create a tuple with 3 arguments: UUID object, index, and metadata bytes
    PyObject *py_args = PyTuple_New(3);
    PyTuple_SetItem(py_args, 0, py_uuid);          // UUID object
    PyTuple_SetItem(py_args, 1, PyLong_FromLong(*index));
    PyTuple_SetItem(py_args, 2, py_metadata_bytes);  // Bytes object
    
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

    QKD_DBG_INFO("Python close method completed with status: %u", status_value);
    
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