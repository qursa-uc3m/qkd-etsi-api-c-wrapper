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

#include <Python.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "etsi004/backends/python_client.h"
#include "qkd_etsi_api.h"

// Python module and client instance
static PyObject *py_qkd_client_module = NULL;
static PyObject *py_qkd_client_class = NULL;
static PyObject *py_qkd_client_instance = NULL;
static bool owns_python_interpreter = false;

// Helper functions for Python integration
static bool initialize_python(void);
static PyObject *convert_qos_to_python_dict(struct qkd_qos_s *qos);
static bool convert_python_to_qos(PyObject *py_qos, struct qkd_qos_s *qos);
static PyObject *uuid_from_bytes(const unsigned char *value);
static bool python_to_uint32(PyObject *value, uint32_t *result);

// Backend implementation functions
static uint32_t python_client_open_connect(const char *source,
                                           const char *destination,
                                           struct qkd_qos_s *qos,
                                           unsigned char *key_stream_id,
                                           uint32_t *status);
static uint32_t python_client_get_key(const unsigned char *key_stream_id,
                                      uint32_t *index,
                                      unsigned char *key_buffer,
                                      struct qkd_metadata_s *metadata,
                                      uint32_t *status);
static uint32_t python_client_close(const unsigned char *key_stream_id,
                                    uint32_t *status);

static void finalize_owned_python(void) {
    if (owns_python_interpreter && Py_IsInitialized())
        Py_Finalize();
    owns_python_interpreter = false;
}

// Initialize the Python interpreter and the QKD client module
static bool initialize_python(void) {
    if (py_qkd_client_instance)
        return true;

    if (!Py_IsInitialized()) {
        Py_Initialize();
        owns_python_interpreter = true;
    }
    if (!Py_IsInitialized()) {
        QKD_DBG_ERR("Failed to initialize Python interpreter");
        return false;
    }

    // Import the sys module to manipulate the path
    PyObject *sys_module = PyImport_ImportModule("sys");
    if (!sys_module) {
        PyErr_Print();
        QKD_DBG_ERR("Failed to import sys module");
        finalize_owned_python();
        return false;
    }

    // Add the qkd module directory to the path
    PyObject *sys_path = PyObject_GetAttrString(sys_module, "path");
    PyObject *path_str = PyUnicode_FromString("/usr/local/lib/qkd");
    if (!sys_path || !PyList_Check(sys_path) || !path_str ||
        PyList_Append(sys_path, path_str) != 0) {
        PyErr_Print();
        Py_XDECREF(path_str);
        Py_XDECREF(sys_path);
        Py_DECREF(sys_module);
        finalize_owned_python();
        return false;
    }
    Py_DECREF(path_str);
    Py_DECREF(sys_path);
    Py_DECREF(sys_module);

    // Import the qkd_client module
    py_qkd_client_module = PyImport_ImportModule("qkd_client");
    if (!py_qkd_client_module) {
        PyErr_Print();
        QKD_DBG_ERR("Failed to import qkd_client module");
        finalize_owned_python();
        return false;
    }

    // Get the QKDClient class from the module
    py_qkd_client_class =
        PyObject_GetAttrString(py_qkd_client_module, "QKDClient");
    if (!py_qkd_client_class || !PyCallable_Check(py_qkd_client_class)) {
        PyErr_Print();
        QKD_DBG_ERR("Failed to get QKDClient class");
        Py_XDECREF(py_qkd_client_class);
        Py_DECREF(py_qkd_client_module);
        py_qkd_client_class = NULL;
        py_qkd_client_module = NULL;
        finalize_owned_python();
        return false;
    }

    // Create an instance of the QKDClient class
    py_qkd_client_instance = PyObject_CallObject(py_qkd_client_class, NULL);
    if (!py_qkd_client_instance) {
        PyErr_Print();
        QKD_DBG_ERR("Failed to create QKDClient instance");
        Py_DECREF(py_qkd_client_class);
        Py_DECREF(py_qkd_client_module);
        py_qkd_client_class = NULL;
        py_qkd_client_module = NULL;
        finalize_owned_python();
        return false;
    }

    return true;
}

static PyObject *uuid_from_bytes(const unsigned char *value) {
    PyObject *uuid_module = PyImport_ImportModule("uuid");
    PyObject *uuid_class = NULL;
    PyObject *uuid_bytes = NULL;
    PyObject *kwargs = NULL;
    PyObject *args = NULL;
    PyObject *uuid_value = NULL;

    if (!uuid_module)
        goto cleanup;
    uuid_class = PyObject_GetAttrString(uuid_module, "UUID");
    uuid_bytes = PyBytes_FromStringAndSize((const char *)value, QKD_KSID_SIZE);
    kwargs = PyDict_New();
    args = PyTuple_New(0);
    if (!uuid_class || !PyCallable_Check(uuid_class) || !uuid_bytes ||
        !kwargs || !args ||
        PyDict_SetItemString(kwargs, "bytes", uuid_bytes) != 0)
        goto cleanup;

    uuid_value = PyObject_Call(uuid_class, args, kwargs);

cleanup:
    Py_XDECREF(args);
    Py_XDECREF(kwargs);
    Py_XDECREF(uuid_bytes);
    Py_XDECREF(uuid_class);
    Py_XDECREF(uuid_module);
    return uuid_value;
}

static bool python_to_uint32(PyObject *value, uint32_t *result) {
    if (!value || !PyLong_Check(value))
        return false;

    unsigned long converted = PyLong_AsUnsignedLong(value);
    if (PyErr_Occurred() || converted > UINT32_MAX) {
        PyErr_Clear();
        return false;
    }
    *result = (uint32_t)converted;
    return true;
}

static bool update_qos_integer(PyObject *py_qos, const char *name,
                               uint32_t *field) {
    PyObject *value = PyDict_GetItemString(py_qos, name);

    return !value || python_to_uint32(value, field);
}

// Convert C QoS structure to Python dictionary
static bool add_dict_item(PyObject *dict, const char *name, PyObject *value) {
    if (!value)
        return false;
    int result = PyDict_SetItemString(dict, name, value);
    Py_DECREF(value);
    return result == 0;
}

static PyObject *convert_qos_to_python_dict(struct qkd_qos_s *qos) {
    PyObject *py_qos = PyDict_New();
    if (!py_qos) {
        PyErr_Print();
        return NULL;
    }

    const char *mimetype_end =
        memchr(qos->Metadata_mimetype, '\0', sizeof(qos->Metadata_mimetype));
    if (!mimetype_end ||
        !add_dict_item(py_qos, "Key_chunk_size",
                       PyLong_FromUnsignedLong(qos->Key_chunk_size)) ||
        !add_dict_item(py_qos, "Max_bps",
                       PyLong_FromUnsignedLong(qos->Max_bps)) ||
        !add_dict_item(py_qos, "Min_bps",
                       PyLong_FromUnsignedLong(qos->Min_bps)) ||
        !add_dict_item(py_qos, "Jitter",
                       PyLong_FromUnsignedLong(qos->Jitter)) ||
        !add_dict_item(py_qos, "Priority",
                       PyLong_FromUnsignedLong(qos->Priority)) ||
        !add_dict_item(py_qos, "Timeout",
                       PyLong_FromUnsignedLong(qos->Timeout)) ||
        !add_dict_item(py_qos, "TTL", PyLong_FromUnsignedLong(qos->TTL)) ||
        !add_dict_item(
            py_qos, "Metadata_mimetype",
            PyUnicode_FromStringAndSize(
                qos->Metadata_mimetype,
                (Py_ssize_t)(mimetype_end - qos->Metadata_mimetype)))) {
        Py_DECREF(py_qos);
        return NULL;
    }

    return py_qos;
}

// Convert Python QoS dictionary to C structure
static bool convert_python_to_qos(PyObject *py_qos, struct qkd_qos_s *qos) {
    if (!PyDict_Check(py_qos) ||
        !update_qos_integer(py_qos, "Key_chunk_size", &qos->Key_chunk_size) ||
        !update_qos_integer(py_qos, "Max_bps", &qos->Max_bps) ||
        !update_qos_integer(py_qos, "Min_bps", &qos->Min_bps) ||
        !update_qos_integer(py_qos, "Jitter", &qos->Jitter) ||
        !update_qos_integer(py_qos, "Priority", &qos->Priority) ||
        !update_qos_integer(py_qos, "Timeout", &qos->Timeout) ||
        !update_qos_integer(py_qos, "TTL", &qos->TTL))
        return false;

    PyObject *value = PyDict_GetItemString(py_qos, "Metadata_mimetype");
    if (value && PyUnicode_Check(value)) {
        const char *str = PyUnicode_AsUTF8(value);
        if (!str)
            return false;
        strncpy(qos->Metadata_mimetype, str,
                sizeof(qos->Metadata_mimetype) - 1);
        qos->Metadata_mimetype[sizeof(qos->Metadata_mimetype) - 1] = '\0';
    } else if (value) {
        return false;
    }

    return true;
}

// Backend implementation for OPEN_CONNECT
static uint32_t python_client_open_connect(const char *source,
                                           const char *destination,
                                           struct qkd_qos_s *qos,
                                           unsigned char *key_stream_id,
                                           uint32_t *status) {
    if (!source || !destination || !qos || !key_stream_id || !status)
        return QKD_STATUS_NO_CONNECTION;

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
    if (strncmp(destination, "server://", sizeof("server://") - 1U) != 0) {
        QKD_DBG_ERR("Invalid destination URI format: %s", destination);
        *status = QKD_STATUS_NO_CONNECTION;
        return QKD_STATUS_NO_CONNECTION;
    }
    char server_host[256] = {0};
    int server_port = 25575; // Default port
    char trailing_character;
    int parsed = sscanf(destination, "server://%255[^:]:%d%c", server_host,
                        &server_port, &trailing_character);
    const char *destination_address = destination + sizeof("server://") - 1U;
    bool has_port = strchr(destination_address, ':') != NULL;
    if (parsed < 1 || parsed > 2 || (has_port && parsed != 2) ||
        server_port <= 0 || server_port > 65535) {
        QKD_DBG_ERR("Invalid destination URI format: %s", destination);
        if (status) {
            *status = QKD_STATUS_NO_CONNECTION;
        }
        return QKD_STATUS_NO_CONNECTION;
    }

    // Call connect() method on the Python client
    PyObject *py_connect_method =
        PyObject_GetAttrString(py_qkd_client_instance, "connect");
    if (!py_connect_method || !PyCallable_Check(py_connect_method)) {
        PyErr_Print();
        Py_XDECREF(py_connect_method);
        if (status) {
            *status = QKD_STATUS_NO_CONNECTION;
        }
        return QKD_STATUS_NO_CONNECTION;
    }

    PyObject *py_host = PyUnicode_FromString(server_host);
    PyObject *py_port = PyLong_FromLong(server_port);
    PyObject *py_args = NULL;
    if (py_host && py_port)
        py_args = PyTuple_Pack(2, py_host, py_port);
    Py_XDECREF(py_host);
    Py_XDECREF(py_port);
    if (!py_args) {
        PyErr_Print();
        Py_DECREF(py_connect_method);
        *status = QKD_STATUS_NO_CONNECTION;
        return QKD_STATUS_NO_CONNECTION;
    }

    PyObject *py_connect_result =
        PyObject_CallObject(py_connect_method, py_args);
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

    // CRITICAL FIX: Convert the input key_stream_id to a Python UUID object
    PyObject *py_key_stream_id = NULL;

    // Check if key_stream_id is all zeros (null UUID)
    bool is_null_uuid = true;
    for (int i = 0; i < QKD_KSID_SIZE; i++) {
        if (key_stream_id[i] != 0) {
            is_null_uuid = false;
            break;
        }
    }

    if (is_null_uuid) {
        // Alice case: pass None to request a new KSID
        py_key_stream_id = Py_None;
        Py_INCREF(Py_None);
        QKD_DBG_INFO(
            "Passing None to Python client (Alice case - new session)");
    } else {
        py_key_stream_id = uuid_from_bytes(key_stream_id);

        if (!py_key_stream_id) {
            PyErr_Print();
            if (status) {
                *status = QKD_STATUS_NO_CONNECTION;
            }
            return QKD_STATUS_NO_CONNECTION;
        }

        PyObject *py_uuid_str = PyObject_Str(py_key_stream_id);
        if (py_uuid_str) {
            const char *uuid_string = PyUnicode_AsUTF8(py_uuid_str);
            if (uuid_string) {
                QKD_DBG_INFO(
                    "Passing Alice's UUID to Python client (Bob case): %s",
                    uuid_string);
            }
            Py_DECREF(py_uuid_str);
        }
    }

    // Call open_connect() method on the Python client
    PyObject *py_open_connect_method =
        PyObject_GetAttrString(py_qkd_client_instance, "open_connect");
    if (!py_open_connect_method || !PyCallable_Check(py_open_connect_method)) {
        PyErr_Print();
        Py_XDECREF(py_open_connect_method);
        Py_DECREF(py_key_stream_id);
        if (status) {
            *status = QKD_STATUS_NO_CONNECTION;
        }
        return QKD_STATUS_NO_CONNECTION;
    }

    // Python signature: open_connect(self, source_uri, dest_uri, qos=None,
    // key_stream_id=None)
    PyObject *py_source = PyUnicode_FromString(source);
    PyObject *py_destination = PyUnicode_FromString(destination);
    py_args = NULL;
    if (py_source && py_destination)
        py_args = PyTuple_Pack(4, py_source, py_destination, Py_None,
                               py_key_stream_id);
    Py_XDECREF(py_source);
    Py_XDECREF(py_destination);
    Py_DECREF(py_key_stream_id);
    if (!py_args) {
        PyErr_Print();
        Py_DECREF(py_open_connect_method);
        *status = QKD_STATUS_NO_CONNECTION;
        return QKD_STATUS_NO_CONNECTION;
    }

    QKD_DBG_INFO("Calling Python open_connect with 4 parameters (source, dest, "
                 "qos=None, key_stream_id)");

    PyObject *py_open_connect_result =
        PyObject_CallObject(py_open_connect_method, py_args);
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
        PyObject *py_key_stream_id_result =
            PyTuple_GetItem(py_open_connect_result, 1);
        PyObject *py_status_obj = PyTuple_GetItem(py_open_connect_result, 2);

        // Extract status value
        python_to_uint32(py_status_obj, &status_value);
        QKD_DBG_INFO("Status value extracted from tuple: %u", status_value);

        // Update QoS from returned values
        if (py_returned_qos && PyDict_Check(py_returned_qos)) {
            if (!convert_python_to_qos(py_returned_qos, qos))
                status_value = QKD_STATUS_NO_CONNECTION;
            else {
                QKD_DBG_INFO("QoS updated from returned values");
            }
        }

        // Process key_stream_id if status is success or QoS_NOT_MET
        if ((status_value == QKD_STATUS_SUCCESS ||
             status_value == QKD_STATUS_QOS_NOT_MET ||
             status_value == QKD_STATUS_PEER_NOT_CONNECTED) &&
            py_key_stream_id_result && py_key_stream_id_result != Py_None) {

            // Get the bytes attribute of the UUID
            PyObject *py_bytes =
                PyObject_GetAttrString(py_key_stream_id_result, "bytes");
            if (py_bytes && PyBytes_Check(py_bytes) &&
                PyBytes_Size(py_bytes) == QKD_KSID_SIZE) {
                // Copy the UUID bytes to the output buffer
                memcpy(key_stream_id, PyBytes_AsString(py_bytes),
                       QKD_KSID_SIZE);
                QKD_DBG_INFO("Key stream ID extracted successfully");

                Py_DECREF(py_bytes);
            } else {
                Py_XDECREF(py_bytes);
                PyErr_Clear();

                QKD_DBG_ERR("Failed to extract key stream ID bytes from server "
                            "response");

                if (is_null_uuid) {
                    memset(key_stream_id, 0, QKD_KSID_SIZE);
                }
            }
        } else {
            // No valid key stream ID or status not successful
            if (is_null_uuid) {
                memset(key_stream_id, 0, QKD_KSID_SIZE);
            }
            QKD_DBG_INFO(
                "Key stream ID not available or status not successful");
        }
    } else {
        // Tuple doesn't have enough elements
        QKD_DBG_ERR(
            "Python open_connect returned tuple with insufficient elements");
        if (is_null_uuid) {
            memset(key_stream_id, 0, QKD_KSID_SIZE);
        }
    }

    PyObject *py_updated_qos =
        PyObject_GetAttrString(py_qkd_client_instance, "qos");
    if (py_updated_qos && PyDict_Check(py_updated_qos)) {
        if (!convert_python_to_qos(py_updated_qos, qos))
            status_value = QKD_STATUS_NO_CONNECTION;
        else {
            QKD_DBG_INFO("QoS updated from client instance");
        }
        Py_DECREF(py_updated_qos);
    }

    Py_DECREF(py_open_connect_result);

    // Set the status parameter
    if (status) {
        *status = status_value;
        QKD_DBG_INFO("Setting output status parameter to %u", status_value);
    }

    // Return the status value
    QKD_DBG_INFO("Returning status value %u from open_connect", status_value);
    return status_value;
}

// Backend implementation for GET_KEY
static uint32_t python_client_get_key(const unsigned char *key_stream_id,
                                      uint32_t *index,
                                      unsigned char *key_buffer,
                                      struct qkd_metadata_s *metadata,
                                      uint32_t *status) {
    if (!key_stream_id || !index || !key_buffer || !status)
        return QKD_STATUS_NO_CONNECTION;

    if (!py_qkd_client_instance) {
        if (status) {
            *status = QKD_STATUS_NO_CONNECTION;
        }
        return QKD_STATUS_NO_CONNECTION;
    }

    // Call get_key() method on the Python client
    PyObject *py_get_key_method =
        PyObject_GetAttrString(py_qkd_client_instance, "get_key");
    if (!py_get_key_method || !PyCallable_Check(py_get_key_method)) {
        PyErr_Print();
        Py_XDECREF(py_get_key_method);
        if (status) {
            *status = QKD_STATUS_NO_CONNECTION;
        }
        return QKD_STATUS_NO_CONNECTION;
    }

    PyObject *py_uuid = uuid_from_bytes(key_stream_id);

    if (!py_uuid) {
        PyErr_Print();
        Py_XDECREF(py_get_key_method);
        if (status) {
            *status = QKD_STATUS_NO_CONNECTION;
        }
        return QKD_STATUS_NO_CONNECTION;
    }

    // Create substantial JSON string for metadata
    const char *json =
        "{\"format\":\"json\",\"version\":\"1.0\",\"source\":\"qkd_client\"}";
    size_t json_len = strlen(json);

    if (metadata && metadata->Metadata_size > 0 &&
        (!metadata->Metadata_buffer || json_len >= metadata->Metadata_size)) {
        metadata->Metadata_size = (uint32_t)json_len + 1U;
        Py_DECREF(py_uuid);
        Py_DECREF(py_get_key_method);
        *status = QKD_STATUS_METADATA_SIZE_INSUFFICIENT;
        return QKD_STATUS_METADATA_SIZE_INSUFFICIENT;
    }

    // The Python client expects metadata request information as bytes. Pass
    // only initialized bytes, never the full capacity of the caller's buffer.
    const char *metadata_data = "";
    Py_ssize_t metadata_size = 0;
    if (metadata && metadata->Metadata_size > 0) {
        metadata_data = json;
        metadata_size = (Py_ssize_t)json_len;
    }
    PyObject *py_metadata_bytes =
        PyBytes_FromStringAndSize(metadata_data, metadata_size);
    PyObject *py_index = PyLong_FromUnsignedLong(*index);
    PyObject *py_args = NULL;
    if (py_metadata_bytes && py_index)
        py_args = PyTuple_Pack(3, py_uuid, py_index, py_metadata_bytes);
    Py_DECREF(py_uuid);
    Py_XDECREF(py_index);
    Py_XDECREF(py_metadata_bytes);
    if (!py_args) {
        PyErr_Print();
        Py_DECREF(py_get_key_method);
        *status = QKD_STATUS_NO_CONNECTION;
        return QKD_STATUS_NO_CONNECTION;
    }

    PyObject *py_get_key_result =
        PyObject_CallObject(py_get_key_method, py_args);
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

    if (PyTuple_Size(py_get_key_result) < 3 ||
        !PyLong_Check(PyTuple_GetItem(py_get_key_result, 0))) {
        Py_DECREF(py_get_key_result);
        *status = QKD_STATUS_NO_CONNECTION;
        return QKD_STATUS_NO_CONNECTION;
    }

    // Extract status, key_material, and metadata from the result tuple
    PyObject *py_status = PyTuple_GetItem(py_get_key_result, 0);
    uint32_t status_value = QKD_STATUS_NO_CONNECTION;
    python_to_uint32(py_status, &status_value);

    if (status_value == QKD_STATUS_SUCCESS) {
        PyObject *py_key_material = PyTuple_GetItem(py_get_key_result, 1);
        if (!py_key_material || !PyBytes_Check(py_key_material) ||
            PyBytes_Size(py_key_material) != QKD_KEY_SIZE)
            status_value = QKD_STATUS_INSUFFICIENT_KEY;

        PyObject *py_metadata = PyTuple_GetItem(py_get_key_result, 2);
        if (status_value == QKD_STATUS_SUCCESS && metadata &&
            metadata->Metadata_size > 0) {
            if (!py_metadata || !PyUnicode_Check(py_metadata)) {
                status_value = QKD_STATUS_NO_CONNECTION;
            } else {
                const char *metadata_str = PyUnicode_AsUTF8(py_metadata);
                if (!metadata_str) {
                    PyErr_Clear();
                    status_value = QKD_STATUS_NO_CONNECTION;
                } else {
                    size_t metadata_len = strlen(metadata_str);

                    if (!metadata->Metadata_buffer ||
                        metadata_len >= metadata->Metadata_size) {
                        metadata->Metadata_size = (uint32_t)metadata_len + 1U;
                        status_value = QKD_STATUS_METADATA_SIZE_INSUFFICIENT;
                    } else {
                        memcpy(metadata->Metadata_buffer, metadata_str,
                               metadata_len + 1U);
                        metadata->Metadata_size = (uint32_t)metadata_len;
                    }
                }
            }
        }

        if (status_value == QKD_STATUS_SUCCESS)
            memcpy(key_buffer, PyBytes_AsString(py_key_material), QKD_KEY_SIZE);
    }

    Py_DECREF(py_get_key_result);

    if (status) {
        *status = status_value;
    }
    return status_value;
}

// Backend implementation for CLOSE
static uint32_t python_client_close(const unsigned char *key_stream_id,
                                    uint32_t *status) {
    if (!key_stream_id || !status)
        return QKD_STATUS_NO_CONNECTION;

    if (!py_qkd_client_instance) {
        if (status) {
            *status = QKD_STATUS_NO_CONNECTION;
        }
        return QKD_STATUS_NO_CONNECTION;
    }

    // Call close() method on the Python client
    PyObject *py_close_method =
        PyObject_GetAttrString(py_qkd_client_instance, "close");
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
    if (PyLong_Check(py_close_result) &&
        !python_to_uint32(py_close_result, &status_value))
        status_value = QKD_STATUS_NO_CONNECTION;
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
    .close = python_client_close};
