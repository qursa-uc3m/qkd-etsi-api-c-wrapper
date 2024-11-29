/*
 * Copyright (C) 2024 QURSA Project
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 * - Javier Blanco-Romero (@fj-blanco) - UC3M
 * 
 */

/*
 * include/debug.h
 */

#ifndef LIBQKD_DEBUG_H_
#define LIBQKD_DEBUG_H_

#include <stdio.h>

#if defined(QKD_DEBUG_LEVEL)
    #define QKD_DBG(level, fmt, ...) \
        do { \
            if ((level) <= QKD_DEBUG_LEVEL) { \
                fprintf(stderr, "libqkd: %s:%d: " fmt "\n", \
                    __func__, __LINE__, ##__VA_ARGS__); \
            } \
        } while (0)
    
    #define QKD_DBG_ERR(fmt, ...)   QKD_DBG(1, fmt, ##__VA_ARGS__)
    #define QKD_DBG_WARN(fmt, ...)  QKD_DBG(2, fmt, ##__VA_ARGS__)
    #define QKD_DBG_INFO(fmt, ...)  QKD_DBG(3, fmt, ##__VA_ARGS__)
    #define QKD_DBG_VERB(fmt, ...)  QKD_DBG(4, fmt, ##__VA_ARGS__)
#else
    #define QKD_DBG(level, fmt, ...)
    #define QKD_DBG_ERR(fmt, ...)
    #define QKD_DBG_WARN(fmt, ...)
    #define QKD_DBG_INFO(fmt, ...)
    #define QKD_DBG_VERB(fmt, ...)
#endif

#endif /* LIBQKD_DEBUG_H_ */