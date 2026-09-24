/* SPDX-License-Identifier: GPL-3.0-or-later WITH Fuse-Proxy-module-exception */
#ifndef NSP_LOG_H
#define NSP_LOG_H

#include <errno.h>
#include <string.h>

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3,
    /* 通道标记不参与严重级别过滤。 */
    LOG_MONITOR = 0x80,
    LOG_IO = 0x81,
    LOG_LOGCAT = 0x82
} LogLevel;

extern LogLevel g_min_log_level;
void log_internal(LogLevel level, const char* format, ...);

#define LOG_DBG(format, ...) log_internal(LOG_DEBUG, format "\n" __VA_OPT__(, ) __VA_ARGS__)
#define LOG_DBG_PERF(format, ...)                                            \
    do {                                                                     \
        if (g_min_log_level == LOG_DEBUG)                                    \
            log_internal(LOG_DEBUG, format "\n" __VA_OPT__(, ) __VA_ARGS__); \
    } while (0)
#define LOG(format, ...)     log_internal(LOG_INFO, format "\n" __VA_OPT__(, ) __VA_ARGS__)
#define LOG_WRN(format, ...) log_internal(LOG_WARN, format "\n" __VA_OPT__(, ) __VA_ARGS__)
#define LOG_ERR(format, ...) log_internal(LOG_ERROR, format "\n" __VA_OPT__(, ) __VA_ARGS__)
#define PERROR(msg)          LOG_ERR("%s: %s", msg, strerror(errno))

#define NSP_LOG_DBG      LOG_DBG
#define NSP_LOG_DBG_PERF LOG_DBG_PERF
#define NSP_LOG          LOG
#define NSP_LOG_WRN      LOG_WRN
#define NSP_LOG_ERR      LOG_ERR
#define NSP_PERROR       PERROR

#endif
