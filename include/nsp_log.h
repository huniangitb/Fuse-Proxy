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

/* 级别 ↔ 名称（DEBUG/INFO/WARN/ERROR）——唯一出处：落盘 sys.log/io.log 行、
   `search-sys` 查询输出与流式推送统一渲染为名称，排查时可直接 grep/肉眼定位，
   不必记 `|0|..|3|` 的映射。实现见 src/core/nsp_util.c（纯 libc，模块可链接）。
   越界值（通道标记 LOG_IO 等）一律回退 "INFO"。 */
const char* nsp_log_level_name(int level);
/* 名称 → 级别；无法识别返回 -1。兼容旧落盘行的纯数字等级，**不得**退化成
   atoi——名字会被静默当 0=DEBUG，与 log_ctl 的 --level 词法属同一类坑。 */
int nsp_log_level_parse(const char* name);

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
