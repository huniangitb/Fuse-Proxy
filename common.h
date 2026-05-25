#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/file.h>
#include <pthread.h>
#include <stddef.h>

#define CONFIG_DIR "/data/Namespace-Proxy"
#define LOG_DIR  CONFIG_DIR "/log"
#define ERROR_LOG_PATH LOG_DIR "/error.log"
#define INJECTOR_CONFIG_PATH CONFIG_DIR "/injector.conf"
#define MONITOR_IGNORE_PATH CONFIG_DIR "/monitor_ignore.conf"
#define APP_RULES_DIR CONFIG_DIR "/App-rules"
#define INJECTOR_PID_PATH CONFIG_DIR "/injector.pid"
// STORAGE_BASE: FUSE 内部读写直接使用 /data/media（真实物理存储）
// 应用通过 /mnt/nsp_global/ 或 /storage/emulated/ 访问 FUSE 挂载
#define STORAGE_BASE "/data/media"
#define BACKUP_DIR "/mnt/backup"
#define REAL_STORAGE_PATH STORAGE_BASE
#define MODULES_ROOT "/data/adb/modules"

#define LOG_TCP_PORT 34215
#define IPC_SOCKET_NAME "nsp_ipc_socket"

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_ERROR = 2,
    LOG_MONITOR = 99,
    LOG_IO = 100,
    LOG_LOGCAT = 101
} LogLevel;

extern LogLevel g_min_log_level;
extern int g_persist_all_logs;

// 新增：全局存储根目录
extern char g_real_root[PATH_MAX];

// 兼容模式：剥离 O_DIRECT 标志（由 --strip-o-direct 参数控制）
extern int g_strip_o_direct;

void log_init(const char* process_name);
void log_close(void);
void log_internal(LogLevel level, const char* format, ...);
void log_internal_ext(LogLevel level, const char* proc_name_override, const char* format, ...);

char* get_self_dir(void);
void set_self_dir(const char* path);
int mkdir_recursive(const char *dir);
int send_ipc_message(const char* message);
int query_ipc_message(const char* command, char* out_buf, size_t buf_size);
void escape_cgroup(void);

void persist_log_to_disk(const char* log_type, const char* message, int append_timestamp);
void start_logcat_capture(void);
void stop_logcat_capture(void);

#define LOG_DBG(format, ...) log_internal(LOG_DEBUG, format "\n", ##__VA_ARGS__)
#define LOG(format, ...)     log_internal(LOG_INFO, format "\n", ##__VA_ARGS__)
#define LOG_ERR(format, ...) log_internal(LOG_ERROR, format "\n", ##__VA_ARGS__)
#define LOG_MON(format, ...) log_internal(LOG_MONITOR, format "\n", ##__VA_ARGS__)

#define PERROR(msg) LOG_ERR("%s: %s", msg, strerror(errno))

void common_cleanup(void);

/**
 * 初始化时区：确保 localtime() 能正确转换时区
 */
void init_timezone(void);

/**
 * 检查路径是否包含不可见Unicode字符
 */
int path_contains_invalid_chars(const char* path);

/**
 * 净化路径：去除不可见Unicode字符
 */
void path_sanitize(char* out, size_t size, const char* path);

#endif