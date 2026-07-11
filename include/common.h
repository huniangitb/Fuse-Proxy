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
#define STORAGE_BASE "/data/media"

#define BACKUP_DIR "/data/local/tmp/nsp_backup"
#define REAL_STORAGE_PATH STORAGE_BASE
#define MODULES_ROOT "/data/adb/modules"
#define LOG_SOCKET_NAME "nsp_log_socket"
#define IPC_SOCKET_NAME "nsp_ipc_socket"
#define CONFIG_BROADCAST_SOCKET "nsp_config_broadcast"

typedef enum {
    LOG_DEBUG   = 0,
    LOG_INFO    = 1,
    LOG_WARN    = 2,
    LOG_ERROR   = 3,
    LOG_MONITOR = 0,
    LOG_IO      = 100,
    LOG_LOGCAT  = 101
} LogLevel;

extern LogLevel g_min_log_level;
extern bool g_persist_all_logs;
extern char g_real_root[PATH_MAX];
extern bool g_strip_o_direct;  

void log_init(const char* process_name);
void log_close();
void log_internal(LogLevel level, const char* format, ...);
void log_internal_ext(LogLevel level, const char* proc_name_override, const char* format, ...);
char* get_self_dir();
void set_self_dir(const char* path);
int mkdir_recursive(const char *dir);
int send_ipc_message(const char* message);
int query_ipc_message(const char* command, char* out_buf, size_t buf_size);
void escape_cgroup();
void persist_log_to_disk(const char* log_type, const char* message, bool append_timestamp);
void start_logcat_capture();
void stop_logcat_capture();

#define LOG_DBG(format, ...) log_internal(LOG_DEBUG, format "\n" __VA_OPT__(,) __VA_ARGS__)
#define LOG_DBG_PERF(format, ...) do { if (g_min_log_level == LOG_DEBUG) log_internal(LOG_DEBUG, format "\n" __VA_OPT__(,) __VA_ARGS__); } while (0)
#define LOG(format, ...)     log_internal(LOG_INFO, format "\n" __VA_OPT__(,) __VA_ARGS__)
#define LOG_WRN(format, ...) log_internal(LOG_WARN, format "\n" __VA_OPT__(,) __VA_ARGS__)
#define LOG_ERR(format, ...) log_internal(LOG_ERROR, format "\n" __VA_OPT__(,) __VA_ARGS__)
#define PERROR(msg) LOG_ERR("%s: %s", msg, strerror(errno))

void common_cleanup();
void init_timezone();
bool path_contains_invalid_chars(const char* path);
void path_sanitize(char* out, size_t size, const char* path);

#endif