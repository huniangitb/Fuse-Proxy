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

/* 配置根目录：Android 用 /data/Namespace-Proxy；GNU 用 /var/fuse-proxy
   （GNU 无 /data，日志/配置/模块默认路径须可写） */
#ifdef TARGET_ANDROID
#define CONFIG_DIR "/data/Namespace-Proxy"
#else
#define CONFIG_DIR "/var/fuse-proxy"
#endif
#define LOG_DIR  CONFIG_DIR "/log"

/* 编译期受控调试日志：仅当 Meson 传入 -Denable_debug=true（-DDEBUG=1）
   时输出到 stderr（测试重定向的 fuse.log），生产构建完全消除 */
#ifdef DEBUG
#define FTP_DBG(...) fprintf(stderr, "[FTP-DBG] " __VA_ARGS__)
#else
#define FTP_DBG(...) do { } while (0)
#endif
#define ERROR_LOG_PATH LOG_DIR "/error.log"
#define INJECTOR_CONFIG_PATH CONFIG_DIR "/injector.conf"
#define MONITOR_IGNORE_PATH CONFIG_DIR "/monitor_ignore.conf"
#define APP_RULES_DIR CONFIG_DIR "/App-rules"
#define INJECTOR_PID_PATH CONFIG_DIR "/injector.pid"
/* 热插拔模块目录：模块 = 一个子目录，内含 <name>.so（规则/后端模块）与可选配置 */
#ifdef TARGET_ANDROID
#define MODULES_DIR CONFIG_DIR "/modules"
#else
#define MODULES_DIR "/var/fuse-proxy/modules"
#endif

// STORAGE_BASE: FUSE 内部读写使用的真实物理存储根目录
#ifdef TARGET_ANDROID
#define STORAGE_BASE "/data/media"
#define BACKUP_DIR CONFIG_DIR "/nsp_backup"
#define MODULES_ROOT "/data/adb/modules"
#else
#define STORAGE_BASE "/var/fuse-proxy/storage"
#define BACKUP_DIR "/var/fuse-proxy/backup"
#define MODULES_ROOT "/etc/fuse-proxy/modules"
#endif
#define REAL_STORAGE_PATH STORAGE_BASE
#define LOG_SOCKET_NAME "nsp_log_socket"
#define IPC_SOCKET_NAME "nsp_ipc_socket"
#define CONFIG_BROADCAST_SOCKET "nsp_config_broadcast"
#define RULE_SOCKET_NAME "nsp_rule_socket"
/* 全局替换式挂载方案（--global-replace）的备份根目录：位于项目配置路径下 */
#define GLOBAL_BACKUP_ROOT BACKUP_DIR "/global_emulated"

typedef enum {
    LOG_DEBUG   = 0,
    LOG_INFO    = 1,
    LOG_WARN    = 2,
    LOG_ERROR   = 3,
    /* 通道标记：使用高位段避免与严重级别 0~3 冲突，g_min_log_level 比较时只看 0~3 */
    LOG_MONITOR = 0x80,
    LOG_IO      = 0x81,
    LOG_LOGCAT  = 0x82
} LogLevel;

extern LogLevel g_min_log_level;
extern bool g_persist_all_logs;
extern char g_real_root[PATH_MAX];
extern bool g_strip_o_direct;
extern _Atomic(bool) g_log_shutdown;  
/* 子进程日志转发 fd：run_in_mnt_ns_* fork 的子进程内环形缓冲/sender 线程
   不可达（fork 不复制线程），经此管道把子进程日志回传父进程统一入缓冲 */
extern int g_log_forward_fd;

void log_init(const char* process_name);
void log_close();
void log_internal(LogLevel level, const char* format, ...);
void log_internal_ext(LogLevel level, const char* proc_name_override, const char* format, ...);
char* get_self_dir();
void set_self_dir(const char* path);
int mkdir_recursive(const char *dir);
int mkdir_recursive_p(const char *path, mode_t mode);
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