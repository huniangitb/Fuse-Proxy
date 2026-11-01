#ifndef COMMON_H
#define COMMON_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "nsp_comm.h"
#include "nsp_constants.h"
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

#define CONFIG_DIR   NSP_CONFIG_DIR
#define STORAGE_BASE NSP_STORAGE_BASE
#define LOG_DIR      NSP_LOG_DIR

/* 编译期受控调试日志：仅当 Meson 传入 -Denable_debug=true（-DDEBUG=1）
   时输出到 stderr（测试重定向的 fuse.log），生产构建完全消除 */
#ifdef DEBUG
#define FTP_DBG(...) fprintf(stderr, "[FTP-DBG] " __VA_ARGS__)
#else
#define FTP_DBG(...) \
    do {             \
    } while (0)
#endif
#define ERROR_LOG_PATH       LOG_DIR "/error.log"
#define INJECTOR_CONFIG_PATH CONFIG_DIR "/injector.conf"
#define MONITOR_IGNORE_PATH  CONFIG_DIR "/monitor_ignore.conf"
#define APP_RULES_DIR        CONFIG_DIR "/" NSP_APP_RULES_DIRNAME
#define INJECTOR_PID_PATH    CONFIG_DIR "/injector.pid"
/* 热插拔模块目录：模块 = 一个子目录，内含 <name>.so（规则/后端模块）与可选配置 */
#define MODULES_DIR CONFIG_DIR "/modules"

// STORAGE_BASE: FUSE 内部读写使用的真实物理存储根目录
#ifdef TARGET_ANDROID
#define BACKUP_DIR   CONFIG_DIR "/nsp_backup"
#define MODULES_ROOT "/data/adb/modules"
#else
#define BACKUP_DIR   "/var/fuse-proxy/backup"
#define MODULES_ROOT "/etc/fuse-proxy/modules"
#endif
#define REAL_STORAGE_PATH       STORAGE_BASE
#define LOG_SOCKET_NAME         "nsp_log_socket"
#define IPC_SOCKET_NAME         "nsp_ipc_socket"
#define CONFIG_BROADCAST_SOCKET "nsp_config_broadcast"
#define RULE_SOCKET_NAME        "nsp_rule_socket"
/* 全局替换式挂载方案（注入方法 v2/v3）的备份根目录：位于项目配置路径下 */
#define GLOBAL_BACKUP_ROOT BACKUP_DIR "/global_emulated"

#include "nsp_log.h"

/* 日志合并周期：batch_begin/batch_end 配对，期间 log_internal 将日志累积
   到批量缓冲（不逐条写环形缓冲），batch_end 时把整个周期的日志合并为
   单条写入，前端最终只显示一条日志（多个发送请求并入一个日志）。
   原子嵌套计数 + 互斥锁，不阻塞日志路径 */
void log_batch_begin(void);
void log_batch_end(void);
extern bool g_persist_all_logs;
extern char g_real_root[PATH_MAX];
extern bool g_strip_o_direct;
extern _Atomic(bool) g_log_shutdown;
/* 子进程日志转发 fd：run_in_mnt_ns_* fork 的子进程内环形缓冲/sender 线程
   不可达（fork 不复制线程），经此管道把子进程日志回传父进程统一入缓冲 */
extern int g_log_forward_fd;

void log_init(const char* process_name);
void log_close();
char* get_self_dir();
void set_self_dir(const char* path);
int mkdir_recursive(const char* dir);
int mkdir_recursive_p(const char* path, mode_t mode);
/* 读取整个文件到堆内存（动态扩容，尾随 NUL）。失败返回 NULL（max_size 超限时
   errno=EFBIG）。max_size > 0 时超过该上限即失败；0 表不限制。
   公共工具：injector 的 mount_manager/ns_utils 与 config_publisher 共用。 */
char* read_file_dynamic(const char* path, size_t* out_size, size_t max_size);
/* 发后即忘 IPC 一律 nsp_comm_post(NSP_CH_IPC, …)（见 nsp_comm.h），
   旧 send_ipc_message 同步直发已删除；query_ipc_message 零调用已删除 */
void escape_cgroup();
void persist_log_to_disk(const char* log_type, const char* message, bool append_timestamp);

/* 存储路径合成统一出口（替代各处手写 STORAGE_BASE "/%d" snprintf）：
 * common_default_real_path：默认真实路径（sub_path 含前导 '/'，user_id<0 表无用户层）；
 * common_storage_root：用户存储根（STORAGE_BASE/<uid>，vfs 权限继承用）；
 *   两者保持 void 签名（模块 ABI），放不下时写空串失败闭合（调用方以 ENOENT
 *   失败，永不读写截断出的错误路径）；
 * common_sandbox_path：沙盒目标（STORAGE_BASE/<uid>/Android/data/<pkg>/<沙盒目录名>，
 *   目录名默认 NSP_SANDBOX_DIRNAME "sandbox"，经 common_set_sandbox_dirname
 *   由配置发布单点覆盖），
 *   成功返回 0，输入非法或输出放不下返回 -1（调用方自行日志并放弃重定向）；
 * common_view_path：**存储视图路径**（应用看到的绝对路径
 *   NSP_ANDROID_EMULATED_ROOT/<user_id><sub_path>）——事件的 spath 与 QUERY
 *   响应的 spath 都由它合成（喂 MediaProvider 扫描的唯一路径域），禁止各处
 *   裸拼 "/storage/emulated"。注意与 common_default_real_path 的差别：后者是
 *   真实落盘路径（受 --root 测试根影响），本函数恒为**视图**口径，不受
 *   g_real_root 影响（测试根是 daemon 的内部实现细节，应用永远看不到）。 */
void common_default_real_path(int user_id, const char* sub_path, char* out, size_t sz);
void common_storage_root(int user_id, char* out, size_t sz);
int common_sandbox_path(int uid, const char* pkg, char* out, size_t sz);
void common_view_path(int user_id, const char* sub_path, char* out, size_t sz);
/* common_fuse_user_path：FUSE 视角路径（"/<user_id><sub_path>"）——common_parse_user_layer
 * 的逆运算，供事件通道把 QUERY 的绝对 spath 反解结果交回 fw_acl_check/fw_rules_resolve
 * （两者的 path 入参都是 FUSE 视角层级）。放不下返回 -1 且**不截断**：截断会让判定
 * 作用在另一个路径上（"/0/Android/data/x" 截成 "/0/Android/da" 就是另一条规则）。 */
int common_fuse_user_path(int user_id, const char* sub_path, char* out, size_t sz);
void common_set_sandbox_dirname(const char* name);
/* 媒体 Provider 判定（common.c 实现；inject_target.h 亦有兼容声明） */
bool is_media_provider(const char* pkg);
/* comm 拥塞上报（common.c 实现）：供各进程 BCAST 等后端复用为 report 钩子 */
void nsp_log_report(nsp_ch_t ch, uint64_t n, void* ctx);
void init_timezone();
bool path_contains_invalid_chars(const char* path);
void path_sanitize(char* out, size_t size, const char* path);

/* ---- 存储根一级条目守卫（历史缺陷：/data/media 顶层反复出现纯数字垃圾目录）----
 * 一级条目 = <有效存储根>/<单个组件>（用户存储根 0/10/… 与 obb），由 vold 掌管，
 * 系统视图里对普通应用不可写。框架的 FUSE 以 root 执行 mkdir/open(O_CREAT)/
 * rename：一旦放行，任意被注入的应用都能替 root 在 /data/media 顶层造出条目。
 * 实测形态即「应用请求 /<数字>/… → 框架把数字当 user_id → 递归补建父目录时把
 * <STORAGE_BASE>/<数字> 造出来」，此后该垃圾目录被当成真实用户目录反复使用。
 * 三个出口统一在此（禁止各回调私刻判定）：
 *   common_storage_base        —— 有效存储根（g_real_root 优先，否则 STORAGE_BASE）；
 *   common_is_storage_root_entry —— real_path 是否恰为一级条目（其后无 '/'）；
 *   common_mkdir_within_storage  —— 建父目录的唯一出口：**永不创建**一级组件，
 *                                   一级组件缺失即失败（errno=ENOENT），非存储根
 *                                   路径（FTP 目标等）沿用 mkdir_recursive_p 语义。 */
void common_storage_base(char* out, size_t sz);
bool common_is_storage_root_entry(const char* real_path);
int common_mkdir_within_storage(const char* dir, mode_t mode);

/* FUSE 路径 <uid>/ 用户层解析（fw_parse_path 与 br_strip_and_sanitize 的唯一实现）：
   1=命中（*user_id / *sub_path 有效）、0=无用户层（*sub_path 指回原路径）、
   -1=非法（数字串溢出 int 的 atoi 别名，调用方须 fail-closed 返回 ENOENT）。 */
int common_parse_user_layer(const char* path, int* user_id, const char** sub_path);

#endif