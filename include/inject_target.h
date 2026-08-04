#ifndef INJECT_TARGET_H
#define INJECT_TARGET_H

#include <sys/types.h>
#include "config_parser.h"
#include "uid_map.h"

bool is_isolated_uid(uid_t uid);
bool is_system_app(uid_t uid);
bool is_system_app_by_pkg(const char* cmdline, uid_t uid);
void init_system_pkg_cache(void);
void cleanup_system_pkg_cache(void);
bool is_process_safe_to_inject(const char* cmdline);
bool is_media_provider(const char* pkg);
bool is_target_app(const char* cmdline, uid_t uid, pid_t pid, bool from_ipc);
/* 已持锁版本：调用方需确保已通过 config_lock_read() 获取配置锁 */
bool is_target_app_locked(const char* cmdline, uid_t uid, pid_t pid, bool from_ipc);
uid_t get_app_uid(int pid);
void update_uid_map(uid_t uid, const char* pkg);
void get_target_storage_path(uid_t uid, char* path, size_t size);
void add_tracked(int pid);
bool is_tracked(int pid);
void remove_tracked(int pid);
/*
 * 全量应用 PID 缓存（非被动模式每次扫描刷新，含已停用/未追踪应用）。
 * 目的：规则变化（如某应用重新启用）时快速定位运行中的 pid 立即挂载，
 * 无需等待应用重启或下一次扫描。
 */
void all_apps_upsert(int pid, uid_t uid, const char* cmdline);
bool all_apps_find_by_cmdline(const char* pkg, int* pid_out, uid_t* uid_out);
void all_apps_prune(void);
void all_apps_cleanup(void);
void audit_tracked_apps();
void audit_and_remount_specific_apps(ChangedPkg* changed, int count);
void force_recover_tracked_mounts();
void handle_list_injected(int client_fd);
/* 
 * 初始化从物理文件恢复的 UID 映射内存缓存。
 * 避免在每次程序重新启动时丢失已持久化的 UID 记录。
 */
void init_uid_map_cache(void);
/*
 * 通用的应用挂载清理/恢复操作：
 * 1. 尝试卸载 target_path 上的 FUSE 挂载
 * 2. 尝试卸载 backup_path 上的 FUSE 挂载
 * 3. 如果 backup_path 存在，移动到 target_path
 * 4. 否则从 /proc/1/root 做 bind mount 恢复
 */
void cleanup_app_mounts(int pid, const char* target_path, const char* backup_path, uid_t uid);
/*
 * 获取当前所有已注入应用列表的快照。
 * 填充 pid、pkg、uid 数组，返回实际填充数量。
 * 用于外部模块（如 config_publisher）读取注入状态。
 */
int get_injected_snapshot(int *out_pids, char (*out_pkgs)[256], uid_t *out_uids, int max_count);
/*
 * 获取 UID 映射表的快照。
 * 基于 inject_target 内部的内存缓存。
 */
int get_uid_map_snapshot(UidMapEntry *out, int max_count);

/*
 * 核心检查：判断当前配置中 com.android.providers.media.module 是否为注入目标对象。
 */
bool is_media_module_injected_target(void);

#endif