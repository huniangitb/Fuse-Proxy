#ifndef INJECT_TARGET_H
#define INJECT_TARGET_H

#include <sys/types.h>
#include "config_parser.h"

bool is_isolated_uid(uid_t uid);
bool is_system_app(uid_t uid);
bool is_system_app_by_pkg(const char* cmdline, uid_t uid);
void init_system_pkg_cache(void);
void cleanup_system_pkg_cache(void);
bool is_process_safe_to_inject(const char* cmdline);
/* is_media_provider 的权威声明在 common.h（architecture.md §7），此处不再重复 */
bool is_target_app(const char* cmdline, uid_t uid, pid_t pid, bool from_ipc);
/* 已持锁版本：调用方需确保已通过 config_lock_read() 获取配置锁 */
bool is_target_app_locked(const char* cmdline, uid_t uid, pid_t pid, bool from_ipc);
uid_t get_app_uid(int pid);
void update_uid_map(uid_t uid, const char* pkg);
void get_target_storage_path(uid_t uid, char* path, size_t size);
void add_tracked(int pid);
bool is_tracked(int pid);
void remove_tracked(int pid);
/* 注入状态稳定公共函数：add_tracked 仅表示已跟踪（含还原的非目标应用），
   是否确实已注入由显式标志维护——注入成功路径调 mark_injected，
   还原/卸载路径调 unmark_injected，list-injected/快照经 is_injected 判定，
   不再依赖 mountinfo 挂载状态探测（GLOBAL_INJECT 下探测不可靠） */
void mark_injected(int pid);
void unmark_injected(int pid);
bool is_injected(int pid);
/* 生命周期清理：清除已退出应用的追踪缓存（被动模式由 IPC 通知路径触发） */
void cleanup_stale_tracked(void);
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
/* 配置热对账（v1）：每次配置重载后对运行中应用逐 pid 比对「期望视图 vs 实测视图」，
   热挂载缺失的、热卸载多余的。覆盖 reload_config_rules_diff 判不出差异的变更
   （规则内容变化、类别段与 App-rules 子文件增删）。 */
void audit_running_apps(void);
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
 * 核心检查：判断当前配置中 com.android.providers.media.module 是否为注入目标对象。
 */
bool is_media_module_injected_target(void);

#endif