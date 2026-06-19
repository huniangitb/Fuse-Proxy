#ifndef INJECT_TARGET_H
#define INJECT_TARGET_H

#include <sys/types.h>
#include "config_parser.h"

bool is_isolated_uid(uid_t uid);
bool is_process_safe_to_inject(const char* cmdline);
bool is_target_app(const char* cmdline, uid_t uid, pid_t pid, bool from_ipc);
/* 已持锁版本：调用方需确保已通过 config_lock_read() 获取配置锁 */
bool is_target_app_locked(const char* cmdline, uid_t uid, pid_t pid, bool from_ipc);
uid_t get_app_uid(int pid);
void update_uid_map(uid_t uid, const char* pkg);
void get_target_storage_path(uid_t uid, char* path, size_t size);

void add_tracked(int pid);
bool is_tracked(int pid);
void remove_tracked(int pid);
void audit_tracked_apps();
void audit_and_remount_specific_apps(ChangedPkg* changed, int count);
void force_recover_tracked_mounts();
void handle_list_injected(int client_fd);

/*
 * 通用的应用挂载清理/恢复操作：
 * 1. 尝试卸载 target_path 上的 FUSE 挂载
 * 2. 尝试卸载 backup_path 上的 FUSE 挂载
 * 3. 如果 backup_path 存在，移动到 target_path
 * 4. 否则从 /proc/1/root 做 bind mount 恢复
 */
void cleanup_app_mounts(int pid, const char* target_path, const char* backup_path);

#endif