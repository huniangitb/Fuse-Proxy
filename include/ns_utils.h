#ifndef NS_UTILS_H
#define NS_UTILS_H

#include <limits.h>
#include <sys/types.h>

/* 绑定挂载 */
int ns_bind_mount(int pid, const char* source, const char* target);

/* 递归卸载 */
int ns_umount_recursive(int pid, const char* target);

/* 卸载并删除目录 */
int ns_umount_and_rmdir(int pid, const char* target);

/* 检查是否已挂载 */
int ns_is_mounted(int pid, const char* target_mount, const char* match_fs_name);

/* 设置挂载点为共享 */
int ns_make_shared(int pid, const char* target);

/* 移动挂载 */
int ns_move_mount(int pid, const char* source, const char* target);

/* 查找原生子挂载点 */
int ns_find_native_submounts(int pid, const char* base_path,
                              char mount_points[][256], int max_count);

/* 带保留路径的绑定挂载 */
int ns_bind_mount_with_preserve(int pid, const char* source, const char* target,
                                 char preserve_paths[][256], int preserve_count);

/* 调试日志：在目标进程命名空间内查询并记录 /storage/emulated 的挂载状态 */
int ns_debug_log_mounts(int pid, const char* pkg, const char* stage);

/*
 * 备份并卸载系统原生的 /dev/fuse（位于 /storage/emulated 底层），
 * 仅在确认 fuse_daemon 已处于顶层挂载后调用。
 * backup_path: 备份目标路径（如 /mnt/backup/system_fuse）
 * mnt_ns_pid: 目标命名空间 PID（通常为 1）
 * fuse_src:   fuse_daemon 的挂载源路径（如 /mnt/nsp_global）
 *
 * 返回值: 0=成功, -1=未找到系统 FUSE 挂载, -2=操作失败
 */
int ns_backup_and_remove_system_fuse(int mnt_ns_pid, const char* fuse_src, const char* backup_path);

/*
 * 从备份恢复系统 FUSE 挂载（用于 fuse_daemon 崩溃或退出时回退）
 */
int ns_restore_system_fuse(int mnt_ns_pid, const char* fuse_src, const char* backup_path);

/*
 * 合并操作：在单次命名空间切换中完成 清理备份 → 复制目标到备份 → 卸载目标
 * 将三次 fork+setns 合并为一次，显著减少挂载耗时
 */
int ns_backup_and_clear_target(int pid, const char* target, const char* backup);

/*
 * 一键合并命名空间挂载（优化版）：
 * 在单次命名空间切换中完成 清理旧备份 → 备份目标挂载树 → 清理目标原生挂载 → 挂载 FUSE 代理 → 恢复保留路径
 */
int ns_combined_mount(int pid, const char* source, const char* target, const char* backup,
                      char preserve_paths[][256], int preserve_count);

#endif