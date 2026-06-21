#ifndef NS_UTILS_H
#define NS_UTILS_H

#include <limits.h>
#include <sys/types.h>

/* 异步挂载上下文结构体 */
typedef struct {
    int status_pipe_fd;
    pid_t child_pid;
    int target_pid;
    char pkg_name[256];
    void* mount_args; /* 携带 CombinedMountArgs 的指针 */
} MountTaskCtx;

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

/* 阻塞式合并挂载（作为向下兼容） */
int ns_combined_mount(int pid, const char* source, const char* target, const char* backup,
                      char preserve_paths[][256], int preserve_count);

/* 核心优化：高并发非阻塞异步合并挂载 */
int ns_combined_mount_async(int pid, const char* pkg, const char* source, const char* target, const char* backup,
                            char preserve_paths[][256], int preserve_count);

int run_in_mnt_ns_async(int target_pid, const char* pkg, int (*func)(void*), void* args, void* mount_args);

/* 全局注入方案：简洁追加挂载，无备份/恢复逻辑 */
int ns_global_mount_async(int pid, const char* pkg, const char* source, const char* target);

/*
 * 强制卸载陈旧 FUSE 挂载（使用 MNT_DETACH，不依赖 FUSE 守护进程响应），
 * 在启动新 fuse_daemon 前调用，处理 "Transport endpoint is not connected" 场景。
 * target: 挂载路径（如 /mnt/nsp_global）
 */
int ns_force_umount_stale(int pid, const char* target);

#endif /* NS_UTILS_H */
