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
int ns_combined_mount(int pid, const char* pkg, const char* source, const char* target, const char* backup,
                      char preserve_paths[][256], int preserve_count);

/* 核心优化：高并发非阻塞异步合并挂载 */
int ns_combined_mount_async(int pid, const char* pkg, const char* source, const char* target, const char* backup,
                            char preserve_paths[][256], int preserve_count);

int run_in_mnt_ns_async(int target_pid, const char* pkg, int (*func)(void*), void* args, void* mount_args);

/* 全局注入方案：简洁追加挂载，无备份/恢复逻辑 */
int ns_global_mount_async(int pid, const char* pkg, const char* source, const char* target);

/* 同步版全局挂载：挂载完成才返回，用于 IPC 线程 */
int ns_global_mount(int pid, const char* pkg, const char* source, const char* target);

/*
 * 强制卸载陈旧 FUSE 挂载（使用 MNT_DETACH，不依赖 FUSE 守护进程响应），
 * 在启动新 fuse_daemon 前调用，处理 "Transport endpoint is not connected" 场景。
 * target: 挂载路径（如 /mnt/nsp_global）
 */
int ns_force_umount_stale(int pid, const char* target);

/* ================= 全局替换式挂载方案（注入方法 v2/v3，卸载优先） =================
 * 对应 scripts/global.sh 的 status/replace/restore，但改为 injector 内建能力：
 *  - 替换：在 init 命名空间（pid=1）中，将 installer/androidwritable/user 三族
 *    所有用户的 emulated 族根替换为项目 FUSE 源（fuse_src），使所有应用默认
 *    看到代理视图；仅备份一个族（优先级 user > androidwritable > installer）。
 *  - 恢复：从备份还原三族所有用户的系统视图。
 *  - 应用还原：进入非目标应用命名空间，卸载项目 FUSE 并 bind 回备份视图。
 * 关键约束：目标设备不支持 MS_REC，备份/替换/恢复全部改为逐节点枚举
 * mountinfo 后单个 MS_BIND（父先子后 bind、最深优先 MNT_DETACH 卸载），
 * 确保不遗漏系统子挂载节点（f2fs 直通 data/obb、嵌套跨用户 fuse 视图）。
 */

/* 全局替换状态枚举 */
enum {
    NSP_GLOBAL_STATUS_UNKNOWN   = 0,  /* 未找到任何族根 */
    NSP_GLOBAL_STATUS_NORMAL    = 1,  /* 全部族根均为系统视图 */
    NSP_GLOBAL_STATUS_REPLACED  = 2,  /* 全部族根均为项目 FUSE */
    NSP_GLOBAL_STATUS_MIXED     = 3,  /* 部分替换 */
};

/*
 * 收集 base_path 前缀下的全部挂载点（含自身与子挂载，含嵌套 fuse 视图），
 * 从 /proc/<pid>/mountinfo 读取（无需进入命名空间），返回路径列表。
 * 结果按路径深度降序（最深优先）排列，便于逆序卸载。
 */
int ns_collect_mounts_under(int pid, const char* base_path, int include_self, int include_fuse,
                            char mount_points[][PATH_MAX], int max_count);

/*
 * 在 mnt_ns_pid 命名空间内执行全局替换（对应 global.sh replace）：
 * 仅备份一个族（user > androidwritable > installer）到 backup_root/user_<id>/emulated
 * （逐节点 MS_BIND，不依赖 MS_REC），随后三族全部替换为 fuse_src 并置 MS_SHARED。
 * 备份点污染（源为 /dev/fuse 或 fuse_src）时拒绝操作。
 */
int ns_global_replace_system(int mnt_ns_pid, const char* fuse_src, const char* backup_root);

/* 在 mnt_ns_pid 命名空间内从备份恢复三族所有用户视图（对应 global.sh restore） */
int ns_global_restore_system(int mnt_ns_pid, const char* backup_root);

/*
 * 在应用命名空间内卸载项目 FUSE 并 bind 回该用户备份的系统视图（幂等）：
 * 仅当 /storage/emulated 顶层源为 fuse_src（或 fuse_daemon 类型）时才操作，
 * 否则视为已还原/非项目视图，直接跳过。
 */
int ns_restore_app_fuse(int app_pid, const char* fuse_src, const char* backup_root, int user_id);

/* 查询 mnt_ns_pid 命名空间内全局替换状态（对应 global.sh status，返回枚举值） */
int ns_global_status(int mnt_ns_pid, const char* fuse_src);

#endif /* NS_UTILS_H */
