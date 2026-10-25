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
/* 在目标 ns 内查找应用 uid 对应的族根挂载点（同 ns 重建目标视图的首选源），
   族优先级 user > androidwritable > installer；命中返回 0，未找到 ENOENT */
int ns_find_family_root(int pid, uid_t app_uid, char* out, size_t outsz);
/* 跨命名空间绑定挂载（族根缺失时的兜底）：源路径位于调用方（init）命名空间
   （如 /proc/1/root<target>）。内核拒绝 mount(2) 源路径穿越（EINVAL），
   改走源命名空间 open_tree 克隆 + 目标命名空间 move_mount */
int ns_bind_mount_cross(int pid, const char* source, const char* target);
/* 递归卸载 */
int ns_umount_recursive(int pid, const char* target);
/* 卸载并删除目录 */
int ns_umount_and_rmdir(int pid, const char* target);
/* 检查是否已挂载 */
int ns_is_mounted(int pid, const char* target_mount, const char* match_fs_name);
/* 设置挂载点为共享 */
int ns_make_shared(int pid, const char* target);
/* 查找原生子挂载点 */
int ns_find_native_submounts(int pid, const char* base_path,
                              char mount_points[][256], int max_count);

/* readiness_ms 的负值哨兵：DEFER 预探测。
   应用场景只有一处——v1 两段式的 pre-specialize 快速尝试（IPC 的 REPORT 通道）：
   目标 ns 里 /storage/emulated 尚未被 vold 装配时，本次尝试**必然**失败，调用方
   会回 DEFER 让 zygisk 在 post-specialize 重发 POST。因此缺失不是失败，日志口径
   必须与真实失败区分（只记 DEBUG，不写 error.log，不宣称"交由重试队列"）。 */
#define NSP_READINESS_DEFER (-1)

/* 阻塞式合并挂载（作为向下兼容）。
   readiness_ms：挂载前等待目标 ns 内 /storage/emulated 出现的预算——
     0     = 只查一次，缺失立即返回 ENOENT（判定发生在任何卸载之前）；
     >0    = 在其内按 100ms 步进等待（POST / 异步首次注入）；
     NSP_READINESS_DEFER（负值）= DEFER 预探测：不等待，缺失按预期未就绪处理
           （静默，DEBUG），返回 ENOENT 由调用方回 DEFER。 */
int ns_combined_mount(int pid, const char* pkg, const char* source, const char* target, const char* backup,
                      char preserve_paths[][256], int preserve_count, int readiness_ms);

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
