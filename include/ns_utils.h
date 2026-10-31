#ifndef NS_UTILS_H
#define NS_UTILS_H

#include <limits.h>
#include <stdbool.h>
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

/* 穿过目标命名空间探测某个路径的挂载状态——**不读 /proc/<pid>/mountinfo**。
   真机实测一次整文件扫描 ≈68ms（Redmi/Android 14，应用 ns 有上千条挂载），而一次
   冷启动注入原本要读三遍，是"注入后冷启动明显变慢"的主因。本原语只用 statx：
     target : 目标命名空间内的绝对路径（如 /storage/emulated/0）
     src    : 本项目 FUSE 源挂载点（如 /mnt/nsp_global）；NULL = 不判定 is_ours
     is_mount: 出参，该路径在目标 ns 里是挂载点（statx mount id 与父目录不同）
     is_ours : 出参，该路径是本项目 FUSE 视图（是挂载点且 dev 与 src 一致）
   返回 0 = 探测成功（出参有效；路径不存在也算成功，两者均为 false）；
        -1 = 无法判定（权限 / 内核不支持 mount id 且 statfs 失败），调用方应回退
             到整文件扫描。 */
int ns_probe_target_view(int pid, const char* target, const char* src, bool* is_mount,
                         bool* is_ours);
/* 设置挂载点为共享 */
int ns_make_shared(int pid, const char* target);
/* 查找原生子挂载点 */
int ns_find_native_submounts(int pid, const char* base_path,
                              char mount_points[][256], int max_count);

/* readiness_ms 的负值哨兵：后台通道（异步扫描 / 失败重试）。
   应用场景：应用已经在运行，代理视图稍后到达即可——本次缺失属**预期未就绪**，
   由重试队列按退避补挂。日志口径必须与权威尝试区分：只记 DEBUG、不写 error.log、
   不出现"交由重试队列"措辞（该通道正是重试队列自己，逐轮报错会把正常等待刷成
   故障：真机历史上表现为每个应用启动刷一条 WARN+一条 error.log，且重试不收敛）。
   IPC 的权威通道（post-specialize 的 POST、旧模块/REQ 的就地挂载）用正值预算，
   缺失即 loud 失败。 */
#define NSP_READINESS_QUIET (-1)

/* 就地快试预算的上限（ms）：>0 且 ≤ 此值的等待属"快试"——真机把 /storage/emulated
   装进应用命名空间要 135–150ms，任何几十毫秒的预算都必然等不到，等不到**是常态**。
   故这类预算下的缺失按预期未就绪处理（只记 DEBUG、不写 error.log、不出现"交由重试
   队列"措辞），由调用方 fail-open 交后台重试。POST 通道的 IPC_MOUNT_INLINE_MS（20）
   正是这一档；旧模块/REQ 的就地挂载（250ms）与 DEFER 预探测（0）仍是权威尝试：
   缺失即 loud，真实故障绝不能被静默。 */
#define NSP_READINESS_INLINE_MAX_MS 50

/* 阻塞式合并挂载（作为向下兼容）。
   readiness_ms：挂载前等待目标 ns 内 /storage/emulated 出现的预算——
     0     = 只查一次，缺失立即返回 ENOENT（判定发生在任何卸载之前）；
     >0    = 在其内按 5ms 步进等待；只有 > NSP_READINESS_INLINE_MAX_MS 才是权威
             尝试（缺失 loud），≤ 该值属就地快试（POST 的 20ms：缺失只记 DEBUG、
             不写 error.log，交后台重试补挂）；
     NSP_READINESS_QUIET（负值）= 后台通道：不等待，缺失按预期未就绪处理
           （静默，DEBUG），由重试队列补挂。
   两条硬约束（真机回归守护）：
     1. 源必须是本命名空间内真实的 FUSE 挂载（statfs == FUSE_SUPER_MAGIC），
        否则**不动目标**直接返回——旧实现先卸载再挂，源不可用就把应用存储拆成
        空目录/空 bind（"某些设备 /storage/emulated/0 整个是空的"）；
     2. 挂载后必须校验目标确为 FUSE 视图，并先把目标子树置私有（MS_PRIVATE），
        避免共享挂载组上的卸载事件传播到 zygote/其它应用的命名空间。 */
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
