/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
/* 后端文件句柄标记：open/create 命中后端时置位（本地 fd 不置位），
   read/write/release/fsync 据此区分本地 fd 与模块句柄。
   用 bit40（非 bit63）：Android tagged-pointer 检测对 fh 的 top byte
   （bit 56-63）非零会 SIGABRT（"Pointer tag truncated"）；bit40 置位
   不触发该检测，且远高于普通 fd 范围 */
#define NSP_FH_BACKEND_FLAG (1ULL << 40)
/* 后端句柄 fh 布局（open 时绑定，read/write 免路径解析直接定位模块 ops）：
   - bit40：后端句柄标志（沿用）
   - bit41-47：模块槽位（MAX_MODULES=16 < 128，7 位足够）
   - bit0-39：后端句柄 ID（模块分配的小整数）
   低 40 位掩码用于提取句柄 ID（不含标志与槽位） */
#define NSP_FH_BACKEND_SLOT_SHIFT 41
#define NSP_FH_BACKEND_SLOT_MASK  (0x7FULL << NSP_FH_BACKEND_SLOT_SHIFT)
#define NSP_FH_HANDLE_MASK        ((1ULL << 40) - 1)
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <sys/prctl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <libgen.h>
#include <sys/syscall.h>
#include <ctype.h>
#include "common.h"
#include "nsp_comm.h"
#include "crash_dump.h"
#include "fault_fence.h"
#include "module_guard.h"
#include "module_loader.h"
#include <fuse3/fuse_log.h>
/* 透传 ABI：Android 用定制 libfuse 的 fuse_kernel.h（含 V0/V1/V2 旧式 ioctl 与
   fuse_passthrough_out_v0）；GNU 用系统官方 libfuse——fuse_kernel.h 不随系统包安装，
   改引内核 UAPI <linux/fuse.h>（提供 FUSE_DEV_IOC_BACKING_OPEN/BACKING_CLOSE 与
   fuse_backing_map）。 */
#ifdef TARGET_ANDROID
#include <fuse3/fuse_kernel.h>
#else
#include <linux/fuse.h>
#endif
#include <sys/ioctl.h>

bool g_passthrough_enabled = false;
bool g_preserve_perms = false;
bool g_disable_sandbox = false; /* 新增：禁用沙盒功能标志 */

static int g_ready_fd = -1;
static int g_global_root_fd = -1;
/* 崩溃触发测试：--crash-test[=segv|abrt|bus]，验证崩溃日志捕获链路 */
static int g_crash_test = 0; /* 0=无 1=SIGSEGV 2=SIGABRT 3=SIGBUS */
#ifdef TARGET_ANDROID
static int g_bpf_fd = -1; /* BPF program fd, -1 = disabled */
#endif
static bool g_passthrough_disabled = false; /* --no-passthrough 显式禁用 */
/* 透传方法：init 阶段一次探测确认，open 阶段直连对应 ioctl，避免每次 open 走回退链。
   GNU 构建同样启用（本机内核支持时经 BACKING_OPEN 协商） */
typedef enum {
    PT_METHOD_NONE = 0,   /* 未启用透传 */
    PT_METHOD_UPSTREAM,   /* 上游 BACKING_OPEN（6.9+/GKI 6.12；老内核上同号即 V0） */
    PT_METHOD_ANDROID_V2, /* Android V2 旧式 ioctl */
    PT_METHOD_ANDROID_V1, /* Android V1 旧式 ioctl */
    PT_METHOD_ANDROID_V0, /* Android V0 旧式 ioctl */
} passthrough_method_t;
static passthrough_method_t g_pt_method = PT_METHOD_NONE;
static bool g_pt_probe_pending = false;             /* GNU：init 无会话 fd，探测推迟到首次 open */
static int passthrough_enable_fixed_method(int fd); /* 实现见文件后部 */
static bool g_is_media_fuse = false;                /* --media-fuse: 媒体模块专属 FUSE */
static char g_modules_dir_arg[PATH_MAX] = {0};      /* --modules-dir: 热插拔模块目录覆盖 */
static int g_fuse_threads = 2;                      /* --fuse-threads: FUSE worker 线程数上限
                                                   （默认 2=双线程；0/-s=单线程；-1=libfuse 默认 10） */

#define MAX_PENDING_CLOSE  64
#define PENDING_CLOSE_MASK (MAX_PENDING_CLOSE - 1)
static int g_pending_close_fds[MAX_PENDING_CLOSE];
/* 无锁环形队列（多生产者单消费者）：
   - next：生产分配水位（fetch_add 分配槽位 idx）
   - ready：生产完成水位（写 fds[idx&MASK] 后推进到 idx+1）
   - consumed：消费水位（flush 已 close 的槽位数）
   MAX_PENDING_CLOSE 为 2 的幂，槽位 = idx & MASK。
   安全性：flush 在 close 全部完成后才 release 更新 consumed；生产者写槽位
   idx 要求 idx - consumed < MAX，故其槽位上一周期值必已被 close，写与 close
   不重叠。空队列时 flush 走零原子写快速路径，不再抢全局互斥锁。 */
static _Atomic(unsigned) g_pc_ready = 0;
static _Atomic(unsigned) g_pc_consumed = 0;

#ifdef TARGET_ANDROID
static _Atomic(unsigned) g_pc_next = 0; /* 生产分配水位（仅 Android defer 使用） */
static void vfs_defer_close(int fd) {
    if (fd < 0) return;
    unsigned idx = atomic_fetch_add_explicit(&g_pc_next, 1, memory_order_relaxed);
    unsigned consumed = atomic_load_explicit(&g_pc_consumed, memory_order_acquire);
    if (idx - consumed >= MAX_PENDING_CLOSE) {
        close(fd); /* 队列满：直接关闭（不阻塞生产者） */
        return;
    }
    g_pending_close_fds[idx & PENDING_CLOSE_MASK] = fd;
    /* 推进 ready 水位到 idx+1：前序（< idx）生产者写入完成后才能推进 */
    for (;;) {
        unsigned r = atomic_load_explicit(&g_pc_ready, memory_order_acquire);
        if (r > idx) break; /* 已被前序推进覆盖 */
        if (r == idx) {
            if (atomic_compare_exchange_weak_explicit(&g_pc_ready, &r, idx + 1,
                                                      memory_order_release, memory_order_relaxed))
                break;
            continue;
        }
        /* r < idx：前序未完成，自旋等待其推进（前序临界区极小，等待极短） */
    }
}
#endif

static void vfs_flush_pending_closes(void) {
    unsigned ready = atomic_load_explicit(&g_pc_ready, memory_order_acquire);
    unsigned consumed = atomic_load_explicit(&g_pc_consumed, memory_order_relaxed);
    if (ready == consumed) return; /* 空队列快速路径：零原子写 */
    do {
        close(g_pending_close_fds[consumed & PENDING_CLOSE_MASK]);
        consumed++;
    } while (consumed < ready);
    atomic_store_explicit(&g_pc_consumed, consumed, memory_order_release);
}

typedef enum { MODE_REDIRECT, MODE_OVERLAY } DaemonMode;
static DaemonMode g_mode = MODE_REDIRECT;

static char g_lower_dir[PATH_MAX] = {0};
static char g_upper_dir[PATH_MAX] = {0};

static int recursive_rmdir(const char* path);
static int recursive_copy_dir(const char* src, const char* dst, uid_t uid, gid_t gid);

static void log_fuse_err(const char* op, const char* path, int err_code) {
    int err = err_code < 0 ? -err_code : err_code;
    if (err != 0 && err != ENOENT && err != EEXIST && err != EROFS) {
        char current_pkg[128] = "unknown";
        struct fuse_context* ctx = fuse_get_context();
        if (ctx) {
            module_dispatch_get_pkg(ctx->uid, ctx->pid, current_pkg, sizeof(current_pkg));
        }
        fprintf(stderr,
                "[FUSE_ERR] 应用: %s (PID: %d, UID: %d) | 操作: %s | 路径: %s | 错误码: %d (%s)\n",
                current_pkg, ctx ? ctx->pid : 0, ctx ? ctx->uid : 0, op, path ? path : "nullptr",
                err, strerror(err));
        fflush(stderr);
        LOG_ERR("[FUSE_ERR] %s %s: %s", op, path ? path : "nullptr", strerror(err));
    }
}

/* 框架最小路径解析（无规则模块时的直通回退）：剥离 /0/ user_id 前缀 + 非法字符清理 */
static int fw_parse_path(const char* path, int* user_id_out, char* sub_path_out, size_t sz) {
    if (!path) return -ENOENT;
    const char* sub = path;
    if (path[0] == '/' && path[1] >= '0' && path[1] <= '9') {
        /* 数字序列后是结尾或 '/' 才是完整 user_id 目录（/0、/10/...）；
           普通数字前缀文件名（/1_abc.txt）不剥离（与规则层判定一致） */
        const char* d = path + 1;
        while (*d >= '0' && *d <= '9') d++;
        if (*d == '\0' || *d == '/') {
            if (user_id_out) *user_id_out = atoi(path + 1);
            const char* slash = strchr(path + 1, '/');
            sub = slash ? slash : "/";
        }
    }
    if (path_contains_invalid_chars(sub)) {
        path_sanitize(sub_path_out, sz, sub);
        if (sub_path_out[0] == '\0') return -ENOENT;
    } else {
        strncpy(sub_path_out, sub, sz - 1);
        sub_path_out[sz - 1] = '\0';
    }
    return 0;
}

/* 框架默认存储路径（无规则模块 / 模块未命中时的直通回退）：
   经 common_default_real_path 统一合成（见 common.h），禁裸拼 STORAGE_BASE */
static void fw_default_real_path(int user_id, const char* sub_path, char* out, size_t sz) {
    common_default_real_path(user_id, sub_path, out, sz);
}

/* 虚拟目录判空（原 vfs_is_virtual_dir_empty 的分派器版）：
   - 虚拟祖先 → 视为非空（拒绝删除）
   - 否则扫描真实目录，跳过规则隐藏/重定向子项（与 readdir 过滤一致） */
static bool fw_virtual_dir_empty(const char* sub_path, const char* real_path,
                                 const char* current_pkg, int path_user_id, uid_t uid) {
    if (uid != 0) {
        struct fuse_context* c = fuse_get_context();
        NspQueryCtx q0 = {
            .uid = uid, .pid = c ? c->pid : 0, .gid = c ? c->gid : 0, .path = sub_path};
        NspProbeResult r0;
        memset(&r0, 0, sizeof r0);
        if (module_dispatch_probe(&q0, &r0) == NSP_DISPATCH_OK && r0.valid &&
            r0.virtual_kind == NSP_VK_ANCESTOR)
            return false;
    }
    struct stat st;
    if (lstat(real_path, &st) == -1) return true;
    DIR* dp = opendir(real_path);
    if (!dp) return false;
    bool skip_sandbox = (path_user_id < 0) || g_disable_sandbox;
    bool hide_others = (!skip_sandbox && current_pkg[0] && strcmp(current_pkg, "system") != 0 &&
                        strcmp(current_pkg, "unknown") != 0);
    bool is_root = (strcmp(sub_path, "/") == 0 || sub_path[0] == '\0');
    struct dirent* de;
    bool empty = true;
    while ((de = readdir(dp)) != nullptr) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (path_contains_invalid_chars(de->d_name)) continue;
        char item_sub_path[2048];
        if (is_root)
            snprintf(item_sub_path, 2047, "/%s", de->d_name);
        else
            snprintf(item_sub_path, 2047, "%s/%s", sub_path, de->d_name);
        if (uid != 0) {
            /* 轻量探测；user_id 目录条目豁免 redirect_target（与 readdir 一致） */
            bool uid_dir = false;
            if (item_sub_path[0] == '/' && isdigit((unsigned char)item_sub_path[1])) {
                const char* d = item_sub_path + 1;
                while (isdigit((unsigned char)*d)) d++;
                uid_dir = (*d == '\0' || *d == '/');
            }
            struct fuse_context* c = fuse_get_context();
            NspQueryCtx iq = {
                .uid = uid, .pid = c ? c->pid : 0, .gid = c ? c->gid : 0, .path = item_sub_path};
            NspProbeResult ir;
            memset(&ir, 0, sizeof ir);
            if (module_dispatch_probe(&iq, &ir) == NSP_DISPATCH_OK && ir.valid) {
                if (ir.appear_missing || (!uid_dir && ir.virtual_kind == NSP_VK_TARGET)) continue;
            }
        }
        if (hide_others &&
            (strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 ||
             strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0)) {
            if (strcmp(de->d_name, current_pkg) != 0) continue;
        }
        empty = false;
        break;
    }
    closedir(dp);
    return empty;
}

static bool is_android_skel_dir(const char* sub_path) {
    if (strcmp(sub_path, "/Android") == 0 || strcmp(sub_path, "/Android/") == 0) return true;
    if (strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0)
        return true;
    if (strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0)
        return true;
    return false;
}

/* ================= 三层数据路径（Phase 2 重构） =================
 *   FUSE 节点（内核）→ FUSE 守护进程：
 *     ① 路由层   fw_route()：FUSE 上下文 + 原始路径 → 路由决策
 *                （user_id 剥离 / 模块分派 / 直通回退 / 决策强制：appear_missing
 *                 → ENOENT、read_only → EROFS）
 *     ② 模块层   module_dispatch_resolve / module_backend_*（loader）：
 *                原子槽位快照 + 在途引用（S2 无锁分派）+ 调用围栏
 *                （崩溃→longjmp 恢复）+ 输出校验 + 熔断（错误→卸载）
 *     ③ FUSE 输出层  各 vfs_* 回调体：消费路由决策，执行真实系统操作
 *                （lstat/open/read/filler...）并返回 FUSE 语义
 * VFS_SETUP_CORE 是①③之间的薄胶水：声明回调体使用的局部变量并调用
 * 路由层（局部变量名保持与原实现一致，回调体零改动）。
 * 线程安全：三层全部无全局可变状态依赖（路由层纯函数 + 模块层原子
 * 快照），FUSE 多线程（fuse_session_loop_mt）下任意 worker 并发进入。 */
/* ================= 决策强制（框架单点） =================
 * V3 起模块只声明"这个路径该怎么表现"（NspPathDecision），errno 映射与权限
 * 策略集中在此，不再散落在各回调里各判一遍：
 *   - appear_missing → 所有回调统一 ENOENT。V2 时代读类回调 ENOENT、写类回调
 *     EACCES，同一声明两种结果；统一后与"存在变不存在"的语义一致。
 *   - read_only → 变更操作统一 EROFS，root 豁免由框架持有（模块无需关心）。
 * "何时算变更"由操作类别给出；open/access 这类"是否写"取决于 flags/mask 的
 * 操作自行判定触发条件，但策略仍走 vfs_check_read_only 这一个出口。 */
typedef enum {
    VFS_OP_READ = 0,  /* 查询/读取：不受 read_only 限制 */
    VFS_OP_MUTATE = 1 /* 变更：read_only 命中时（非 root）返回 EROFS */
} VfsOpKind;

/* 只读检查：0 放行，-EROFS 拒绝。root 豁免是框架策略，模块无需关心。 */
static inline int vfs_check_read_only(const NspPathDecision* d, uid_t uid) {
    return (uid != 0 && d->read_only) ? -EROFS : 0;
}

/* 属性覆盖落实（getattr 用）：在框架既有权限策略**之后**应用，故模块的显式
   声明优先于框架默认（伪造模式属主=访问者、skel 目录 0755、/Android/data 保留
   真实属主等）。只改权限位，文件类型位始终取自真实属性——不允许模块把一个
   文件声明成目录（那属于 appear_missing/重定向该解决的问题）。 */
static inline void vfs_apply_attr_override(const NspPathDecision* d, struct stat* st) {
    if (!d->valid) return;
    if (d->attr_override & NSP_OV_MODE) st->st_mode = (st->st_mode & S_IFMT) | (d->mode & 07777);
    if (d->attr_override & NSP_OV_UID) st->st_uid = (uid_t)d->uid;
    if (d->attr_override & NSP_OV_GID) st->st_gid = (gid_t)d->gid;
}

static int fw_route(struct fuse_context* ctx, const char* path_val, NspPathDecision* rr,
                    bool* nsp_ok, char* current_pkg, int* user_id, char* sub_path, char* real_path,
                    bool* is_redir, VfsOpKind op) {
    *nsp_ok = false;
    /* user_id 必须先置 -1：fw_parse_path 只在路径含完整 <uid>/ 用户层时才写它，
       挂载点根（"/"）等无用户层路径不会赋值——漏置会让调用方拿到未初始化值，
       下游（如 readdir 的 user_id<0 判定）据此误判为"在用户层内" */
    *user_id = -1;
    *is_redir = false;
    sub_path[0] = '\0';
    real_path[0] = '\0';
    strcpy(current_pkg, "unknown");
    /* 用户层剥离与虚拟路径归一由框架自算：与模块侧剥离逻辑
       （br_strip_and_sanitize）逐行等价，故 V3 起不经 ABI 回传——
       模块只回传它真正能决定的字段 */
    if (fw_parse_path(path_val, user_id, sub_path, PATH_MAX) != 0) return -ENOENT;
    /* module_dispatch_resolve 统一经 nsp_decision_init 初始化默认输出
       （valid/appear_missing/read_only/mode/uid/gid 等全部有定义值），无论
       是否命中模块都无需调用方预置；返回 NSP_DISPATCH_NONE 时 `*nsp_ok`
       短路，调用方不读 rr 决策字段 */
    NspQueryCtx nsp_q = {.uid = ctx->uid, .pid = ctx->pid, .gid = ctx->gid, .path = path_val};
    if (module_dispatch_resolve(&nsp_q, rr) == NSP_DISPATCH_OK && rr->valid) {
        *nsp_ok = true;
        if (rr->pkg[0]) {
            strncpy(current_pkg, rr->pkg, 128 - 1);
            current_pkg[128 - 1] = '\0';
        }
        strcpy(real_path, rr->real_path);
        *is_redir = rr->is_redirect;
        /* ---- 决策强制（单点）---- */
        if (rr->appear_missing) return -ENOENT;
        if (op == VFS_OP_MUTATE) {
            int rc = vfs_check_read_only(rr, ctx->uid);
            if (rc != 0) {
                /* 拒绝日志也收口在此：原先每个变更回调各写一条
                   <OP>_RO_DENIED，同一声明散成 11 处重复代码 */
                log_fuse_err("RO_DENIED", path_val, -rc);
                return rc;
            }
        }
        return 0;
    }
    /* 框架直通回退（无规则模块 / 模块未命中） */
    fw_default_real_path(*user_id, sub_path, real_path, PATH_MAX);
    return 0;
}

/* 后端返回码是否为契约内的业务结果：POSIX errno 范围内的负值（-1..-4095）。

   模块以 errno 风格报告业务失败（ENOENT 路径不存在、EPERM 命令被拒、
   ENOTEMPTY 目录非空、EIO 后端暂不可达……）是**正常返回**，不得计入模块
   错误计数：熔断窗口默认「10s 内 5 次」，而应用扫描缺失路径
   （os.path.exists / 文件管理器的存在性探测）瞬间即可打满——健康模块被置毒
   卸载并落盘 ban（哈希不变则不再重载），FTP 存储整体失效。只有非 errno 的
   返回码（正数、或超出 errno 范围）才说明模块契约违规。

   仅后端分派豁免：`backend_*` 是模块回传业务结果的唯一通道，errno 风格返回
   码即其契约；`resolve`/`probe` 走决策字段（appear_missing 等），返回非 0
   仍视为契约违规（见 module_guard 的规则模块熔断用例）。 */
static inline bool backend_rc_is_business(int rc) {
    return rc < 0 && rc >= -4095;
}

#define VFS_SETUP_CORE(path_val, op_kind)                                         \
    struct fuse_context* ctx = fuse_get_context();                                \
    if (!ctx) return -EIO; /* 不可达：libfuse 在每个回调内均设置上下文 */          \
    NspPathDecision rr;                                                           \
    bool nsp_ok = false;                                                          \
    char current_pkg[128];                                                        \
    int path_user_id;                                                             \
    char sub_path[PATH_MAX];                                                      \
    char p[PATH_MAX];                                                             \
    bool is_redir;                                                                \
    int fw_rc = fw_route(ctx, path_val, &rr, &nsp_ok, current_pkg, &path_user_id, \
                         sub_path, p, &is_redir, op_kind);                        \
    if (fw_rc != 0) return fw_rc;                                                 \
    (void)is_redir; /* 部分回调不使用 is_redir，抑制未使用警告 */

#define VFS_RETURN(val) \
    do {                \
        return val;     \
    } while (0)

/* 框架版 I/O 监控日志：由框架记录目标应用操作的【原始路径】；
   target_path 为模块 resolve 可选返回的【目标路径】（REDIRECT 命中时
   非空，否则 NULL），附加到日志尾部。monitor 开关来自模块配置。 */
static void vfs_log_io(const char* pkg, uid_t uid, const char* op, const char* orig_path,
                       const char* target_path, bool monitor_on) {
    /* 热路径提前过滤：MONITOR 关闭且非 DEBUG 级别时零开销返回。
       LOG_IO 为通道标记（0x81）恒 > g_min_log_level，log_internal 不会过滤
       它，故格式化仅在 monitor_on 或 DEBUG MAP 分支才真正需要 */
    if (!monitor_on && g_min_log_level != LOG_DEBUG) return;
    if (monitor_on) {
        if (target_path && target_path[0]) {
            log_internal(LOG_IO, "[%s(%u)] [%s] %s -> %s", pkg, uid, op, orig_path, target_path);
        } else {
            log_internal(LOG_IO, "[%s(%u)] [%s] %s", pkg, uid, op, orig_path);
        }
    }
    if (target_path && target_path[0] && g_min_log_level == LOG_DEBUG) {
        log_internal(LOG_DEBUG, "[MAP] %s: '%s' -> '%s'", op, orig_path, target_path);
    }
}

static void vfs_log_io_err(const char* pkg, const char* op, const char* sub_path, const char* fmt,
                           ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    log_internal(LOG_IO, "[%s] [ERR] %s %s %s", pkg, op, sub_path, msg);
}

/* readdir 去重哈希（原 vfs_core 提供，框架保留）
   池化改造：节点与名字存于可增长的连续池，桶内用索引链接（realloc 移动
   安全），免每条目 2 次堆分配（HashNode + strdup）——大目录 readdir 的
   malloc/free 风暴变为 O(log n) 次 realloc；桶数组从 8KB 栈降至 4KB */
#define HASH_BUCKETS    1024
#define HASH_INIT_NODES 256
#define HASH_INIT_NAMES (16 * 1024)

typedef struct {
    int32_t next;      /* 桶内链表下一节点索引，-1 = 结尾 */
    uint32_t name_off; /* 名字在 names 池中的偏移 */
} HashNode;

typedef struct {
    int32_t buckets[HASH_BUCKETS]; /* 桶头节点索引，-1 = 空 */
    HashNode* nodes;               /* 节点池（realloc 增长） */
    int32_t node_count, node_cap;
    char* names; /* 名字池（realloc 增长） */
    size_t name_used, name_cap;
} DirHashTable;

static void vfs_hash_init(DirHashTable* ht) {
    memset(ht->buckets, 0xFF, sizeof(ht->buckets)); /* 全 -1（空桶） */
    ht->nodes = NULL;
    ht->node_count = 0;
    ht->node_cap = 0;
    ht->names = NULL;
    ht->name_used = 0;
    ht->name_cap = 0;
}

static unsigned long hash_djb2(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) hash = ((hash << 5) + hash) + c;
    return hash;
}

static bool vfs_hash_insert(DirHashTable* ht, const char* name) {
    unsigned long h = hash_djb2(name) % HASH_BUCKETS;
    int32_t idx = ht->buckets[h];
    while (idx >= 0) {
        if (strcmp(ht->names + ht->nodes[idx].name_off, name) == 0) return false;
        idx = ht->nodes[idx].next;
    }
    size_t nlen = strlen(name) + 1;
    if (ht->name_used + nlen > ht->name_cap) {
        size_t ncap = ht->name_cap ? ht->name_cap * 2 : HASH_INIT_NAMES;
        while (ncap < ht->name_used + nlen) ncap *= 2;
        char* nn = realloc(ht->names, ncap);
        if (!nn) return false;
        ht->names = nn;
        ht->name_cap = ncap;
    }
    if (ht->node_count >= ht->node_cap) {
        int32_t ncap = ht->node_cap ? ht->node_cap * 2 : HASH_INIT_NODES;
        HashNode* nn = realloc(ht->nodes, (size_t)ncap * sizeof(HashNode));
        if (!nn) return false;
        ht->nodes = nn;
        ht->node_cap = ncap;
    }
    uint32_t off = (uint32_t)ht->name_used;
    memcpy(ht->names + off, name, nlen);
    ht->name_used += nlen;
    int32_t slot = ht->node_count++;
    ht->nodes[slot].name_off = off;
    ht->nodes[slot].next = ht->buckets[h];
    ht->buckets[h] = slot;
    return true;
}

static void vfs_hash_free(DirHashTable* ht) {
    free(ht->nodes);
    free(ht->names);
    ht->nodes = NULL;
    ht->names = NULL;
}

/* 为合成目录 stat 生成非零 inode（原 vfs_core.h static inline） */
static inline ino_t synthetic_inode(const char* path) {
    if (!path) return 1;
    unsigned long h = 5381;
    int c;
    while ((c = (unsigned char)*path++)) h = ((h << 5) + h) + c;
    return (ino_t)(h | 1);
}

static int vfs_getattr(const char* path, struct stat* st, struct fuse_file_info* fi) {
    vfs_flush_pending_closes();
    (void)fi;
    VFS_SETUP_CORE(path, VFS_OP_READ);
    if (st == nullptr) VFS_RETURN(-EINVAL);
    /* 后端分派：路径命中 BACKEND 模块时由模块方法提供元数据（模块不实现 FUSE） */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0) {
        if (!bops->backend_getattr) {
            /* 模块未提供 getattr 回调：释放 lookup 在途引用后按未命中走本地 lstat
               （否则 backend_refs 不归零，模块无法热卸载） */
            module_backend_put(bops);
        } else {
            memset(st, 0, sizeof *st);
            int bslot = module_ops_slot(bops);
            int brc = nsp_fence_backend_getattr(bslot, "backend_getattr", bops->backend_getattr,
                                                sub_path, st);
            module_backend_put(bops);
            if (brc == NSP_FENCE_FAULT) {
                module_guard_fault(bslot, "backend_getattr", sub_path);
                VFS_RETURN(-EIO);
            }
            if (brc != 0) {
                if (brc != NSP_FENCE_BADFN && !backend_rc_is_business(brc))
                    module_guard_error(bslot, "backend_getattr", brc, sub_path, "getattr 返回异常");
                VFS_RETURN(brc < 0 ? brc : -EIO);
            }
            if (!g_preserve_perms) {
                st->st_uid = ctx->uid;
                st->st_gid = ctx->gid;
            } else if (st->st_uid == 0 && st->st_gid == 0) {
                /* 权限完全镜像：FTP 后端未提供真实属主（uid/gid=0），FTP 虚拟目录
                   （如前缀"云盘"及其子项）权限继承其本地上级——用户存储根
                   /data/media/<uid>/（FTP 虚拟路径在本地不存在，直接父目录
                   lstat 必失败，故取用户存储根的真实属主，而非固定 root） */
                int root_uid = (path_user_id >= 0) ? path_user_id : 0;
                char root_path[PATH_MAX];
                common_storage_root(root_uid, root_path, sizeof(root_path));
                struct stat pst;
                if (lstat(root_path, &pst) == 0) {
                    st->st_uid = pst.st_uid;
                    st->st_gid = pst.st_gid;
                }
            }
            vfs_apply_attr_override(&rr, st);
            VFS_RETURN(0);
        }
    }
    if (lstat(p, st) == -1) {
        int err = errno;
        if ((err == ENOENT || err == EACCES) &&
            (is_android_skel_dir(sub_path) || rr.virtual_kind == NSP_VK_ANCESTOR || rr.virtual_kind == NSP_VK_TARGET)) {
            /* 虚拟目录（无真实底层文件，如 FTP 前缀/重定向祖先）：权限继承
               上级目录（父路径的真实 mode/uid/gid），而非固定 root/访问者 */
            memset(st, 0, sizeof(struct stat));
            st->st_ino = synthetic_inode(sub_path);
            st->st_mode = S_IFDIR;
            st->st_nlink = 2;
            char parent[PATH_MAX];
            strncpy(parent, p, sizeof(parent) - 1);
            parent[sizeof(parent) - 1] = '\0';
            char* last = strrchr(parent, '/');
            if (last && last != parent)
                *last = '\0';
            else if (last == parent)
                strcpy(parent, "/");
            struct stat pst;
            if (lstat(parent, &pst) == 0) {
                st->st_mode |= (pst.st_mode & 07777);
                st->st_uid = pst.st_uid;
                st->st_gid = pst.st_gid;
            } else {
                st->st_mode |= 0755;
                st->st_uid = ctx->uid;
                st->st_gid = ctx->gid;
            }
            vfs_apply_attr_override(&rr, st);
            VFS_RETURN(0);
        }
        log_fuse_err("GETATTR", path, err);
        if (err == EIO) {
            vfs_log_io_err(current_pkg, "GETATTR", sub_path, "EIO real='%s'", p);
            VFS_RETURN(-EIO);
        }
        if (err != ENOENT && g_min_log_level == LOG_DEBUG)
            vfs_log_io_err(current_pkg, "GETATTR", sub_path, "errno=%d real='%s'", err, p);
        VFS_RETURN(-err);
    }
    bool is_data_or_obb =
        (strncmp(sub_path, "/Android/data", 13) == 0 || strncmp(sub_path, "/Android/obb", 12) == 0);
    if (!g_preserve_perms && !is_data_or_obb) {
        st->st_uid = ctx->uid;
        st->st_gid = ctx->gid;
    } else if (!g_preserve_perms && is_redir && S_ISDIR(st->st_mode)) {
        /* 权限完全镜像模式下（--preserve-perms）保留底层真实目录权限，
           不强制 0777；仅伪造模式才放开重定向目录写权限 */
        st->st_mode = (st->st_mode & ~07777) | 0777;
    }
    if (is_android_skel_dir(sub_path)) {
        if (!g_preserve_perms) {
            /* 伪造模式：skel 骨架目录统一 0755 + 访问者属主 */
            st->st_mode = (st->st_mode & ~07777) | S_IFDIR | 0755;
            st->st_uid = ctx->uid;
            st->st_gid = ctx->gid;
        }
        /* 权限完全镜像模式（--preserve-perms）：保留底层真实目录权限与属主 */
    }
            vfs_apply_attr_override(&rr, st);
    VFS_RETURN(0);
}

static int vfs_access(const char* path, int mask) {
    vfs_flush_pending_closes();
    VFS_SETUP_CORE(path, VFS_OP_READ);
    /* access 归类 VFS_OP_READ（F_OK/R_OK 在 RO 路径上必须放行），只在请求
       写访问时走框架的只读策略——"何时算写"由 mask 决定属 FUSE 语义，
       策略本身（root 豁免 + EROFS）仍在 vfs_check_read_only 单点。
       与 vfs_open 相同先于后端分派检查 */
    if (mask & W_OK) {
        int ro_rc = vfs_check_read_only(&rr, ctx->uid);
        if (ro_rc != 0) {
            log_fuse_err("ACCESS_RO_DENIED", path, -ro_rc);
            VFS_RETURN(ro_rc);
        }
    }
    /* 后端路径：访问检查由后端语义决定，框架默认放行 */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0) {
        module_backend_put(bops);
        VFS_RETURN(0);
    }
    if (access(p, mask) == -1) {
        int err = errno;
        if ((err == ENOENT || err == EACCES) &&
            (is_android_skel_dir(sub_path) || rr.virtual_kind == NSP_VK_ANCESTOR || rr.virtual_kind == NSP_VK_TARGET)) {
            VFS_RETURN(0);
        }
        log_fuse_err("ACCESS", path, err);
        if (err == EIO) VFS_RETURN(-EIO);
        vfs_log_io_err(current_pkg, "ACCESS", sub_path, "errno=%d", err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

/* readdir 条目路径拼接：结果可容纳时 memcpy 组装，免每条目 snprintf 格式化
   开销（大目录每条目省 ~200-400ns）；超长边界回退 snprintf 保持与原名一致
   的截断语义。base 传 "" 表示根（生成 "/name"）。 */
static void readdir_join(char* dst, size_t cap, const char* base, const char* name) {
    size_t bl = strlen(base);
    size_t nl = strlen(name);
    if (bl + 1 + nl < cap) {
        memcpy(dst, base, bl);
        dst[bl] = '/';
        memcpy(dst + bl + 1, name, nl + 1);
    } else {
        snprintf(dst, cap, "%s/%s", base, name);
    }
}

/* ================= readdir 分阶段实现 =================
 * vfs_readdir 拆为：后端分派 → 本地目录扫描（probe 过滤/去重/filler）
 * → 骨架与虚拟目录合成 → . / .. 收尾。各阶段共享 VfsReaddirCtx，
 * 任一 filler 返回非 0（内核缓冲已满）即短路结束本次 readdir（返回 0）。 */
typedef struct {
    struct fuse_context* ctx;
    const char* sub_path;  /* 剥离 <uid>/ 后的虚拟路径 */
    const char* real_path; /* 本地真实目录（opendir/lstat 用） */
    const char* current_pkg;
    void* buf;
    fuse_fill_dir_t filler;
    DirHashTable ht; /* 条目去重表 */
    bool is_root;    /* sub_path 为挂载点根 */
    bool is_android_dir;
    bool hide_others; /* 跨应用隔离生效（沙盒开启 + 非 root/未知访问者） */
    bool has_data, has_obb, has_android, has_pkg;
} VfsReaddirCtx;

/* readdir 后端分派：rr.is_ftp 且路径命中 BACKEND 模块时由模块方法返回条目，
   框架负责 . / .. 与 filler 输出。返回 true = 已处理（*rc_out 为 FUSE 返回码）；
   false = 未命中后端，交回本地目录路径。 */
static bool vfs_readdir_backend(struct fuse_context* ctx, const char* sub_path, bool is_ftp,
                                void* buf, fuse_fill_dir_t filler, int* rc_out) {
    if (!is_ftp) return false;
    const NspModuleOps* bops = NULL;
    if (module_backend_lookup(sub_path, &bops) != 0) return false;
    if (!bops->backend_readdir) {
        /* 模块未提供 readdir 回调：释放 lookup 在途引用后走本地目录路径 */
        module_backend_put(bops);
        return false;
    }
    /* 512×NspDirEntry ≈ 135KB：必须堆分配——FUSE 线程栈（Android 常为
       1MB）上放 135KB 栈数组仍有风险。calloc 同时提供清零防御
       （防后端未填充字段残留垃圾）。原 1024×270KB：readdir 缓冲
       每请求一次性分配，FTP 目录条目数通常远小于 512（超限时
       FUSE 分页续读），减半降低每请求堆分配开销 */
    NspDirEntry* entries = calloc(512, sizeof(NspDirEntry));
    if (!entries) {
        module_backend_put(bops); /* calloc 失败：释放引用再报错 */
        *rc_out = -ENOMEM;
        return true;
    }
    int bslot = module_ops_slot(bops);
    int n = nsp_fence_backend_readdir(bslot, "backend_readdir", bops->backend_readdir, sub_path,
                                      entries, 512);
    module_backend_put(bops);
    if (n == NSP_FENCE_FAULT) {
        module_guard_fault(bslot, "backend_readdir", sub_path);
        free(entries);
        *rc_out = -EIO;
        return true;
    }
    if (n == NSP_FENCE_BADFN) {
        free(entries);
        *rc_out = -EIO;
        return true;
    }
    if (n < 0) {
        if (!backend_rc_is_business(n))
            module_guard_error(bslot, "backend_readdir", n, sub_path, "readdir 返回异常");
        free(entries);
        *rc_out = n;
        return true;
    }
    if (n > 512) {
        module_guard_error(bslot, "backend_readdir", 0, sub_path, "返回条目数超限(越界写)");
        free(entries);
        *rc_out = -EIO;
        return true;
    }
    /* POSIX readdir 恒含 . / ..（与本地文件系统 readdir 路径一致） */
    struct stat dirst;
    memset(&dirst, 0, sizeof dirst);
    dirst.st_mode = S_IFDIR | 0755;
    if (!g_preserve_perms) {
        dirst.st_uid = ctx->uid;
        dirst.st_gid = ctx->gid;
    }
    filler(buf, ".", &dirst, 0, 0);
    filler(buf, "..", &dirst, 0, 0);
    for (int i = 0; i < n; i++) {
        struct stat st;
        memset(&st, 0, sizeof st);
        st.st_mode = entries[i].is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644);
        if (!g_preserve_perms) {
            st.st_uid = ctx->uid;
            st.st_gid = ctx->gid;
        }
        if (filler(buf, entries[i].name, &st, 0, 0) != 0) break;
    }
    free(entries);
    *rc_out = 0;
    return true;
}

static void vfs_readdir_ctx_init(VfsReaddirCtx* d, struct fuse_context* ctx, const char* sub_path,
                                 const char* real_path, const char* current_pkg, int path_user_id,
                                 void* buf, fuse_fill_dir_t filler) {
    d->ctx = ctx;
    d->sub_path = sub_path;
    d->real_path = real_path;
    d->current_pkg = current_pkg;
    d->buf = buf;
    d->filler = filler;
    vfs_hash_init(&d->ht);
    d->is_root = (strcmp(sub_path, "/") == 0 || sub_path[0] == '\0');
    /* 根据 g_disable_sandbox 强制跳过沙盒屏蔽逻辑；无用户层（user_id<0）同理 */
    bool skip_sandbox = (path_user_id < 0) || g_disable_sandbox;
    d->is_android_dir = (!skip_sandbox &&
                         (strcmp(sub_path, "/Android") == 0 || strcmp(sub_path, "/Android/") == 0));
    d->hide_others = (!skip_sandbox && current_pkg[0] && strcmp(current_pkg, "system") != 0 &&
                      strcmp(current_pkg, "unknown") != 0);
    d->has_data = d->has_obb = d->has_android = d->has_pkg = false;
}

/* 合成目录条目输出（经 ht 去重）。返回 false = filler 缓冲已满，须立即结束 */
static bool vfs_readdir_emit_dedup(VfsReaddirCtx* d, const char* name) {
    if (!vfs_hash_insert(&d->ht, name)) return true; /* 已存在：跳过 */
    struct stat st;
    memset(&st, 0, sizeof(st));
    st.st_ino = synthetic_inode(name);
    st.st_mode = S_IFDIR | 0755;
    st.st_uid = d->ctx->uid;
    st.st_gid = d->ctx->gid;
    return d->filler(d->buf, name, &st, 0, 0) == 0;
}

/* 合成目录条目输出（不经 ht 去重）：data/obb 骨架沿用原语义——物理扫描未
   出现即补，不与后续虚拟目录条目去重。返回 false = filler 缓冲已满 */
static bool vfs_readdir_emit_raw(VfsReaddirCtx* d, const char* name) {
    struct stat st;
    memset(&st, 0, sizeof(st));
    st.st_ino = synthetic_inode(name);
    st.st_mode = S_IFDIR | 0755;
    st.st_uid = d->ctx->uid;
    st.st_gid = d->ctx->gid;
    return d->filler(d->buf, name, &st, 0, 0) == 0;
}

/* 本地目录扫描：probe 条目级过滤（hidden/redirect_target）+ ht 去重 +
   lstat + filler，并记录 Android/data/obb/自身包名骨架项是否已出现。
   dp 由调用方打开并负责关闭。返回 false = filler 缓冲已满，须立即结束。 */
static bool vfs_readdir_scan_local(VfsReaddirCtx* d, DIR* dp) {
    char item_sub_path[2048], item_real_path[2048];
    /* 循环外复用查询上下文，只改 path——省每条目结构初始化 */
    NspQueryCtx probe_q = {
        .uid = d->ctx->uid, .pid = d->ctx->pid, .gid = d->ctx->gid, .path = NULL};
    struct dirent* de;
    while ((de = readdir(dp)) != nullptr) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (d->is_root)
            readdir_join(item_sub_path, 2047, "", de->d_name);
        else
            readdir_join(item_sub_path, 2047, d->sub_path, de->d_name);
        if (path_contains_invalid_chars(de->d_name)) continue;
        /* 子项轻量探测（probe）：只判 hidden/redirect_target，不构建真实路径、
           不触发 sandbox 目录创建（无模块时直通不过滤）。
           user_id 目录条目（/0、/1...）旧语义用原始串判 redirect_target 恒 false
           （Trie 无数字前缀规则）；剥离 /0/ 后会误判为根目录 sandbox 重定向目标，
           故豁免其 redirect_target 检查（仅 hidden 生效）。
           hidden 过滤对所有访问者生效（含 root，与 getattr 的 hidden 拒绝一致）：
           否则 root ls 时被 HIDE 的条目仍出现在列表（stat 却失败），隐藏不彻底 */
        bool uid_dir = false;
        if (item_sub_path[0] == '/' && isdigit((unsigned char)item_sub_path[1])) {
            const char* dg = item_sub_path + 1;
            while (isdigit((unsigned char)*dg)) dg++;
            uid_dir = (*dg == '\0' || *dg == '/');
        }
        probe_q.path = item_sub_path;
        NspProbeResult ir;
        memset(&ir, 0, sizeof ir);
        if (module_dispatch_probe(&probe_q, &ir) == NSP_DISPATCH_OK && ir.valid) {
            if (ir.appear_missing || (!uid_dir && ir.virtual_kind == NSP_VK_TARGET)) continue;
        }
        if (d->is_root && strcmp(de->d_name, "Android") == 0) d->has_android = true;
        if (d->is_android_dir) {
            if (strcmp(de->d_name, "data") == 0)
                d->has_data = true;
            else if (strcmp(de->d_name, "obb") == 0)
                d->has_obb = true;
        }
        if (d->hide_others && (strcmp(d->sub_path, "/Android/data") == 0 ||
                               strcmp(d->sub_path, "/Android/data/") == 0 ||
                               strcmp(d->sub_path, "/Android/obb") == 0 ||
                               strcmp(d->sub_path, "/Android/obb/") == 0)) {
            if (strcmp(de->d_name, d->current_pkg) != 0) continue;
            d->has_pkg = true;
        }
        if (vfs_hash_insert(&d->ht, de->d_name)) {
            struct stat st;
            memset(&st, 0, sizeof(st));
            readdir_join(item_real_path, 2047, d->real_path, de->d_name);
            if (lstat(item_real_path, &st) == 0) {
                if (!g_preserve_perms) {
                    st.st_uid = d->ctx->uid;
                    st.st_gid = d->ctx->gid;
                }
                if (d->filler(d->buf, de->d_name, &st, 0, 0) != 0) return false;
            } else {
                if (d->filler(d->buf, de->d_name, nullptr, 0, 0) != 0) return false;
            }
        }
    }
    return true;
}

/* 根目录虚拟 Android 骨架：物理循环未出现 Android 时补合成。ALLOW /Android 会
   使物理循环按 redirect_target 跳过真实 Android（has_android=false），而虚拟
   目录补充仍会经 ht 合成 Android——必须走同一 ht 去重，否则出现两个 Android。 */
static bool vfs_readdir_fill_android_skel(VfsReaddirCtx* d) {
    if (!(d->is_root && d->hide_others && !d->has_android)) return true;
    return vfs_readdir_emit_dedup(d, "Android");
}

/* /Android 下 data/obb 骨架补齐（无用户层/沙盒关闭时不合成） */
static bool vfs_readdir_fill_android_children(VfsReaddirCtx* d) {
    if (!d->is_android_dir) return true;
    if (!d->has_data && !vfs_readdir_emit_raw(d, "data")) return false;
    if (!d->has_obb && !vfs_readdir_emit_raw(d, "obb")) return false;
    return true;
}

/* /Android/data|obb 下访问者自身包名骨架补齐（跨应用隔离下仅见自身） */
static bool vfs_readdir_fill_own_pkg(VfsReaddirCtx* d) {
    if (!(d->hide_others && !d->has_pkg &&
          (strcmp(d->sub_path, "/Android/data") == 0 ||
           strcmp(d->sub_path, "/Android/data/") == 0 || strcmp(d->sub_path, "/Android/obb") == 0 ||
           strcmp(d->sub_path, "/Android/obb/") == 0)))
        return true;
    return vfs_readdir_emit_dedup(d, d->current_pkg);
}

/* 虚拟目录补充：模块 readdir_extra 返回条目数组，框架 ht 去重 + filler。
   虚拟条目（如 FTP 前缀目录）权限继承其本地上级——用户存储根
   /data/media/<uid>/（FTP 虚拟路径在本地不存在，直接父目录 lstat 必失败），
   而非固定 root/访问者属主 */
static bool vfs_readdir_fill_virtual(VfsReaddirCtx* d, int path_user_id) {
    NspDirEntry virt[MAX_MODULES * 8];
    NspQueryCtx vq = {
        .uid = d->ctx->uid, .pid = d->ctx->pid, .gid = d->ctx->gid, .path = d->sub_path};
    struct stat parent_st;
    memset(&parent_st, 0, sizeof(parent_st));
    bool have_parent = false;
    {
        int root_uid = (path_user_id >= 0) ? path_user_id : 0;
        char root_path[PATH_MAX];
        common_storage_root(root_uid, root_path, sizeof(root_path));
        have_parent = (lstat(root_path, &parent_st) == 0);
    }
    int vn = module_dispatch_readdir(&vq, d->sub_path, path_user_id, d->current_pkg, d->is_root,
                                     virt, MAX_MODULES * 8);
    /* 纵深防御：dispatch 已钳制，但仍钳制 vn 防栈越界读 */
    if (vn < 0) vn = 0;
    if (vn > MAX_MODULES * 8) vn = MAX_MODULES * 8;
    for (int vi = 0; vi < vn; vi++) {
        if (virt[vi].name[0] == '\0') continue;
        if (!vfs_hash_insert(&d->ht, virt[vi].name)) continue;
        struct stat st_dir;
        memset(&st_dir, 0, sizeof(st_dir));
        st_dir.st_ino = synthetic_inode(virt[vi].name);
        st_dir.st_mode = S_IFDIR;
        if (g_preserve_perms && have_parent) {
            /* 权限完全镜像模式：虚拟条目（如 FTP 前缀目录）继承
               用户存储根属主/组与权限位——与 vfs_getattr FTP 分支
               语义一致（默认伪造模式下两者均用访问者属主） */
            st_dir.st_mode |= (parent_st.st_mode & 07777);
            st_dir.st_uid = parent_st.st_uid;
            st_dir.st_gid = parent_st.st_gid;
        } else {
            st_dir.st_mode |= 0755;
            st_dir.st_uid = d->ctx->uid;
            st_dir.st_gid = d->ctx->gid;
        }
        if (d->filler(d->buf, virt[vi].name, &st_dir, 0, 0) != 0) return false;
    }
    return true;
}

/* POSIX readdir 收尾：恒含 . / ..（与本地文件系统 readdir 路径一致） */
static bool vfs_readdir_fill_dots(VfsReaddirCtx* d) {
    if (d->filler(d->buf, ".", nullptr, 0, 0) != 0) return false;
    if (d->filler(d->buf, "..", nullptr, 0, 0) != 0) return false;
    return true;
}

static int vfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset,
                       struct fuse_file_info* fi, enum fuse_readdir_flags flags) {
    vfs_flush_pending_closes();
    (void)offset;
    (void)flags;
    (void)fi;
    VFS_SETUP_CORE(path, VFS_OP_READ);
    vfs_log_io(current_pkg, ctx->uid, "READDIR", sub_path,
               (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    LOG_DBG_PERF("[READDIR_ENTRY] path=%s real=%s", path, p);

    /* 后端分派：readdir 由模块方法返回条目，框架负责 filler */
    int brc = 0;
    if (vfs_readdir_backend(ctx, sub_path, rr.is_ftp, buf, filler, &brc)) VFS_RETURN(brc);

    VfsReaddirCtx d;
    vfs_readdir_ctx_init(&d, ctx, sub_path, p, current_pkg, path_user_id, buf, filler);
    DIR* dp = opendir(p);
    if (!dp) {
        int err = errno;
        /* 骨架/虚拟目录允许无真实底层目录，不视为错误 */
        if (!is_android_skel_dir(sub_path) &&
            !(err == ENOENT && (rr.virtual_kind == NSP_VK_ANCESTOR || rr.virtual_kind == NSP_VK_TARGET))) {
            log_fuse_err("READDIR", path, err);
        }
    } else {
        bool scan_ok = vfs_readdir_scan_local(&d, dp);
        closedir(dp);
        if (!scan_ok) {
            vfs_hash_free(&d.ht);
            VFS_RETURN(0);
        }
    }
    /* 合成阶段：任一 filler 缓冲已满即短路停止（各阶段返回码同为 0） */
    (void)(vfs_readdir_fill_android_skel(&d) && vfs_readdir_fill_android_children(&d) &&
           vfs_readdir_fill_own_pkg(&d) && vfs_readdir_fill_virtual(&d, path_user_id) &&
           vfs_readdir_fill_dots(&d));
    vfs_hash_free(&d.ht);
    VFS_RETURN(0);
}

static void inherit_parent_attributes(const char* real_path, mode_t base_mode) {
    char parent[PATH_MAX];
    strncpy(parent, real_path, PATH_MAX - 1);
    parent[PATH_MAX - 1] = '\0';
    char* last = strrchr(parent, '/');
    if (last) {
        if (last == parent)
            strcpy(parent, "/");
        else
            *last = '\0';
        struct stat st;
        if (lstat(parent, &st) == 0) {
            if (lchown(real_path, st.st_uid, st.st_gid) != 0) {
            }
            mode_t final_mode = st.st_mode & 07777;
            if (!S_ISDIR(base_mode)) {
                final_mode &= ~0111;
                final_mode &= ~06000;
            }
            chmod(real_path, final_mode);
#ifdef TARGET_ANDROID
            char context[256];
            ssize_t ctx_len = lgetxattr(parent, "security.selinux", context, sizeof(context));
            if (ctx_len > 0)
                lsetxattr(real_path, "security.selinux", context, (size_t)ctx_len, 0);
            else if (strstr(real_path, STORAGE_BASE) == real_path)
                lsetxattr(real_path, "security.selinux", "u:object_r:media_rw_data_file:s0", 35, 0);
#endif
        }
    }
}

static int vfs_open(const char* path, struct fuse_file_info* fi) {
    FTP_DBG("vfs_open: 入口 path=%s\n", path);
    vfs_flush_pending_closes();
    VFS_SETUP_CORE(path, VFS_OP_READ);
    vfs_log_io(current_pkg, ctx->uid, "OPEN", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL,
               nsp_ok ? rr.monitor_on : false);
    if (g_strip_o_direct && (fi->flags & O_DIRECT)) fi->flags &= ~O_DIRECT;
    /* open 归类 VFS_OP_READ（O_RDONLY 打开 RO 路径必须放行），只在 flags 表明
       要写时走框架只读策略；策略本身仍在 vfs_check_read_only 单点 */
    {
        int accmode = fi->flags & O_ACCMODE;
        if (accmode == O_WRONLY || accmode == O_RDWR || (fi->flags & O_CREAT) ||
            (fi->flags & O_TRUNC) || (fi->flags & O_APPEND)) {
            int ro_rc = vfs_check_read_only(&rr, ctx->uid);
            if (ro_rc != 0) {
                log_fuse_err("OPEN_RO_DENIED", path, -ro_rc);
                VFS_RETURN(ro_rc);
            }
        }
    }
    /* 后端分派：open 由模块方法打开，fi->fh 存后端句柄（read/write 经槽位快速分派） */
    int bslot = -1;
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup_slot(sub_path, &bslot, &bops) == 0) {
        if (!bops->backend_open) {
            /* 模块未提供 open 回调：释放 lookup_slot 在途引用后走本地 open */
            module_backend_put(bops);
        } else {
            uint64_t h = 0;
            int brc = nsp_fence_backend_open(bslot, "backend_open", bops->backend_open, sub_path,
                                             fi->flags, &h);
            module_backend_put(bops);
            if (brc == NSP_FENCE_FAULT) {
                module_guard_fault(bslot, "backend_open", sub_path);
                VFS_RETURN(-EIO);
            }
            if (brc != 0) {
                if (brc != NSP_FENCE_BADFN && !backend_rc_is_business(brc))
                    module_guard_error(bslot, "backend_open", brc, sub_path, "open 返回异常");
                VFS_RETURN(brc < 0 ? brc : -EIO);
            }
            /* FTP 路径：句柄为模块小整数 ID（非 fd），不设 FD 透传等本地
               文件系统才可用的优化（passthrough 仅对下方本地 open 的 fd）；
               设 direct_io 绕过内核 page cache——FUSE 内核在 close 后可能
               失效 page cache，但 dentry 缓存仍命中第二次 open 导致 read
               返回空（复用缓存的 fh 但 page cache 已空）。
               fh 高位编码模块槽位：read/write/flush/release/fsync 经
               module_backend_acquire_slot 无锁快速分派，免每 IO 路径解析
               与线性扫描（模块卸载时快照置空→快速失败，不悬垂） */
            fi->fh =
                h | NSP_FH_BACKEND_FLAG | ((uint64_t)(bslot & 0x7F) << NSP_FH_BACKEND_SLOT_SHIFT);
            fi->direct_io = 1;
            FTP_DBG("vfs_open: 后端命中 sub=%s fh=%llu slot=%d flags=%o direct_io=1\n", sub_path,
                    (unsigned long long)fi->fh, bslot, fi->flags);
            VFS_RETURN(0);
        }
    }
    int fd = open(p, fi->flags | O_CLOEXEC, is_redir ? 0666 : 0);
    if (fd == -1) {
        int err = errno;
        log_fuse_err("OPEN", path, err);
        if (err != ENOENT)
            vfs_log_io_err(current_pkg, "OPEN", sub_path, "errno=%d real='%s'", err, p);
        VFS_RETURN(-err);
    }
    fi->fh = fd;
    if (g_passthrough_enabled) {
        int backing_id = passthrough_enable_fixed_method(fd);
        if (backing_id > 0) {
#ifdef TARGET_ANDROID
            fi->passthrough_fh = (uint32_t)backing_id; /* 定制 libfuse 的透传句柄字段 */
#else
            fi->backing_id = (int32_t)backing_id; /* 系统 libfuse 官方高层透传字段 */
#endif
            LOG_DBG_PERF("FUSE Passthrough: ✅ %s -> backing_id=%d", sub_path, backing_id);
        } else {
            LOG_DBG_PERF("FUSE Passthrough: ❌ %s -> %s (errno=%d)", sub_path, strerror(errno),
                         errno);
        }
    }
    VFS_RETURN(0);
}

static int vfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    VFS_SETUP_CORE(path, VFS_OP_MUTATE);
    vfs_log_io(current_pkg, ctx->uid, "CREATE", sub_path,
               (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    if (g_strip_o_direct && (fi->flags & O_DIRECT)) fi->flags &= ~O_DIRECT;
    /* 后端分派：create 由模块方法创建，fi->fh 存后端句柄（含模块槽位） */
    int bslot = -1;
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup_slot(sub_path, &bslot, &bops) == 0) {
        if (!bops->backend_create) {
            /* 模块未提供 create 回调：释放 lookup_slot 在途引用后走本地创建 */
            module_backend_put(bops);
        } else {
            uint64_t h = 0;
            int brc = nsp_fence_backend_create(bslot, "backend_create", bops->backend_create,
                                               sub_path, mode, &h);
            module_backend_put(bops);
            if (brc == NSP_FENCE_FAULT) {
                module_guard_fault(bslot, "backend_create", sub_path);
                VFS_RETURN(-EIO);
            }
            if (brc != 0) {
                if (brc != NSP_FENCE_BADFN && !backend_rc_is_business(brc))
                    module_guard_error(bslot, "backend_create", brc, sub_path, "create 返回异常");
                VFS_RETURN(brc < 0 ? brc : -EIO);
            }
            fi->fh =
                h | NSP_FH_BACKEND_FLAG | ((uint64_t)(bslot & 0x7F) << NSP_FH_BACKEND_SLOT_SHIFT);
            VFS_RETURN(0);
        }
    }
    int fd = open(p, fi->flags | O_CREAT | O_EXCL | O_CLOEXEC, is_redir ? 0666 : mode);
    if (fd == -1) {
        if (errno == ENOENT) {
            char *p_dup = strdup(p), *p_dir = dirname(p_dup);
            if (mkdir_recursive_p(p_dir, 0775) == 0)
                fd = open(p, fi->flags | O_CREAT | O_EXCL | O_CLOEXEC, is_redir ? 0666 : mode);
            free(p_dup);
        }
        if (fd == -1) {
            int err = errno;
            log_fuse_err("CREATE", path, err);
            if (err != EEXIST) vfs_log_io_err(current_pkg, "CREATE", sub_path, "errno=%d", err);
            VFS_RETURN(-err);
        }
    }
    inherit_parent_attributes(p, S_IFREG);
    fi->fh = fd;
    if (g_passthrough_enabled) {
        int backing_id = passthrough_enable_fixed_method(fd);
        if (backing_id > 0) {
#ifdef TARGET_ANDROID
            fi->passthrough_fh = (uint32_t)backing_id; /* 定制 libfuse 的透传句柄字段 */
#else
            fi->backing_id = (int32_t)backing_id; /* 系统 libfuse 官方高层透传字段 */
#endif
            LOG_DBG_PERF("FUSE Passthrough: ✅ %s -> backing_id=%d", sub_path, backing_id);
        } else {
            LOG_DBG_PERF("FUSE Passthrough: ❌ %s -> %s (errno=%d)", sub_path, strerror(errno),
                         errno);
        }
    }
    VFS_RETURN(0);
}

static int vfs_mkdir(const char* path, mode_t mode) {
    VFS_SETUP_CORE(path, VFS_OP_MUTATE);
    vfs_log_io(current_pkg, ctx->uid, "MKDIR", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL,
               nsp_ok ? rr.monitor_on : false);
    /* 后端分派：mkdir 由模块方法创建（rr.is_ftp 短路，避免非 FTP 路径付出
       无条件 rwlock + backend_match 扫描） */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0 && bops && bops->backend_mkdir) {
        int bslot = module_ops_slot(bops);
        int brc =
            nsp_fence_backend_mkdir(bslot, "backend_mkdir", bops->backend_mkdir, sub_path, mode);
        module_backend_put(bops);
        if (brc == NSP_FENCE_FAULT) {
            module_guard_fault(bslot, "backend_mkdir", sub_path);
            VFS_RETURN(-EIO);
        }
        if (brc != 0) {
            if (brc != NSP_FENCE_BADFN && !backend_rc_is_business(brc))
                module_guard_error(bslot, "backend_mkdir", brc, sub_path, "mkdir 返回异常");
            VFS_RETURN(brc < 0 ? brc : -EIO);
        }
        VFS_RETURN(0);
    }
    /* fallback：lookup 成功但未走后端分支时释放引用，防止 backend_refs 泄漏
       导致模块无法热卸载（loader 等待 backend_refs == 0） */
    if (bops) module_backend_put(bops);
    int ret = mkdir(p, is_redir ? 0775 : mode);
    if (ret == -1) {
        if (errno == ENOENT) {
            char *p_dup = strdup(p), *parent = dirname(p_dup);
            if (mkdir_recursive_p(parent, 0775) == 0) ret = mkdir(p, is_redir ? 0775 : mode);
            free(p_dup);
        }
        if (ret == -1) {
            int err = errno;
            log_fuse_err("MKDIR", path, err);
            if (err != EEXIST) vfs_log_io_err(current_pkg, "MKDIR", sub_path, "errno=%d", err);
            VFS_RETURN(-err);
        }
    }
    inherit_parent_attributes(p, S_IFDIR);
    VFS_RETURN(0);
}

static int vfs_unlink(const char* path) {
    VFS_SETUP_CORE(path, VFS_OP_MUTATE);
    vfs_log_io(current_pkg, ctx->uid, "UNLINK", sub_path,
               (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    /* 后端分派：unlink 由模块方法删除 */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0) {
        if (!bops->backend_unlink) {
            /* 模块未提供 unlink 回调：释放 lookup 在途引用后走本地 unlink */
            module_backend_put(bops);
        } else {
            int bslot = module_ops_slot(bops);
            int brc =
                nsp_fence_backend_simple(bslot, "backend_unlink", bops->backend_unlink, sub_path);
            module_backend_put(bops);
            if (brc == NSP_FENCE_FAULT) {
                module_guard_fault(bslot, "backend_unlink", sub_path);
                VFS_RETURN(-EIO);
            }
            if (brc != 0) {
                if (brc != NSP_FENCE_BADFN && !backend_rc_is_business(brc))
                    module_guard_error(bslot, "backend_unlink", brc, sub_path, "unlink 返回异常");
                VFS_RETURN(brc < 0 ? brc : -EIO);
            }
            VFS_RETURN(0);
        }
    }
    int ret = unlink(p);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("UNLINK", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_rmdir(const char* path) {
    VFS_SETUP_CORE(path, VFS_OP_MUTATE);
    vfs_log_io(current_pkg, ctx->uid, "RMDIR", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL,
               nsp_ok ? rr.monitor_on : false);
    if (rr.virtual_kind == NSP_VK_ANCESTOR || rr.virtual_kind == NSP_VK_TARGET) {
        if (!fw_virtual_dir_empty(sub_path, p, current_pkg, path_user_id, ctx->uid)) {
            log_fuse_err("RMDIR_NOT_EMPTY", path, ENOTEMPTY);
            VFS_RETURN(-ENOTEMPTY);
        }
        int ret = rmdir(p);
        if (ret == -1 && errno != ENOENT) {
            int err = errno;
            log_fuse_err("RMDIR", path, err);
            VFS_RETURN(-err);
        }
        VFS_RETURN(0);
    }
    /* 后端分派：rmdir 由模块方法删除 */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0) {
        if (!bops->backend_rmdir) {
            /* 模块未提供 rmdir 回调：释放 lookup 在途引用后走本地 rmdir */
            module_backend_put(bops);
        } else {
            int bslot = module_ops_slot(bops);
            int brc =
                nsp_fence_backend_simple(bslot, "backend_rmdir", bops->backend_rmdir, sub_path);
            module_backend_put(bops);
            if (brc == NSP_FENCE_FAULT) {
                module_guard_fault(bslot, "backend_rmdir", sub_path);
                VFS_RETURN(-EIO);
            }
            if (brc != 0) {
                if (brc != NSP_FENCE_BADFN && !backend_rc_is_business(brc))
                    module_guard_error(bslot, "backend_rmdir", brc, sub_path, "rmdir 返回异常");
                VFS_RETURN(brc < 0 ? brc : -EIO);
            }
            VFS_RETURN(0);
        }
    }
    int ret = rmdir(p);
    if (ret == -1) {
        int err = errno;
        if (err == ENOTEMPTY) {
            int r = recursive_rmdir(p);
            if (r == 0) VFS_RETURN(0);
            log_fuse_err("RMDIR", path, -r);
            VFS_RETURN(r);
        }
        log_fuse_err("RMDIR", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_read(const char* path, char* buf, size_t size, off_t off,
                    struct fuse_file_info* fi) {
    FTP_DBG("vfs_read: 入口 path=%s fh=%llu off=%lld size=%zu\n", path,
            (unsigned long long)(fi ? fi->fh : 0), (long long)off, size);
    if (fi->fh & NSP_FH_BACKEND_FLAG) {
        /* 后端句柄（本地 fd 无标记）：经 fh 高位槽位快速分派，免每 IO
           路径解析与线性扫描。模块卸载时快照已置空 → acquire 失败返回 -EIO，
           不把后端句柄当 fd 用（pread 后端 ID 会 EBADF 或崩溃） */
        int slot = (int)((fi->fh & NSP_FH_BACKEND_SLOT_MASK) >> NSP_FH_BACKEND_SLOT_SHIFT);
        const NspModuleOps* bops = NULL;
        FTP_DBG("vfs_read: fh=%llu slot=%d\n", (unsigned long long)fi->fh, slot);
        if (module_backend_acquire_slot(slot, &bops) == 0) {
            if (bops->backend_read) {
                size_t got = 0;
                int rc = nsp_fence_backend_read(slot, "backend_read", bops->backend_read,
                                                fi->fh & NSP_FH_HANDLE_MASK, (char*)buf, size, off,
                                                &got);
                module_backend_release_slot(slot);
                if (rc == NSP_FENCE_FAULT) {
                    module_guard_fault(slot, "backend_read", path);
                    FTP_DBG("vfs_read: 后端围栏恢复\n");
                    return -EIO;
                }
                FTP_DBG("vfs_read: 后端返回 rc=%d got=%zu\n", rc, got);
                if (rc != 0 && rc != NSP_FENCE_BADFN && !backend_rc_is_business(rc))
                    module_guard_error(slot, "backend_read", rc, path, "read 返回异常");
                return rc == 0 ? (int)got : (rc < 0 ? rc : -EIO);
            }
            /* 模块未提供 read 回调：释放引用后按未命中处理 */
            module_backend_release_slot(slot);
        }
        FTP_DBG("vfs_read: 后端未命中 slot=%d\n", slot);
        return -EIO;
    }
    ssize_t ret = pread(fi->fh, buf, size, off);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("READ", path, err);
        return -err;
    }
    return (int)ret;
}

static int vfs_write(const char* path, const char* buf, size_t size, off_t off,
                     struct fuse_file_info* fi) {
    /* 与 vfs_read 对齐：仅后端句柄（带 NSP_FH_BACKEND_FLAG）才走模块分派。
       缺少该检查时，FTP 等后端模块加载后本地 fd 的写入会误入后端分支：
       module_backend_lookup 对本地路径不命中 → 返回 -EIO，本地写入全部失败；
       若路径恰与后端前缀匹配还会把本地 fd 数值当作后端句柄 ID 传入。 */
    if (fi->fh & NSP_FH_BACKEND_FLAG) {
        int slot = (int)((fi->fh & NSP_FH_BACKEND_SLOT_MASK) >> NSP_FH_BACKEND_SLOT_SHIFT);
        const NspModuleOps* bops = NULL;
        if (module_backend_acquire_slot(slot, &bops) == 0) {
            if (bops->backend_write) {
                size_t wrote = 0;
                int rc = nsp_fence_backend_write(slot, "backend_write", bops->backend_write,
                                                 fi->fh & NSP_FH_HANDLE_MASK, (const char*)buf,
                                                 size, off, &wrote);
                module_backend_release_slot(slot);
                if (rc == NSP_FENCE_FAULT) {
                    module_guard_fault(slot, "backend_write", path);
                    return -EIO;
                }
                if (rc != 0 && rc != NSP_FENCE_BADFN && !backend_rc_is_business(rc))
                    module_guard_error(slot, "backend_write", rc, path, "write 返回异常");
                return rc == 0 ? (int)wrote : (rc < 0 ? rc : -EIO);
            }
            module_backend_release_slot(slot);
        }
        return -EIO; /* 后端句柄未命中后端，不 pwrite */
    }
    ssize_t ret = pwrite(fi->fh, buf, size, off);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("WRITE", path, err);
        return -err;
    }
    return (int)ret;
}

static int vfs_release(const char* path, struct fuse_file_info* fi) {
    FTP_DBG("vfs_release: 入口 path=%s fh=%llu\n", path, (unsigned long long)(fi ? fi->fh : 0));
    if (fi->fh & NSP_FH_BACKEND_FLAG) {
        /* 后端句柄（本地 fd 无标记）：经 fh 高位槽位快速分派，避免完整
           resolve 在 HIDE/解析失败时提前返回而泄漏已打开的 fd；未命中后端
           则兜底不 close（非 fd，避免崩溃） */
        int slot = (int)((fi->fh & NSP_FH_BACKEND_SLOT_MASK) >> NSP_FH_BACKEND_SLOT_SHIFT);
        const NspModuleOps* bops = NULL;
        if (module_backend_acquire_slot(slot, &bops) == 0) {
            if (bops->backend_release) {
                int rc = nsp_fence_backend_release(slot, "backend_release", bops->backend_release,
                                                   fi->fh & NSP_FH_HANDLE_MASK);
                module_backend_release_slot(slot);
                if (rc == NSP_FENCE_FAULT) {
                    module_guard_fault(slot, "backend_release", path);
                    rc = -EIO;
                } else if (rc != 0 && rc != NSP_FENCE_BADFN && !backend_rc_is_business(rc))
                    module_guard_error(slot, "backend_release", rc, path, "release 返回异常");
                /* 句柄销毁唯一入口（FLUSH 只收尾数据不释放句柄）：
                   -EINVAL 容忍作防御（模块异常/重复释放时避免传播错误） */
                return (rc == -EINVAL) ? 0 : (rc < 0 ? rc : 0);
            }
            module_backend_release_slot(slot);
        }
        return 0; /* 后端句柄未命中后端：不 close（非 fd），避免崩溃 */
    }
    close(fi->fh);
    return 0;
}

static int vfs_fsync(const char* path, int datasync, struct fuse_file_info* fi) {
    if (fi->fh & NSP_FH_BACKEND_FLAG) {
        int slot = (int)((fi->fh & NSP_FH_BACKEND_SLOT_MASK) >> NSP_FH_BACKEND_SLOT_SHIFT);
        const NspModuleOps* bops = NULL;
        if (module_backend_acquire_slot(slot, &bops) == 0) {
            module_backend_release_slot(slot);
            return 0; /* 后端文件：数据同步语义由模块 FLUSH/RELEASE 收尾负责 */
        }
        return 0;
    }
    if (!fi || fi->fh <= 0) return 0;
    int ret = (datasync ? fdatasync(fi->fh) : fsync(fi->fh));
    if (ret == -1) {
        if (errno == EBADF || errno == EINVAL) return 0;
        log_fuse_err("FSYNC", path, errno);
        return -errno;
    }
    return 0;
}

/* ================= 路径缓存失效（框架侧唯一出口） =================
 * 两级语义互补，需同时做：
 *   - inode 级 fuse_invalidate_path：丢属性/数据缓存。对已打开的文件
 *     立即生效（句柄直接持 inode，不再经名字查找）；
 *   - entry 级 fuse_invalidate_path_entry：丢内核 dentry，使「名字 →
 *     inode」重新 lookup。远端增删/改名后只有它能让旧映射立刻失效——
 *     inode 级不触碰名字映射，旧 dentry 会一直命中到 entry_timeout 到期。
 * entry 级是项目内 libfuse 分支（subprojects/libfuse，master-Android）追加
 * 的接口，上游/系统/预构建 libfuse 均无此符号，故用弱引用：缺失时自动
 * 退化为仅 inode 级，不影响在系统库上的构建与运行。行为回归见
 * tests/test_libfuse_inval.py。 */
extern int fuse_invalidate_path_entry(struct fuse* f, const char* path)
    __attribute__((weak));

static void vfs_inval_path(struct fuse* f, const char* path) {
    if (!f) return;
    fuse_invalidate_path(f, path);
    if (fuse_invalidate_path_entry) fuse_invalidate_path_entry(f, path);
}

static int vfs_flush(const char* path, struct fuse_file_info* fi) {
    /* close() 同步等待 FLUSH 返回——写模式 STOR 上传必须在此完成（FLUSH
       错误会传播给 close() → 应用读到 EIO）。backend_flush 只收尾数据、
       **不销毁句柄**：FUSE 的 FLUSH 可因 dup/fork 对同一句柄调用多次，
       销毁必须等 RELEASE（最后一个引用关闭后），否则存活 fd 的后续
       读写会命中已销毁句柄（-EINVAL 确定性失败） */
    /* 后端分派：flush 由模块方法收尾数据（不销毁句柄） */
    if (fi->fh & NSP_FH_BACKEND_FLAG) {
        int slot = (int)((fi->fh & NSP_FH_BACKEND_SLOT_MASK) >> NSP_FH_BACKEND_SLOT_SHIFT);
        const NspModuleOps* bops = NULL;
        if (module_backend_acquire_slot(slot, &bops) == 0) {
            int rc = 0;
            if (bops->backend_flush)
                rc = nsp_fence_backend_flush(slot, "backend_flush", bops->backend_flush,
                                             fi->fh & NSP_FH_HANDLE_MASK);
            module_backend_release_slot(slot);
            if (rc == NSP_FENCE_FAULT) {
                module_guard_fault(slot, "backend_flush", path);
                rc = -EIO;
            } else if (rc != 0 && rc != NSP_FENCE_BADFN && !backend_rc_is_business(rc))
                module_guard_error(slot, "backend_flush", rc, path, "flush 返回异常");
            if (rc == 0) {
                /* 数据已落盘（上传完成）：使路径缓存失效，否则立即读取
                   会命中旧属性/旧 dentry */
                struct fuse_context* ctx = fuse_get_context();
                if (ctx) vfs_inval_path(ctx->fuse, path);
            }
            return rc < 0 ? rc : 0;
        }
        return 0;
    }
    /* 非后端文件：仅写模式 open 才在 close 时同步落盘（只读 open 无需
       写回，避免每次 close 无条件 fsync 的热路径吞吐回归）；fsync 失败
       传播给 close()（写回错误不再静默吞掉） */
    if ((fi->flags & O_ACCMODE) != O_RDONLY) {
        if (fsync(fi->fh) == -1) return -errno;
    }
    return 0;
}

static int vfs_readlink(const char* path, char* buf, size_t size) {
    VFS_SETUP_CORE(path, VFS_OP_READ);
    vfs_log_io(current_pkg, ctx->uid, "READLINK", sub_path,
               (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    ssize_t res = readlink(p, buf, size - 1);
    if (res == -1) {
        log_fuse_err("READLINK", path, errno);
        VFS_RETURN(-errno);
    }
    buf[res] = '\0';
    VFS_RETURN(0);
}

static int vfs_opendir(const char* path, struct fuse_file_info* fi) {
    VFS_SETUP_CORE(path, VFS_OP_READ);
    vfs_log_io(current_pkg, ctx->uid, "OPENDIR", sub_path,
               (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    /* 后端分派：目录由后端模块管理时直接放行（readdir 条目由模块方法提供，
       本地 real_path 不存在，不可 opendir） */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0) {
        module_backend_put(bops);
        fi->fh = 0;
        VFS_RETURN(0);
    }
    DIR* dp = opendir(p);
    if (dp) {
        closedir(dp);
        fi->fh = 0;
        VFS_RETURN(0);
    }
    int err = errno;
    if ((err == ENOENT || err == EACCES) &&
        (is_android_skel_dir(sub_path) || rr.virtual_kind == NSP_VK_ANCESTOR || rr.virtual_kind == NSP_VK_TARGET)) {
        VFS_RETURN(0);
    }
    log_fuse_err("OPENDIR", path, err);
    VFS_RETURN(-err);
}

static int vfs_symlink(const char* target, const char* linkpath) {
    VFS_SETUP_CORE(linkpath, VFS_OP_MUTATE);
    vfs_log_io(current_pkg, ctx->uid, "SYMLINK", sub_path,
               (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    if (symlink(target, p) == -1) {
        if (errno == ENOENT) {
            char *p_dup = strdup(p), *p_dir = dirname(p_dup);
            if (mkdir_recursive_p(p_dir, 0775) == 0 && symlink(target, p) == 0) {
                free(p_dup);
                inherit_parent_attributes(p, S_IFLNK);
                VFS_RETURN(0);
            }
            free(p_dup);
        }
        log_fuse_err("SYMLINK", linkpath, errno);
        VFS_RETURN(-errno);
    }
    inherit_parent_attributes(p, S_IFLNK);
    VFS_RETURN(0);
}

static int recursive_rmdir(const char* path) {
    DIR* d = opendir(path);
    if (!d) return -errno;
    struct dirent* p;
    int r = 0;
    while (!r && (p = readdir(d))) {
        if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) continue;
        char buf[PATH_MAX];
        snprintf(buf, sizeof(buf), "%s/%s", path, p->d_name);
        struct stat statbuf;
        if (!lstat(buf, &statbuf)) {
            if (S_ISDIR(statbuf.st_mode))
                r = recursive_rmdir(buf);
            else
                r = unlink(buf);
        }
    }
    closedir(d);
    if (!r) r = rmdir(path);
    return r;
}

static int recursive_copy_dir(const char* src, const char* dst, uid_t uid, gid_t gid) {
    struct stat st;
    if (lstat(src, &st) != 0) return -errno;
    if (mkdir(dst, st.st_mode & 07777) != 0 && errno != EEXIST) return -errno;
    lchown(dst, st.st_uid, st.st_gid);
    DIR* d = opendir(src);
    if (!d) return -errno;
    struct dirent* p;
    int r = 0;
    while (!r && (p = readdir(d))) {
        if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) continue;
        char s_path[PATH_MAX], d_path[PATH_MAX];
        snprintf(s_path, sizeof(s_path), "%s/%s", src, p->d_name);
        snprintf(d_path, sizeof(d_path), "%s/%s", dst, p->d_name);
        struct stat s_st;
        if (!lstat(s_path, &s_st)) {
            if (S_ISDIR(s_st.st_mode)) {
                r = recursive_copy_dir(s_path, d_path, uid, gid);
            } else if (S_ISREG(s_st.st_mode)) {
                int fd_src = open(s_path, O_RDONLY | O_CLOEXEC);
                if (fd_src >= 0) {
                    int fd_dst =
                        open(d_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, s_st.st_mode & 0777);
                    if (fd_dst >= 0) {
                        char buf[16384];
                        ssize_t r_len;
                        bool copy_ok = true;
                        while ((r_len = read(fd_src, buf, sizeof(buf))) > 0) {
                            ssize_t w_off = 0;
                            while (w_off < r_len) {
                                ssize_t w_len = write(fd_dst, buf + w_off, r_len - w_off);
                                if (w_len < 0) {
                                    if (errno == EINTR) continue;
                                    copy_ok = false;
                                    break;
                                }
                                w_off += w_len;
                            }
                            if (!copy_ok) break;
                        }
                        if (r_len < 0) copy_ok = false;
                        if (copy_ok) {
                            struct timespec ts[2] = {s_st.st_atim, s_st.st_mtim};
                            futimens(fd_dst, ts);
                            fchown(fd_dst, s_st.st_uid, s_st.st_gid);
                            fchmod(fd_dst, s_st.st_mode & 07777);
#ifdef TARGET_ANDROID
                            char context[256];
                            ssize_t ctx_len =
                                lgetxattr(s_path, "security.selinux", context, sizeof(context));
                            if (ctx_len > 0)
                                lsetxattr(d_path, "security.selinux", context, (size_t)ctx_len, 0);
#endif
                        } else {
                            r = -EIO;
                        }
                        close(fd_dst);
                        if (!copy_ok) unlink(d_path);
                    } else {
                        r = -errno;
                    }
                    close(fd_src);
                } else {
                    r = -errno;
                }
            }
        }
    }
    closedir(d);
    return r;
}

static int vfs_rename_copy_file(const char* src, const char* dst, struct stat* st) {
    int fd_src = open(src, O_RDONLY | O_CLOEXEC);
    if (fd_src < 0) return -errno;
    int fd_dst = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, st->st_mode & 0777);
    if (fd_dst < 0) {
        int err = errno;
        close(fd_src);
        return -err;
    }
    char* buf = malloc(65536);
    if (!buf) {
        close(fd_src);
        close(fd_dst);
        return -ENOMEM;
    }
    ssize_t r_len;
    int copy_err = 0;
    while ((r_len = read(fd_src, buf, 65536)) > 0) {
        ssize_t w_off = 0;
        while (w_off < r_len) {
            ssize_t w_len = write(fd_dst, buf + w_off, (size_t)(r_len - w_off));
            if (w_len < 0) {
                if (errno == EINTR) continue;
                copy_err = -errno;
                break;
            }
            w_off += w_len;
        }
        if (copy_err < 0) break;
    }
    if (r_len < 0 && copy_err == 0) copy_err = -errno;
    free(buf);
    if (copy_err == 0) {
        struct timespec ts[2] = {st->st_atim, st->st_mtim};
        futimens(fd_dst, ts);
        fchown(fd_dst, st->st_uid, st->st_gid);
        fchmod(fd_dst, st->st_mode & 07777);
#ifdef TARGET_ANDROID
        char context[256];
        ssize_t ctx_len = lgetxattr(src, "security.selinux", context, sizeof(context));
        if (ctx_len > 0) lsetxattr(dst, "security.selinux", context, (size_t)ctx_len, 0);
#endif
    }
    close(fd_src);
    close(fd_dst);
    if (copy_err < 0) {
        unlink(dst);
        return copy_err;
    }
    return 0;
}

static int vfs_rename(const char* from, const char* to, unsigned int flags) {
    struct fuse_context* ctx = fuse_get_context();
    if (!ctx) return -EACCES;
    /* from/to 各走一次路由（无模块时直通回退）。rename 属变更操作，故两端
       任一 appear_missing/read_only 都由 fw_route 单点拒绝——旧实现在此
       手写两遍 hidden/ro 判定，与其它回调的判定容易漂移 */
    NspPathDecision r1, r2;
    bool ok1 = false, ok2 = false;
    char sub_from[PATH_MAX], sub_to[PATH_MAX], p_from[PATH_MAX], p_to[PATH_MAX];
    int u_from = -1, u_to = -1;
    bool redir_from = false, redir_to = false;
    char pkg_from[128], pkg_to[128];
    int rrc = fw_route(ctx, from, &r1, &ok1, pkg_from, &u_from, sub_from, p_from, &redir_from,
                       VFS_OP_MUTATE);
    if (rrc != 0) return rrc;
    rrc = fw_route(ctx, to, &r2, &ok2, pkg_to, &u_to, sub_to, p_to, &redir_to, VFS_OP_MUTATE);
    if (rrc != 0) return rrc;
    vfs_log_io(pkg_from, ctx->uid, "RENAME_FROM", sub_from,
               (ok1 && redir_from) ? r1.real_path : NULL, ok1 ? r1.monitor_on : false);
    vfs_log_io(pkg_to, ctx->uid, "RENAME_TO", sub_to, (ok2 && redir_to) ? r2.real_path : NULL,
               ok2 ? r2.monitor_on : false);
    /* 后端分派：from/to 命中后端时由模块方法重命名（两端须同一后端模块） */
    const NspModuleOps* bf_ops = NULL;
    const NspModuleOps* bt_ops = NULL;
    bool bf_hit = (ok1 && r1.is_ftp && module_backend_lookup(sub_from, &bf_ops) == 0);
    bool bt_hit = (ok2 && r2.is_ftp && module_backend_lookup(sub_to, &bt_ops) == 0);
    if (bf_hit || bt_hit) {
        if (bf_hit && bt_hit && bf_ops == bt_ops && bf_ops->backend_rename) {
            int bslot = module_ops_slot(bf_ops);
            int brc = nsp_fence_backend_rename(bslot, "backend_rename", bf_ops->backend_rename,
                                               sub_from, sub_to);
            /* from/to 各 lookup 一次，同模块时槽位引用计数为 2：逐次配对释放 */
            module_backend_put(bf_ops);
            module_backend_put(bt_ops);
            if (brc == NSP_FENCE_FAULT) {
                module_guard_fault(bslot, "backend_rename", sub_from);
                return -EIO;
            }
            if (brc == NSP_FENCE_BADFN) return -EXDEV;
            if (brc < 0 && !backend_rc_is_business(brc)) {
                module_guard_error(bslot, "backend_rename", brc, sub_from, "rename 返回异常");
            }
            return brc < 0 ? brc : 0;
        }
        /* 跨后端/后端↔本地重命名不支持；两次 lookup 的在途引用逐次配对释放
           （同模块亦为两次引用，不可按指针去重只 put 一次） */
        if (bf_hit) module_backend_put(bf_ops);
        if (bt_hit) module_backend_put(bt_ops);
        return -EXDEV;
    }
#ifdef SYS_renameat2
    if (flags && syscall(SYS_renameat2, AT_FDCWD, p_from, AT_FDCWD, p_to, flags) == 0) return 0;
#endif
    char *p_to_dup = strdup(p_to), *p_to_dir = dirname(p_to_dup);
    int mkdir_res = mkdir_recursive_p(p_to_dir, 0775);
    free(p_to_dup);
    if (mkdir_res != 0) {
        LOG_ERR("重命名创建目标父目录失败: %s (errno=%d)", p_to_dir, errno);
        return -errno;
    }
    if (rename(p_from, p_to) == 0) return 0;
    int err = errno;
    if (err == EXDEV) {
        struct stat st;
        if (lstat(p_from, &st) == 0) {
            if (S_ISREG(st.st_mode)) {
                int copy_res = vfs_rename_copy_file(p_from, p_to, &st);
                if (copy_res == 0) {
                    unlink(p_from);
                    return 0;
                }
                LOG_ERR("跨设备复制文件失败: %s -> %s (err=%d)", p_from, p_to, copy_res);
                return copy_res;
            } else if (S_ISDIR(st.st_mode)) {
                int copy_res = recursive_copy_dir(p_from, p_to, ctx->uid, ctx->gid);
                if (copy_res == 0) {
                    if (recursive_rmdir(p_from) == 0)
                        return 0;
                    else {
                        recursive_rmdir(p_to);
                        return -errno;
                    }
                } else {
                    recursive_rmdir(p_to);
                    LOG_ERR("跨设备复制文件夹失败: %s -> %s (err=%d)", p_from, p_to, copy_res);
                    return copy_res;
                }
            }
        } else {
            return -errno;
        }
    }
    log_fuse_err("RENAME", from, err);
    return -err;
}

static int vfs_chmod(const char* path, mode_t mode, struct fuse_file_info* fi) {
    (void)fi;
    VFS_SETUP_CORE(path, VFS_OP_MUTATE);
    int ret = chmod(p, mode);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("CHMOD", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_chown(const char* path, uid_t uid, gid_t gid, struct fuse_file_info* fi) {
    (void)fi;
    VFS_SETUP_CORE(path, VFS_OP_MUTATE);
    int ret = lchown(p, uid, gid);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("CHOWN", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_truncate(const char* path, off_t size, struct fuse_file_info* fi) {
    (void)fi;
    VFS_SETUP_CORE(path, VFS_OP_MUTATE);
    /* 后端分派：truncate 由模块方法截断 */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0) {
        if (!bops->backend_truncate) {
            /* 模块未提供 truncate 回调：释放 lookup 在途引用后走本地 truncate */
            module_backend_put(bops);
        } else {
            int bslot = module_ops_slot(bops);
            int brc = nsp_fence_backend_truncate(bslot, "backend_truncate", bops->backend_truncate,
                                                 sub_path, size);
            module_backend_put(bops);
            if (brc == NSP_FENCE_FAULT) {
                module_guard_fault(bslot, "backend_truncate", sub_path);
                VFS_RETURN(-EIO);
            }
            if (brc != 0) {
                if (brc != NSP_FENCE_BADFN && !backend_rc_is_business(brc))
                    module_guard_error(bslot, "backend_truncate", brc, sub_path,
                                       "truncate 返回异常");
                VFS_RETURN(brc < 0 ? brc : -EIO);
            }
            VFS_RETURN(0);
        }
    }
    int ret = truncate(p, size);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("TRUNCATE", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_utimens(const char* path, const struct timespec ts[2], struct fuse_file_info* fi) {
    (void)fi;
    VFS_SETUP_CORE(path, VFS_OP_MUTATE);
    int ret = utimensat(AT_FDCWD, p, ts, AT_SYMLINK_NOFOLLOW);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("UTIMENS", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_statfs(const char* path, struct statvfs* st) {
    (void)path;
    int ret = statvfs(STORAGE_BASE, st);
    if (ret == -1) return -errno;
    return 0;
}

static int vfs_getxattr(const char* path, const char* name, char* value, size_t size) {
    VFS_SETUP_CORE(path, VFS_OP_READ);
    ssize_t res = lgetxattr(p, name, value, size);
    if (res == -1) {
        if (errno == ENODATA || errno == EOPNOTSUPP) {
#ifdef TARGET_ANDROID
            if (strcmp(name, "security.selinux") == 0) {
                const char* default_ctx = "u:object_r:media_rw_data_file:s0";
                size_t len = strlen(default_ctx) + 1;
                if (size == 0) {
                    VFS_RETURN((int)len);
                }
                if (size < len) {
                    VFS_RETURN(-ERANGE);
                }
                strcpy(value, default_ctx);
                VFS_RETURN((int)len);
            }
#endif
            VFS_RETURN(-errno);
        }
        int err = errno;
        log_fuse_err("GETXATTR", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN((int)res);
}

static int vfs_listxattr(const char* path, char* list, size_t size) {
    VFS_SETUP_CORE(path, VFS_OP_READ);
    ssize_t res = llistxattr(p, list, size);
    if (res == -1) {
        int err = errno;
        log_fuse_err("LISTXATTR", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN((int)res);
}

static int vfs_setxattr(const char* path, const char* name, const char* value, size_t size,
                        int flags) {
    VFS_SETUP_CORE(path, VFS_OP_MUTATE);
    int ret = lsetxattr(p, name, value, size, flags);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("SETXATTR", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_removexattr(const char* path, const char* name) {
    VFS_SETUP_CORE(path, VFS_OP_MUTATE);
    int ret = lremovexattr(p, name);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("REMOVEXATTR", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static void vfs_destroy(void* private_data) {
    (void)private_data;
    LOG_DBG("FUSE 守护进程正在退出，清理资源...");
    /* 先投递 EXIT（comm 线程仍存活），再 log_close 做最尽力 drain + join */
    char msg[256];
    snprintf(msg, sizeof(msg), "FUSE_EXIT %d", getpid());
    nsp_comm_post(NSP_CH_IPC, msg, strlen(msg) + 1);
    if (g_global_root_fd >= 0) close(g_global_root_fd);
#ifdef TARGET_ANDROID
    if (g_bpf_fd >= 0) close(g_bpf_fd);
#endif
    log_close();
}

/* 透传会话 fd：经 fuse_get_context()->fuse → fuse_get_session → fuse_session_fd 解析
   （不依赖 conn->fd——系统 libfuse 的 fuse_conn_info 无该成员，GNU 下同样可用） */
static int passthrough_session_fd(void) {
    struct fuse_context* ctx = fuse_get_context();
    if (!ctx || !ctx->fuse) return -1;
    struct fuse_session* se = fuse_get_session(ctx->fuse);
    if (!se) return -1;
    return fuse_session_fd(se);
}

/* 透传方法探测：用普通文件测试 BACKING_OPEN（上游/新内核；老内核上同号即 V0），
   V2/V1/V0 仅 Android 旧式 ioctl 兜底。结果写入 g_passthrough_enabled/g_pt_method。
   探测fd必须用普通文件：BACKING_OPEN 要求 d_is_reg，字符设备会被内核拒绝并返回
   EINVAL(errno=22)——这正是 6.12 设备上报「协商失败 errno=22」的根因。 */
static void passthrough_probe(int dev_fd) {
    int backing_id = -1;
    int saved_errno = 0;
    bool ioctl_exists = false;
    passthrough_method_t method = PT_METHOD_NONE;
    char probe_path[64];
#ifdef TARGET_ANDROID
    snprintf(probe_path, sizeof(probe_path), "/data/local/tmp/.fuse_pt_probe.%d", getpid());
#else
    snprintf(probe_path, sizeof(probe_path), "/tmp/.fuse_pt_probe.%d", getpid());
#endif
    int test_fd = open(probe_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (test_fd < 0) {
        LOG_ERR("FUSE Passthrough: ❌ 无法创建探测文件 %s: %s", probe_path, strerror(errno));
        return;
    }

    /* 1) 上游/新内核: FUSE_DEV_IOC_BACKING_OPEN(229/1, fuse_backing_map)。
          老式 Android 内核上该 ioctl 号恰好也是 PASSTHROUGH_OPEN(V0), flags=0/padding=0
          等价于旧式的 len=0/vec=NULL 调用, 两种内核都能命中。 */
    struct fuse_backing_map map = {.fd = test_fd, .flags = 0, .padding = 0};
    backing_id = (int)ioctl(dev_fd, FUSE_DEV_IOC_BACKING_OPEN, &map);
    if (backing_id > 0) {
        ioctl_exists = true;
        method = PT_METHOD_UPSTREAM;
    } else {
        saved_errno = errno;
        if (saved_errno == EPERM) {
            ioctl_exists = true;
            method = PT_METHOD_UPSTREAM;
        }
#ifdef TARGET_ANDROID
        else if (saved_errno == ENOTTY || saved_errno == EINVAL) {
            /* 2) Android V2/V1/V0 旧式 ioctl 兜底 */
            backing_id = (int)ioctl(dev_fd, FUSE_DEV_IOC_PASSTHROUGH_OPEN_V2, &test_fd);
            if (backing_id > 0) {
                ioctl_exists = true;
                method = PT_METHOD_ANDROID_V2;
            } else {
                saved_errno = errno;
                if (saved_errno == EPERM) {
                    ioctl_exists = true;
                    method = PT_METHOD_ANDROID_V2;
                } else if (saved_errno == ENOTTY || saved_errno == EINVAL) {
                    struct fuse_passthrough_out_v0 out = {
                        .fd = (uint32_t)test_fd, .len = 0, .vec = NULL};
                    errno = 0;
                    backing_id = (int)ioctl(dev_fd, FUSE_DEV_IOC_PASSTHROUGH_OPEN_V1, &out);
                    if (backing_id > 0) {
                        ioctl_exists = true;
                        method = PT_METHOD_ANDROID_V1;
                    } else {
                        saved_errno = errno;
                        if (saved_errno == EPERM) {
                            ioctl_exists = true;
                            method = PT_METHOD_ANDROID_V1;
                        } else if (saved_errno == ENOTTY || saved_errno == EINVAL) {
                            errno = 0;
                            backing_id = (int)ioctl(dev_fd, FUSE_DEV_IOC_PASSTHROUGH_OPEN_V0, &out);
                            if (backing_id > 0) {
                                ioctl_exists = true;
                                method = PT_METHOD_ANDROID_V0;
                            } else {
                                saved_errno = errno;
                                if (saved_errno == EPERM) {
                                    ioctl_exists = true;
                                    method = PT_METHOD_ANDROID_V0;
                                }
                            }
                        }
                    }
                }
            }
        }
#endif
    }
    unlink(probe_path);

    if (ioctl_exists) {
        g_passthrough_enabled = true;
        g_pt_method = method; /* 记录已确认的透传方法，per-open 直连使用 */
        if (backing_id > 0) {
            LOG("FUSE Passthrough: ✅ ioctl协商成功! backing_id=%d, 文件I/O将走直通加速",
                backing_id);
            int close_ret = ioctl(dev_fd, FUSE_DEV_IOC_BACKING_CLOSE, &backing_id);
            if (close_ret < 0)
                LOG_DBG("FUSE Passthrough: 关闭测试backing_id=%d: %s", backing_id, strerror(errno));
        } else {
            LOG_DBG("FUSE Passthrough: ioctl 已确认(EPERM), 交由 per-open 协商启用");
        }
    } else {
        int err = saved_errno;
        switch (err) {
            case ENOTTY:
                LOG_ERR("FUSE Passthrough: ❌ 内核FUSE模块不支持任何已知的PASSTHROUGH ioctl");
                break;
            case EPERM: LOG_ERR("FUSE Passthrough: ❌ 缺少运行所需权限 (EPERM)"); break;
            default:
                LOG_ERR("FUSE Passthrough: ❌ 协商失败 errno=%d (%s)", err, strerror(err));
                break;
        }
    }
    close(test_fd);
}

/* 按 init 阶段已确认的透传方法执行单次 ioctl（open/create 直连，不走回退链），
   返回 backing_id(>0) 或 <=0 */
static int passthrough_enable_fixed_method(int fd) {
    int sfd = passthrough_session_fd();
    if (sfd < 0) return -1;
    /* GNU：init 阶段无会话 fd，探测推迟到首次 open 时补执行一次 */
    if (g_pt_probe_pending) {
        g_pt_probe_pending = false;
        passthrough_probe(sfd);
    }
    if (!g_passthrough_enabled) return -1;
    int backing_id;
    switch (g_pt_method) {
        case PT_METHOD_UPSTREAM: {
            struct fuse_backing_map map = {.fd = fd, .flags = 0, .padding = 0};
            backing_id = (int)ioctl(sfd, FUSE_DEV_IOC_BACKING_OPEN, &map);
            break;
        }
#ifdef TARGET_ANDROID
        case PT_METHOD_ANDROID_V2:
            backing_id = (int)ioctl(sfd, FUSE_DEV_IOC_PASSTHROUGH_OPEN_V2, &fd);
            break;
        case PT_METHOD_ANDROID_V1:
        case PT_METHOD_ANDROID_V0: {
            struct fuse_passthrough_out_v0 out = {.fd = (uint32_t)fd, .len = 0, .vec = NULL};
            backing_id =
                (int)ioctl(sfd,
                           (g_pt_method == PT_METHOD_ANDROID_V1) ? FUSE_DEV_IOC_PASSTHROUGH_OPEN_V1
                                                                 : FUSE_DEV_IOC_PASSTHROUGH_OPEN_V0,
                           &out);
            break;
        }
#endif
        default: return -1;
    }
    return backing_id;
}

static void* vfs_init(struct fuse_conn_info* conn, struct fuse_config* cfg) {
    cfg->use_ino = 1;
    /* 缓存超时不在此处写死：`fuse_new` 已按 libfuse 默认值填好 conf
       （entry/attr=1.0、negative=0.0）**并已解析用户经 -o 传入的值**
       （fuse.c: 默认值 → fuse_opt_parse → fuse_fs_init 才回调本函数），
       此处再无条件赋值会覆盖用户的 -o attr_timeout=... 等设置。
       特别注意 negative_timeout：libfuse 默认 0.0（不缓存 ENOENT），旧代码
       把它抬到 0.5，正是"上传成功后立即 open 命中陈旧负缓存报 ENOENT"的根因
       （FTP 后端只能靠 open 内 2×10ms 重试兜底）。保持默认 0 后该竞态消失；
       后端自有 stat 缓存（含负条目）吸收内核层未命中的重复查询，无吞吐回退。
       需要负缓存时经 FUSE_EXTRA_ARGS 传 -o negative_timeout=N 即可生效。 */
    signal(SIGPIPE, SIG_IGN);
    g_passthrough_enabled = false;

    if (g_passthrough_disabled) {
        LOG("FUSE Passthrough: 已被 --no-passthrough 参数禁用");
        goto skip_passthrough;
    }

    /* —— 高版本内核(6.9+/GKI 6.12)的新协商方式, 与 AOSP FuseDaemon 的 pf_init 一致: ——
     * 上游内核在 INIT 回包 capable 中直接上报 FUSE_PASSTHROUGH 能力(flags2 bit37/1ULL<<37,
     * 老式 Android 内核为 flags bit31), libfuse 折算到 FUSE_CAP_PASSTHROUGH 位。
     * 内核说支持就直接请求启用, 不再盲试 ioctl。 */
    if (conn->capable & FUSE_CAP_PASSTHROUGH) {
        conn->want |= FUSE_CAP_PASSTHROUGH;
        g_passthrough_enabled = true;
        g_pt_method = PT_METHOD_UPSTREAM; /* 能力协商内核的透传 open 即 cmd1（BACKING_OPEN 号） */
        LOG_DBG("FUSE Passthrough: ✅ 内核INIT能力协商成功 (capable=0x%x), 直接启用",
                conn->capable);
        goto passthrough_done;
    }
    LOG_DBG("FUSE Passthrough: 内核INIT未上报passthrough能力, 回退ioctl探测 (capable=0x%x)",
            conn->capable);

#ifdef TARGET_ANDROID
    passthrough_probe(conn->fd); /* Android：conn->fd 即会话 fd，init 直接探测 */
    /* 注意：探测成功（BACKING_OPEN/V2/V1/V0 ioctl 直通）≠ 内核 INIT 上报了透传
       能力（capable_ext 无 FUSE_CAP_PASSTHROUGH）。此时绝不置 want 位——否则
       libfuse want_flags_valid 拒绝（unknown want flags: 0x20000000）→ EPROTO
       → 连接终止。ioctl 直通透传不依赖 INIT 协商位，per-open 仍可正常工作。 */
#else
    /* GNU：init 回调拿不到会话 fd（高层 fuse_main），探测推迟到首次文件 open，
       per-open 经 fuse_get_context 取会话 fd 后补执行一次 */
    g_pt_probe_pending = true;
    LOG_DBG("FUSE Passthrough: GNU 下 ioctl 探测推迟到首次文件 open");
#endif

passthrough_done:
skip_passthrough:
    if (g_passthrough_enabled) {
        LOG("FUSE Passthrough: 🟢 启用成功");
    } else if (g_pt_probe_pending) {
        LOG("FUSE Passthrough: 透传探测已延迟，将在首次文件 open 时确认");
    } else {
        LOG_WRN("FUSE Passthrough: 所有文件I/O将走标准FUSE用户态路径 (性能较低)");
    }
    /* 生命线投递经 comm 线程（init 路径不再被 connect 卡 500ms） */
    char msg[512];
    snprintf(msg, 511, "FUSE_ALIVE Global %d", getpid());
    nsp_comm_post(NSP_CH_IPC, msg, strlen(msg) + 1);
    /* 协商详情：内核上报能力与本端请求位——若后续就绪验证失败(内核 conn_error)，
       据此可定位是哪个请求位被内核拒绝（如 DAX 设备把回包 legacy bit31 误读为
       FUSE_MAP_ALIGNMENT 而拒绝回包） */
    LOG_DBG("FUSE 协商详情: 内核 capable=0x%x, 本端 want=0x%x, 透传=%s", (unsigned)conn->capable,
            (unsigned)conn->want,
            g_passthrough_enabled ? "启用" : (g_pt_probe_pending ? "延迟探测" : "标准FUSE回退"));
    if (g_ready_fd >= 0) {
        write(g_ready_fd, "1", 1);
        close(g_ready_fd);
        g_ready_fd = -1;
    }
    return nullptr;
}

#ifdef TARGET_ANDROID
static bool is_fuse_bpf_supported(void) {
    FILE* fp = fopen("/sys/fs/fuse/features/fuse_bpf", "r");
    if (!fp) {
        LOG_DBG("FUSE BPF: 特性文件不可读");
        return false;
    }
    char line[64];
    bool ok = false;
    if (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len && line[len - 1] == '\n') line[--len] = '\0';
        ok = (strcmp(line, "supported") == 0);
    }
    fclose(fp);
    LOG_DBG("FUSE BPF: %s -> %s", "/sys/fs/fuse/features/fuse_bpf",
            ok ? "supported" : "not supported");
    return ok;
}

#ifndef __NR_bpf
#if defined(__aarch64__)
#define __NR_bpf 280
#else
#define __NR_bpf 321
#endif
#endif
#include <linux/bpf.h>

static int open_bpf_prog(void) {
    static const char* bpf_paths[] = {"/sys/fs/bpf/prog_fuseMedia_fuse_media",
                                      "/sys/fs/bpf/prog_fuse_media", NULL};
    for (int i = 0; bpf_paths[i]; i++) {
        union bpf_attr attr = {};
        attr.pathname = (uint64_t)(uintptr_t)bpf_paths[i];
        attr.bpf_fd = 0;
        int fd = (int)syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
        if (fd >= 0) {
            LOG_DBG("FUSE BPF: 已获取程序 %s (fd=%d)", bpf_paths[i], fd);
            return fd;
        }
        LOG_DBG("FUSE BPF: %s: %s", bpf_paths[i], strerror(errno));
    }
    LOG_WRN("FUSE BPF: 无法获取 BPF 程序, 将以标准 FUSE 模式运行");
    return -1;
}
#endif

#ifdef TARGET_ANDROID
static int vfs_bpf_setup(const char* path, struct fuse_entry_param* e) {
    if (g_bpf_fd < 0) return -ENOSYS;
    if (!path || !e) return -EINVAL;

    char real[PATH_MAX];

    if (!g_is_media_fuse) {
        const char* suffix;
        if ((suffix = strstr(path, "/Android/data")) == NULL &&
            (suffix = strstr(path, "/Android/obb")) == NULL)
            return -ENOENT;
    }

    snprintf(real, sizeof(real), "%s%s", g_real_root, path);
    if (!S_ISDIR(e->attr.st_mode)) return -ENOTDIR;

    int bfd = open(real, O_CLOEXEC | O_DIRECTORY | O_RDONLY);
    if (bfd < 0) {
        LOG_DBG("FUSE BPF: open(%s) = %s", real, strerror(errno));
        return -errno;
    }

    e->backing_action = FUSE_ACTION_REPLACE;
    e->backing_fd = (uint64_t)bfd;
    e->bpf_action = FUSE_ACTION_REPLACE;
    e->bpf_fd = (uint64_t)g_bpf_fd;
    LOG_DBG_PERF("FUSE BPF: backing %s (fd=%d, bpf=%d, media=%d)", real, bfd, g_bpf_fd,
                 g_is_media_fuse);

    vfs_defer_close(bfd);
    return 0;
}
#endif

static struct fuse_operations vfs_ops = {
    .init = vfs_init,
    .destroy = vfs_destroy,
    .getattr = vfs_getattr,
    .access = vfs_access,
    .readlink = vfs_readlink,
    .symlink = vfs_symlink,
    .opendir = vfs_opendir,
    .readdir = vfs_readdir,
    .open = vfs_open,
    .create = vfs_create,
    .read = vfs_read,
    .write = vfs_write,
    .release = vfs_release,
    .fsync = vfs_fsync,
    .flush = vfs_flush,
    .mkdir = vfs_mkdir,
    .unlink = vfs_unlink,
    .rmdir = vfs_rmdir,
    .rename = vfs_rename,
    .chmod = vfs_chmod,
    .chown = vfs_chown,
    .truncate = vfs_truncate,
    .utimens = vfs_utimens,
    .statfs = vfs_statfs,
    .getxattr = vfs_getxattr,
    .listxattr = vfs_listxattr,
    .setxattr = vfs_setxattr,
    .removexattr = vfs_removexattr,
#ifdef TARGET_ANDROID
    .bpf_setup = vfs_bpf_setup,
#endif
};

int main(int argc, char* argv[]) {
    char rules_path[PATH_MAX] = {0};
    char* fuse_argv[argc + 1];
    int fuse_argc = 0;
    if (argc > 0) fuse_argv[fuse_argc++] = argv[0];
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--mode=", 7) == 0) {
            if (strcmp(argv[i] + 7, "overlay") == 0)
                g_mode = MODE_OVERLAY;
            else
                g_mode = MODE_REDIRECT;
        } else if (strncmp(argv[i], "--root=", 7) == 0) {
            strncpy(g_real_root, argv[i] + 7, PATH_MAX - 1);
        } else if (strncmp(argv[i], "--rules=", 8) == 0) {
            strncpy(rules_path, argv[i] + 8, PATH_MAX - 1);
        } else if (strncmp(argv[i], "--lower=", 8) == 0) {
            strncpy(g_lower_dir, argv[i] + 8, PATH_MAX - 1);
        } else if (strncmp(argv[i], "--upper=", 8) == 0) {
            strncpy(g_upper_dir, argv[i] + 8, PATH_MAX - 1);
        } else if (strncmp(argv[i], "--ready-fd=", 11) == 0) {
            g_ready_fd = atoi(argv[i] + 11);
        } else if (strncmp(argv[i], "--global-root-fd=", 17) == 0) {
            g_global_root_fd = atoi(argv[i] + 17);
        } else if (strcmp(argv[i], "--preserve-perms") == 0) {
            g_preserve_perms = true;
        } else if (strcmp(argv[i], "--strip-o-direct") == 0) {
            g_strip_o_direct = true;
#ifdef TARGET_ANDROID
        } else if (strcmp(argv[i], "--no-bpf") == 0) {
            g_bpf_fd = -2;
#endif
        } else if (strcmp(argv[i], "--no-passthrough") == 0) {
            g_passthrough_disabled = true;
        } else if (strncmp(argv[i], "--crash-test", 12) == 0) {
            /* 崩溃触发测试：--crash-test[=segv|abrt|bus]（默认 segv） */
            const char* t = argv[i] + 12;
            g_crash_test = 1;
            if (*t == '=') {
                if (strcmp(t + 1, "abrt") == 0)
                    g_crash_test = 2;
                else if (strcmp(t + 1, "bus") == 0)
                    g_crash_test = 3;
            }
        } else if (strcmp(argv[i], "--media-fuse") == 0) {
            g_is_media_fuse = true;
        } else if (strncmp(argv[i], "--modules-dir=", 14) == 0) {
            strncpy(g_modules_dir_arg, argv[i] + 14, PATH_MAX - 1);
        } else if (strcmp(argv[i], "--disable-sandbox") == 0) {
            /* 解析并应用禁用沙盒指令 */
            g_disable_sandbox = true;
        } else if (strncmp(argv[i], "--fuse-threads=", 15) == 0) {
            /* FUSE 多线程 worker 数上限（libfuse fuse_session_loop_mt）。
               缺省 2=双线程；显式 0（或 -s）= 单线程 fuse_loop；
               -1=libfuse 默认（10，兼容旧语义）；小于 -1 钳制为 -1。
               注入器可按宿主 CPU 核数经 fuse_extra_args 下发调优。 */
            g_fuse_threads = atoi(argv[i] + 15);
            if (g_fuse_threads < -1) g_fuse_threads = -1;
        } else if (strcmp(argv[i], "debug") == 0 || strcmp(argv[i], "--debug") == 0) {
            g_min_log_level = LOG_DEBUG;
            fuse_argv[fuse_argc++] = "-d";
        } else if (strcmp(argv[i], "info") == 0) {
            g_min_log_level = LOG_INFO;
        } else if (strcmp(argv[i], "warn") == 0 || strcmp(argv[i], "warning") == 0) {
            g_min_log_level = LOG_WARN;
        } else if (strcmp(argv[i], "error") == 0) {
            g_min_log_level = LOG_ERROR;
        } else {
            fuse_argv[fuse_argc++] = argv[i];
        }
    }
    fuse_argv[fuse_argc] = nullptr;
    prctl(PR_SET_NAME, "fuse_daemon", 0, 0, 0);
    log_init("fuse_daemon");
    /* 环境信息仅 injector 输出一次（崩溃归因走 crash_dump 的 Build 行），此处不重复 */
    /* 崩溃处理器安装顺序（关键）：先装 crash_handler（内层/dump+re-raise），
       再装 fault_fence 处理器（外层/活动处理器）——后安装者生效。fence 在
       模块调用窗口内崩溃时 siglongjmp 恢复（daemon 存活，模块置毒卸载）；
       归因失败（窗口外/非模块崩溃）委托 crash_handler 走原 dump 链路。
       顺序颠倒（先 fence 后 crash）会使 fence 被覆盖而失效。 */
    install_crash_handlers();
    fault_fence_set_orig_handler(crash_handler);
    fault_fence_init();
    /* 崩溃触发测试：验证 error.log 记录与 stderr→fuse_crash.log 的 backtrace 捕获链路。
       崩溃发生在挂载/模块初始化前，可独立运行（无需挂载）。 */
    if (g_crash_test != 0) {
        const char* what = g_crash_test == 1 ? "SIGSEGV" : g_crash_test == 2 ? "SIGABRT" : "SIGBUS";
        LOG_ERR(
            "崩溃触发测试(--crash-test): 即将触发 %s，请检查 error.log 与 fuse_crash.log 是否捕获完整 backtrace",
            what);
        if (g_crash_test == 1) {
            volatile int* p = NULL;
            *p = 1; /* 空指针解引用 → SIGSEGV */
        } else if (g_crash_test == 2) {
            abort(); /* → SIGABRT */
        } else {
#if defined(__aarch64__)
            volatile char base[8] = {0};
            /* 未对齐 8 字节原子存储：aarch64 的 STXR 要求对齐 → 真实 SIGBUS */
            __atomic_store_n((volatile uint64_t*)(base + 1), 0x1122334455667788ULL,
                             __ATOMIC_SEQ_CST);
#else
            raise(SIGBUS); /* x86 无未对齐故障，直接 raise */
#endif
        }
    }
    /* 模块守卫（校验+熔断+MOD_ERR 日志限流）：须在模块系统初始化前
       就绪——模块加载/init 调用可能立即触发错误上报 */
    module_guard_init();
    /* 热插拔模块系统：扫描模块目录并启动监控线程（规则模块能力在此注册） */
    uint32_t mod_flags = g_disable_sandbox ? NSP_FLAG_DISABLE_SANDBOX : 0;
    module_system_init(rules_path, g_modules_dir_arg[0] ? g_modules_dir_arg : NULL, mod_flags);

    if (g_disable_sandbox) {
        LOG("沙盒特性已强制禁用");
    }

#ifdef TARGET_ANDROID
    if (g_bpf_fd != -2) {
        g_bpf_fd = -1;
        if (is_fuse_bpf_supported()) {
            int fd = open_bpf_prog();
            if (fd >= 0) {
                g_bpf_fd = fd;
                LOG("FUSE BPF: 已启用 (bpf_fd=%d)", g_bpf_fd);
            }
        }
    } else {
        LOG("FUSE BPF: 已被 --no-bpf 参数禁用");
        g_bpf_fd = -1;
    }
#endif
    /* Phase 3：显式 FUSE 会话，复刻 libfuse fuse_main_real_versioned
       （3.18）的完整 7 步序列，仅将最后一步的 worker 线程数变为可控
       （--fuse-threads=N；缺省 2=双线程；0/-s = 单线程；-1 = libfuse 默认 10）。
       注意 fuse_new 本身**不做** cmdline 解析/挂载/信号注册——这些是
       fuse_main 的独立步骤，缺了 fuse_session_new 会把 -f/挂载点当
       unknown option 拒绝。
       三层数据路径（路由/模块/输出）全部无全局可变状态——任意 worker
       线程并发进入安全（见文件头 fw_route 注释）。 */
    struct fuse_args fa = FUSE_ARGS_INIT(fuse_argc, fuse_argv);
    struct fuse_cmdline_opts fopts = {0};
    int fmain_rc = 0;
    struct fuse* f = NULL;
    struct fuse_loop_config* lcfg = NULL;
    if (fuse_parse_cmdline(&fa, &fopts) != 0)
        fmain_rc = 1; /* 与 fuse_main 错误码对齐 */
    else if (!fopts.show_help && !fopts.mountpoint) {
        LOG_ERR("FUSE: 缺少挂载点");
        fmain_rc = 2;
    } else if ((f = fuse_new(&fa, &vfs_ops, sizeof(struct fuse_operations), nullptr)) == NULL) {
        LOG_ERR("FUSE 会话创建失败（fuse_new）");
        fmain_rc = 3;
    } else if (fuse_mount(f, fopts.mountpoint) != 0) {
        LOG_ERR("FUSE 挂载失败: %s", fopts.mountpoint);
        fmain_rc = 4;
    } else if (fuse_daemonize(fopts.foreground) != 0) {
        LOG_ERR("FUSE 后台化失败");
        fmain_rc = 5;
    } else {
        struct fuse_session* se = fuse_get_session(f);
        if (fuse_set_signal_handlers(se) != 0) {
            LOG_ERR("FUSE 信号处理器安装失败");
            fmain_rc = 6;
        } else {
            /* 关键：libfuse 刚接管故障信号（SIGSEGV/SIGBUS/SIGFPE/SIGILL/
               SIGABRT），须重新武装围栏使其成为活动处理器——否则模块
               崩溃将走 libfuse 处理器（记日志后退出）带崩框架，围栏
               longjmp 恢复链路失效。SIGINT/SIGTERM 仍归 libfuse。 */
            fault_fence_rearm();
            LOG("FUSE 会话就绪: 挂载点=%s, worker 线程数=%s", fopts.mountpoint,
                (fopts.singlethread || g_fuse_threads == 0)
                    ? "单线程"
                    : (g_fuse_threads == -1  ? "libfuse 默认(10)"
                       : g_fuse_threads == 2 ? "双线程(2)"
                                             : "自定义"));
            if (fopts.singlethread || g_fuse_threads == 0) {
                /* 单线程（-s / --fuse-threads=0）：刻意沿用旧 fuse_loop 语义
                   （调用线程服务请求）。libfuse 3.19 起将其标记 deprecated
                   并改变语义（worker 代服），但升 FUSE_USE_VERSION 到 319
                   会断 GNU 系统库（3.18.3）兼容，故此处压警告保留旧行为。 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
                fmain_rc = fuse_loop(f);
#pragma GCC diagnostic pop
            } else {
                lcfg = fuse_loop_cfg_create(); /* 默认: max_threads=10, idle=无上限 */
                if (!lcfg) {
                    LOG_ERR("FUSE loop 配置创建失败（fuse_loop_cfg_create）");
                    fmain_rc = 7;
                } else {
                    if (g_fuse_threads > 0)
                        fuse_loop_cfg_set_max_threads(lcfg, (unsigned)g_fuse_threads);
                    /* g_fuse_threads == -1：保留默认 10，不覆盖 */
                    fmain_rc = fuse_loop_mt(f, lcfg);
                    if (fmain_rc) fmain_rc = 8;
                }
            }
            fuse_remove_signal_handlers(se);
        }
        fuse_unmount(f);
        fuse_destroy(f);
    }
    if (lcfg) fuse_loop_cfg_destroy(lcfg);
    free(fopts.mountpoint);
    fuse_opt_free_args(&fa);
    if (fmain_rc && fmain_rc != 8) LOG_ERR("FUSE 会话退出: rc=%d", fmain_rc);
    return fmain_rc;
}
