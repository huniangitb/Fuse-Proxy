/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _FILE_OFFSET_BITS 64
/* 后端文件句柄标记：open/create 命中后端时置位（本地 fd 不置位），
   read/write/release/fsync 据此区分本地 fd 与模块句柄。
   用 bit40（非 bit63）：Android tagged-pointer 检测对 fh 的 top byte
   （bit 56-63）非零会 SIGABRT（"Pointer tag truncated"）；bit40 置位
   不触发该检测，且远高于普通 fd 范围 */
#define NSP_FH_BACKEND_FLAG (1ULL << 40)
/* 后端句柄 fh 布局（open 时绑定，read/write 免路径解析直接定位模块 ops）：
   - bit40：后端句柄标志（沿用）
   - bit41-50：模块槽位（V5 注册表动态化，上限 1024，10 位）
   - bit51：写意图（open/create 按调用方 flags 记下，FLUSH/FSYNC 读回，见下）
   - bit0-39：后端句柄 ID（模块分配的小整数）
   低 40 位掩码用于提取句柄 ID（不含标志与槽位）。
   bit56-63 禁用（Android tagged-pointer 检测，见上）。 */
#define NSP_FH_BACKEND_SLOT_SHIFT 41
#define NSP_FH_BACKEND_SLOT_MASK  (0x3FFULL << NSP_FH_BACKEND_SLOT_SHIFT)
#define NSP_FH_BACKEND_SLOT_MAX   1024
#define NSP_FH_HANDLE_MASK        ((1ULL << 40) - 1)
/* 写意图位：open/create 时按调用方 flags 记录在这个句柄上，FLUSH/FSYNC 读回。
   FUSE 的 FLUSH/FSYNC 请求不带 open 标志，libfuse 把 fi->flags 填 0——在回调里
   重算 (fi->flags & O_ACCMODE) != O_RDONLY 恒为"只读"，后端写收尾据此判定的
   媒体刷新事件因此一条都发不出。句柄是唯一能跨回调带着这个事实的地方。 */
#define NSP_FH_WRITE_INTENT_FLAG (1ULL << 51)
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
#include <limits.h>
#include "common.h"
#include "config_parser.h" /* config_set_modules_dir：模块自有配置的读取归属 */
#include "fw_acl.h"
#include "vfs_synth.h" /* 访问控制唯一判定点（对齐 Android 原生 FUSE 用户态策略层） */
#include "fw_events.h"
#include "fw_ingest.h" /* 后端落点物化：让媒体刷新请求有一个真实本地文件可扫 */
#include "fuse_threads.h" /* FUSE 事件通道（默认 OFF，关闭时埋点只剩一次原子读） */
#include "fw_config.h"
#include "fw_pkg.h"
#include "fw_rules.h" /* 内建规则引擎：规则决策已归框架 */
#include "fd_close_queue.h"
#include "nsp_comm.h"
#include "nsp_util.h" /* nsp_log_gate：高频稳定事实的日志限频门 */
#include "crash_dump.h"
#include "fault_fence.h"
#include "module_guard.h"

/* GNU 开发构建链接的是系统 libfuse（3.18.3），没有这个 API：弱引用使缺失时
   编译链接照旧通过，运行时把判断跳过（Android 子模块固定提供该实现）。 */
extern void fuse_disable_copy_file_range(struct fuse *f) __attribute__((weak));
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
bool g_disable_sandbox = false; /* 新增：禁用沙盒功能标志 */

/* ================= 本地 open-unlink 的属性快照 =================
   本地路径的「删除仍打开的文件」由 vfs_rename 直接 unlink（不产生 .fuse_hidden，
   见 vfs_rename 内注释）。名字消失后，内核仍可能对打开句柄发 GETATTR（fstat）；
   此时路径已不存在，必须用快照回答，否则 fstat(2) 会拿到 ENOENT——Android 自带
   FUSE 在同样场景下 fstat 正常（实测 size 仍可读），我们与之对齐。
   键是 FUSE 侧路径（rename 的 to、后续 getattr/write/release 的 path 都是同一个
   隐藏名），故不受底层真实路径拼法影响。表很小：隐藏名本就只在 open-unlink 的
   短窗口内存在；满了覆盖最旧项。 */
#define HIDDEN_STAT_SLOTS 64
typedef struct {
    bool used;
    unsigned long stamp;
    char path[PATH_MAX];
    struct stat st;
} HiddenStatEntry;
static HiddenStatEntry g_hidden_stats[HIDDEN_STAT_SLOTS];
static pthread_mutex_t g_hidden_stats_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long g_hidden_stat_tick;

static void hidden_stat_put(const char* path, const struct stat* st) {
    if (!path || !st) return;
    pthread_mutex_lock(&g_hidden_stats_lock);
    int slot = -1, oldest = 0;
    for (int i = 0; i < HIDDEN_STAT_SLOTS; i++) {
        if (g_hidden_stats[i].used && strcmp(g_hidden_stats[i].path, path) == 0) {
            slot = i;
            break;
        }
        if (!g_hidden_stats[i].used && slot < 0) slot = i;
        if (g_hidden_stats[i].stamp < g_hidden_stats[oldest].stamp) oldest = i;
    }
    if (slot < 0) slot = oldest; /* 满：覆盖最旧（隐藏名只存活到 release） */
    HiddenStatEntry* e = &g_hidden_stats[slot];
    e->used = true;
    e->stamp = ++g_hidden_stat_tick;
    strncpy(e->path, path, sizeof(e->path) - 1);
    e->path[sizeof(e->path) - 1] = '\0';
    e->st = *st;
    pthread_mutex_unlock(&g_hidden_stats_lock);
}

static bool hidden_stat_get(const char* path, struct stat* out) {
    if (!path || !out) return false;
    bool found = false;
    pthread_mutex_lock(&g_hidden_stats_lock);
    for (int i = 0; i < HIDDEN_STAT_SLOTS; i++) {
        if (g_hidden_stats[i].used && strcmp(g_hidden_stats[i].path, path) == 0) {
            *out = g_hidden_stats[i].st;
            g_hidden_stats[i].stamp = ++g_hidden_stat_tick;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_hidden_stats_lock);
    return found;
}

/* 删除后仍可写：用本地句柄重新 fstat，刷新**已有**快照（size/mtime 与真实
   一致）。只更新不新建——普通写入不能凭空注册快照，否则原路径在 unlink 后
   会被误判为「仍存在」。 */
static void hidden_stat_refresh(const char* path, int fd) {
    if (!path || fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) != 0) return;
    pthread_mutex_lock(&g_hidden_stats_lock);
    for (int i = 0; i < HIDDEN_STAT_SLOTS; i++) {
        if (g_hidden_stats[i].used && strcmp(g_hidden_stats[i].path, path) == 0) {
            g_hidden_stats[i].st = st;
            g_hidden_stats[i].stamp = ++g_hidden_stat_tick;
            break;
        }
    }
    pthread_mutex_unlock(&g_hidden_stats_lock);
}

static void hidden_stat_remove(const char* path) {
    if (!path) return;
    pthread_mutex_lock(&g_hidden_stats_lock);
    for (int i = 0; i < HIDDEN_STAT_SLOTS; i++) {
        if (g_hidden_stats[i].used && strcmp(g_hidden_stats[i].path, path) == 0) {
            g_hidden_stats[i].used = false;
            break;
        }
    }
    pthread_mutex_unlock(&g_hidden_stats_lock);
}

static int g_ready_fd = -1;
/* 崩溃触发测试：--crash-test[=segv|abrt|bus]，验证崩溃日志捕获链路 */
static int g_crash_test = 0; /* 0=无 1=SIGSEGV 2=SIGABRT 3=SIGBUS */
#ifdef TARGET_ANDROID
static bool g_bpf_disabled = false; /* --no-bpf：禁用 backing 直通挂接 */
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
static atomic_bool g_pt_probe_pending = false;      /* GNU：init 无会话 fd，探测推迟到首次 open。
                                                       多 worker 并发 open 时用原子 test-and-set 保证
                                                       只探测一次（见 B3；原先 bool 检查-清零非原子） */
static int passthrough_enable_fixed_method(int fd); /* 实现见文件后部 */
static bool g_is_media_fuse = false;                /* --media-fuse: 媒体模块专属 FUSE */
static char g_modules_dir_arg[PATH_MAX] = {0};      /* --modules-dir: 热插拔模块目录覆盖 */
static bool g_fuse_threads_explicit = false;       /* 是否由 --fuse-threads 显式指定 */
static int g_fuse_threads = 2;                      /* --fuse-threads: FUSE worker 线程数上限
                                                   （默认 2=双线程；0/-s=单线程；-1=libfuse 默认 10） */

/* Android backing fd 只由产生它的 worker 回收。legacy lookup 在 bpf_setup
   后同步发送 reply，期间不再调用 daemon；同 worker 下一 getattr 才能确认
   上次回复结束。别的 worker 进入回调不是成熟证明。worker 退出由 TSD 清尾。 */
#ifdef TARGET_ANDROID
static bool vfs_defer_close(int fd) { return fdq_thread_defer(fd); }
#endif

static void vfs_flush_pending_closes(void) {
#ifdef TARGET_ANDROID
    fdq_thread_flush();
#endif
}

static int recursive_rmdir(const char* path);
/* *created（可为 NULL）只在本次调用**成功创建** dst 时置 true：调用方据此
   只清理自己创建的临时产物，绝不碰别人的同名对象 */
static int recursive_copy_dir(const char* src, const char* dst, uid_t uid, gid_t gid,
                              bool* created);
/* FSYNC 与 FLUSH 共用的后端数据收尾（定义在 vfs_inval_path 之后） */
static int vfs_backend_finish_data(int slot, uint64_t fh, const char* path, bool write_intent);

/* open-unlink 本地直删的观测限速（范式同 fw_rules.c 的 br_note_isolation：
   首个命中 + 每 1024 次各一条）。真机 20:05:18 一秒 633 行（com.taobao.idlefish
   批量删 lockfile），把 sys.log 里有用的行全冲掉了。首条打全路径，之后每 1024 条
   一条、只报目录 + 累计计数——"哪个应用在批量删"够用，且不会变成新的刷屏源。 */
static void log_open_unlink_direct(const char* path) {
    static atomic_ulong seq;
    unsigned long n = atomic_fetch_add_explicit(&seq, 1, memory_order_relaxed) + 1;
    if (n == 1) {
        LOG_DBG("open-unlink 本地直删（不产生隐藏名）: %s", path);
        return;
    }
    if ((n & 1023u) != 0) return;
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", path);
    char* slash = strrchr(dir, '/');
    if (slash && slash != dir) *slash = '\0';
    LOG_DBG("open-unlink 本地直删（累计 %lu 次，此后只报目录）: %s/", n, dir);
}

static void log_fuse_err(const char* op, const char* path, int err_code) {
    int err = err_code < 0 ? -err_code : err_code;
    if (err != 0 && err != ENOENT && err != EEXIST && err != EROFS) {
        char current_pkg[128] = "unknown";
        struct fuse_context* ctx = fuse_get_context();
        if (ctx) {
            /* 包名由框架自算（fw_pkg.c）：错误日志路径不该再经模块围栏调用
               get_pkg——模块缺席时正是最需要看清"是哪个应用报的错"的时刻 */
            fw_pkg_resolve(ctx->uid, ctx->pid, current_pkg, sizeof(current_pkg));
        }
        fprintf(stderr,
                "[FUSE_ERR] 应用: %s (PID: %d, UID: %d) | 操作: %s | 路径: %s | 错误码: %d (%s)\n",
                current_pkg, ctx ? ctx->pid : 0, ctx ? ctx->uid : 0, op, path ? path : "nullptr",
                err, strerror(err));
        fflush(stderr);
        LOG_ERR("[FUSE_ERR] %s %s: %s", op, path ? path : "nullptr", strerror(err));
    }
}

/* 框架最小路径解析（无规则模块时的直通回退）：剥离 /0/ user_id 前缀 + 非法字符清理。
   用户层解析与规则引擎共用 common_parse_user_layer（唯一实现；数字串溢出 int 时
   该函数返回 -1——atoi 溢出会把 /4294967296/x 别名成 /0/x，必须 fail-closed）。 */
static int fw_parse_path(const char* path, int* user_id_out, char* sub_path_out, size_t sz) {
    if (!path) return -ENOENT;
    int uid = -1;
    const char* sub = path;
    int pr = common_parse_user_layer(path, &uid, &sub);
    if (pr < 0) return -ENOENT; /* 非法用户层：按不存在处理 */
    if (pr > 0 && user_id_out) *user_id_out = uid;
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

/* 前向声明：readdir 路径合成唯一出口（定义在后，probe/ino 派生先用） */
static void readdir_base_normalize(char* dst, size_t cap, const char* src);
static void readdir_join(char* dst, size_t cap, const char* base, const char* name);
static int readdir_join_checked(char* dst, size_t cap, const char* base, const char* name);

/* ================= 列举条目可见性单点（C2） =================
 * 「该目录条目对本次调用者是否可见」的唯一判定出口：本地物理扫描
 * （vfs_readdir_scan_local）、虚拟目录判空（fw_virtual_dir_empty）、后端
 * （FTP 等）列举（vfs_readdir_backend）三条路径共用——历史上三份副本各自
 * 处理 probe 且已分叉：后端路径**完全漏了过滤**（HIDE 条目在列举里可见而
 * stat ENOENT，既是「列表可见但打开 ENOENT」的反向形态，也构成名字泄露），
 * 另两份的路径过长截断策略还相反（一份 fail-closed、一份截断后 fail-open）。
 *
 * 契约：
 *   - probe 入参必须是**带 <uid>/ 层的原始 FUSE 路径**（fw_rules.h 的
 *     NspQueryCtx 注释）：传剥层路径会让探针早退（valid=false）而恒不过滤。
 *     故 item_fuse_out 由 fuse_path（未剥层）拼出；item_sub_out 仅作旁路输出
 *     （uid 目录判定等）。
 *   - 路径放不下返回 NSP_VIS_TOO_LONG（fail-closed 跳过），**绝不截断**后
 *     拿去 probe/lstat——截断路径可能命中另一个真实文件。
 *   - user_id 目录条目（/0、/1…）豁免 redirect_target：剥层后会被误判成根目录
 *     的 sandbox 重定向目标（与 getattr 的 uid 目录语义一致）。
 *   - hidden 对所有访问者生效（含 root），与 getattr 的 hidden 拒绝一致：
 *     否则 root 列举时被 HIDE 的条目仍出现而 stat 失败，隐藏不彻底。
 */
typedef enum {
    NSP_VIS_EMIT = 0, /* 可见：允许上架 */
    NSP_VIS_SKIP,     /* 不可见：跳过该条目 */
    NSP_VIS_TOO_LONG, /* 路径过长：跳过该条目（fail-closed） */
} NspVisibility;

/* 定义在 vfs_rename 附近；此处只需前置声明供 open-unlink 分支识别 */
static bool is_fuse_hidden_name(const char* name);

static NspVisibility vfs_entry_visibility(const char* sub_path, const char* fuse_path,
                                          const char* name, const char* current_pkg,
                                          int path_user_id, uid_t uid, char* item_sub_out,
                                          size_t sub_sz, char* item_fuse_out, size_t fuse_sz) {
    if (path_contains_invalid_chars(name)) return NSP_VIS_SKIP;
    /* libfuse 的 open-unlink 隐藏名（.fuse_hidden + 16 位十六进制）**不在此处
       过滤**：本层本地路径已改为直删（vfs_rename 的 open-unlink 分支，不再产生
       新隐藏名），磁盘上出现的残留来自旧版本 daemon 或下层 FUSE（/data/media
       由 MediaProvider 提供时，本层 unlink 会触发下层 libfuse 的 hide 语义）。
       按普通条目可见、可 getattr/open——保留取证与手工回收能力，
       既不做列举过滤，也不在列举时就地删除。 */
    char norm_base[2048], norm_fuse_base[2048];
    /* base 先剥尾部 '/'（与 getattr/child_ino 同一合成语义）：非规范 sub_path
       （如 "/Android/data/"）会拼出 "//name"，与 getattr 规范形式的哈希不一致 */
    readdir_base_normalize(norm_base, sizeof norm_base, sub_path);
    readdir_base_normalize(norm_fuse_base, sizeof norm_fuse_base, fuse_path);
    if (readdir_join_checked(item_sub_out, sub_sz, norm_base, name) != 0) return NSP_VIS_TOO_LONG;
    if (readdir_join_checked(item_fuse_out, fuse_sz, norm_fuse_base, name) != 0)
        return NSP_VIS_TOO_LONG;

    /* Android/data|obb 只显示自身包名（沙盒/无用户层时该语义不适用）。
       与 resolve 侧 br_isolation_blocks 共用同一条判据（fw_rules_cross_app_access：
       白名单、特权签名、能力档），三处判定只写一份，否则会出现「列表看得到、
       按名打开却 ENOENT」的割裂。能力档区分完整访问与只读 obb，故这里要按当前
       列举的父目录传 is_obb。appops 查询有代价（一次调用，按 uid 缓存 30s），
       档位判定内部对已命中白名单/特权的调用方早退，不查。
       同 uid 多包（sharedUserId / 系统同进程宿主）按 uid 视为同一应用：目录名与
       调用方解析出的包名不同，但属主 uid 相同，列举不能把它滤掉。 */
    bool skip_sandbox = (path_user_id < 0) || g_disable_sandbox;
    bool hide_others = (!skip_sandbox && current_pkg && current_pkg[0] &&
                        strcmp(current_pkg, "system") != 0 && strcmp(current_pkg, "unknown") != 0);
    if (hide_others &&
        (strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 ||
         strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0)) {
        uid_t owner_uid = 0;
        bool same_app = (strcmp(name, current_pkg) == 0) ||
                        (fw_pkg_uid_for_package(name, &owner_uid) && owner_uid == uid);
        bool is_obb = (strncmp(sub_path, "/Android/obb", 12) == 0);
        if (!same_app &&
            fw_rules_cross_app_access_snapshot(current_pkg, uid, is_obb) == NSP_XAPP_NONE)
            return NSP_VIS_SKIP;
    }

    /* 子项轻量探测：只判 hidden/redirect_target，不构建真实路径、不触发
       sandbox 目录创建（无规则时直通不过滤） */
    bool uid_dir = false;
    if (item_sub_out[0] == '/' && isdigit((unsigned char)item_sub_out[1])) {
        const char* dg = item_sub_out + 1;
        while (isdigit((unsigned char)*dg)) dg++;
        uid_dir = (*dg == '\0' || *dg == '/');
    }
    struct fuse_context* c = fuse_get_context();
    NspQueryCtx q = {
        .uid = uid, .pid = c ? c->pid : 0, .gid = c ? c->gid : 0, .path = item_fuse_out};
    NspProbeResult r;
    memset(&r, 0, sizeof r);
    fw_rules_probe(&q, &r);
    if (r.valid && (r.appear_missing || (!uid_dir && r.virtual_kind == NSP_VK_TARGET)))
        return NSP_VIS_SKIP;
    return NSP_VIS_EMIT;
}

/* 虚拟目录判空（原 vfs_is_virtual_dir_empty 的分派器版）：
   - 虚拟祖先 → 视为非空（拒绝删除）
   - 否则扫描真实目录，跳过规则隐藏/重定向子项（与 readdir 过滤一致，共用
     vfs_entry_visibility 单点） */
static bool fw_virtual_dir_empty(const char* fuse_path, const char* sub_path,
                                 const char* real_path, const char* current_pkg, int path_user_id,
                                 uid_t uid) {
    if (uid != 0) {
        struct fuse_context* c = fuse_get_context();
        /* probe 收带 <uid>/ 层的原始路径（同 readdir 侧），否则探针早退、过滤失效 */
        NspQueryCtx q0 = {
            .uid = uid, .pid = c ? c->pid : 0, .gid = c ? c->gid : 0, .path = fuse_path};
        NspProbeResult r0;
        memset(&r0, 0, sizeof r0);
        fw_rules_probe(&q0, &r0);
        if (r0.valid && r0.virtual_kind == NSP_VK_ANCESTOR)
            return false;
    }
    struct stat st;
    if (lstat(real_path, &st) == -1) return true;
    DIR* dp = opendir(real_path);
    if (!dp) return false;
    struct dirent* de;
    bool empty = true;
    while ((de = readdir(dp)) != nullptr) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char item_sub[2048], item_fuse[2048];
        if (vfs_entry_visibility(sub_path, fuse_path, de->d_name, current_pkg, path_user_id, uid,
                                 item_sub, sizeof item_sub, item_fuse, sizeof item_fuse) !=
            NSP_VIS_EMIT)
            continue;
        empty = false;
        break;
    }
    closedir(dp);
    return empty;
}

/* 路径段判定与合成条目属性住在 vfs_synth.c：readdir 列举与 getattr/access/
   opendir 兜底共用同一份实现，避免「列表里看得见、stat 却失败」的口径漂移。 */

/* ================= 三层数据路径（Phase 2 重构） =================
 *   FUSE 节点（内核）→ FUSE 守护进程：
 *     ① 路由层   fw_route()：FUSE 上下文 + 原始路径 → 路由决策
 *                （user_id 剥离 / fw_rules_resolve 规则决策 / 直通回退 /
 *                 决策强制：appear_missing → ENOENT、read_only → EROFS）
 *     ② 模块层   module_backend_*（loader）：原子槽位快照 + 在途引用
 *                （无锁分派）+ 调用围栏（崩溃→longjmp 恢复）+ 输出校验 +
 *                熔断（错误→卸载）。规则决策不在此层：引擎已内建（fw_rules）
 *     ③ FUSE 输出层  各 vfs_* 回调体：消费路由决策，执行真实系统操作
 *                （lstat/open/read/filler...）并返回 FUSE 语义
 * VFS_SETUP_CORE 是①③之间的薄胶水：声明回调体使用的局部变量并调用
 * 路由层（局部变量名保持与原实现一致，回调体零改动）。
 * 线程安全：三层全部无全局可变状态依赖（路由层纯函数 + 模块层原子
 * 快照），FUSE 多线程（fuse_session_loop_mt）下任意 worker 并发进入。 */
/* ================= 决策强制（框架单点） =================
 * 规则引擎只声明"这个路径该怎么表现"（NspPathDecision，见 fw_rules.h），errno
 * 映射与权限策略集中在此，不再散落在各回调里各判一遍：
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

/* ================= 存储根一级条目守卫（框架单点） =================
 * 背景（历史缺陷）：/data/media（= /storage/emulated）顶层反复出现纯数字垃圾
 * 目录，用户只能在 /data/media 下删除。链路是「应用请求 /<数字>/… → 框架把
 * 第一个全数字段当 user_id（fw_parse_path/br_strip_and_sanitize 均无存在性
 * 校验）→ real_path=<STORAGE_BASE>/<数字>/… → 创建路径的父目录补建以 root
 * 把 <STORAGE_BASE>/<数字> 造出来」，此后它就被当成真实用户目录反复使用。
 * 存储根一级条目（用户存储根 0/10/…、obb）由 vold 掌管，FUSE 视图不承载该
 * 命名空间的管理，两个判定都在此 fail-closed：
 *   ① 路径带 <uid>/ 层而 <STORAGE_BASE>/<uid> 不是目录 → -ENOENT（**读写一律**）；
 *   ② real_path 恰为存储根一级条目：变更（创建/删除/改名/元数据）→ -EPERM，
 *      读（列出/stat 既有条目）照旧放行。
 * ①为什么连读也拦：规则引擎的虚拟目录合成会把 /<数字> 合成为“已存在目录”
 * （NSP_VK_ANCESTOR，根级 REDIRECT 规则下必现），应用据此下探 /<数字>/… 并在
 * CREATE/MKDIR/RENAME/SYMLINK 的父目录补建里把 <STORAGE_BASE>/<数字> 造出来
 * ——这正是线上「顶层反复出现纯数字垃圾目录」的主链路（根级 REDIRECT + 数字名
 * 请求 = 100% 复现）。读侧返回 ENOENT 后内核不再认为该名字存在，下探不会发生。
 * 成本：正例用户（0/999…）首次 lstat 后入 16 槽缓存，稳态零系统调用；负例每次
 * lstat（只发生在垃圾/攻击路径上）。
 * root 调用者同样拒绝：这不是 DAC，而是结构性约束；需要管理一级条目时走真实
 * 路径 /data/media/<uid>。两个判定都只在此处，各回调不得私刻（与 hidden/ro
 * 单点同一红线）。拒绝日志按原因 1 小时限频（nsp_log_gate 非线程安全，多 worker
 * 用短锁包住）。 */
#define VFS_USER_ROOT_CACHE_MAX 16
static _Atomic int g_vfs_user_ok[VFS_USER_ROOT_CACHE_MAX];
static _Atomic int g_vfs_user_ok_n;

/* 用户存储根存在性：正例入小表缓存（设备上用户数极少，命中后零开销）；负例每次
   复查，避免把「模块运行期新建的用户」永久误判为不存在。 */
static bool vfs_user_root_exists(int user_id) {
    int n = atomic_load_explicit(&g_vfs_user_ok_n, memory_order_relaxed);
    if (n > VFS_USER_ROOT_CACHE_MAX) n = VFS_USER_ROOT_CACHE_MAX;
    for (int i = 0; i < n; i++) {
        if (atomic_load_explicit(&g_vfs_user_ok[i], memory_order_relaxed) == user_id) return true;
    }
    char uroot[PATH_MAX];
    common_storage_root(user_id, uroot, sizeof uroot);
    if (uroot[0] == '\0') return false;
    struct stat st;
    if (lstat(uroot, &st) != 0 || !S_ISDIR(st.st_mode)) return false;
    int slot = atomic_load_explicit(&g_vfs_user_ok_n, memory_order_relaxed);
    while (slot >= 0 && slot < VFS_USER_ROOT_CACHE_MAX &&
           !atomic_compare_exchange_weak_explicit(&g_vfs_user_ok_n, &slot, slot + 1,
                                                  memory_order_relaxed, memory_order_relaxed)) {
    }
    if (slot >= 0 && slot < VFS_USER_ROOT_CACHE_MAX)
        atomic_store_explicit(&g_vfs_user_ok[slot], user_id, memory_order_relaxed);
    return true;
}

enum { SRG_UNKNOWN_USER = 0, SRG_ROOT_ENTRY = 1, SRG_N };
static const char* const g_srg_reason[SRG_N] = {"不存在的用户存储根", "变更存储根一级条目"};
static NspLogGate g_srg_gate[SRG_N];
static pthread_mutex_t g_srg_mu = PTHREAD_MUTEX_INITIALIZER;

static void storage_root_guard_log(int reason, const char* path, const char* real, const char* pkg,
                                   uid_t uid, pid_t pid) {
    unsigned suppressed = 0;
    pthread_mutex_lock(&g_srg_mu);
    bool emit = nsp_log_gate(&g_srg_gate[reason], path ? path : "?", 3600, &suppressed);
    pthread_mutex_unlock(&g_srg_mu);
    if (!emit) return;
    if (suppressed)
        LOG_WRN("[STORAGE_ROOT_GUARD] 拒绝%s（另有 %u 次同因被抑制）: path=%s real=%s "
                "pkg=%s(uid=%u,pid=%d)",
                g_srg_reason[reason], suppressed, path ? path : "?", real ? real : "?",
                pkg ? pkg : "unknown", (unsigned)uid, (int)pid);
    else
        LOG_WRN("[STORAGE_ROOT_GUARD] 拒绝%s: path=%s real=%s pkg=%s(uid=%u,pid=%d)",
                g_srg_reason[reason], path ? path : "?", real ? real : "?", pkg ? pkg : "unknown",
                (unsigned)uid, (int)pid);
}

/* 返回 0 放行，负 errno 拒绝：① 不存在的用户存储根 → -ENOENT（**读写都拦**，
   见函数头注释的主链路说明）；② 变更存储根一级条目 → -EPERM（读放行）。
   op 只对②有意义；带写 flags 的 open 由 vfs_open 显式按 MUTATE 再调一次。 */
static int vfs_storage_root_guard(const struct fuse_context* ctx, const char* path_val,
                                  const char* current_pkg, int user_id, const char* real_path,
                                  VfsOpKind op) {
    if (user_id >= 0 && !vfs_user_root_exists(user_id)) {
        storage_root_guard_log(SRG_UNKNOWN_USER, path_val, real_path, current_pkg, ctx->uid,
                               ctx->pid);
        return -ENOENT;
    }
    if (op == VFS_OP_MUTATE && common_is_storage_root_entry(real_path)) {
        storage_root_guard_log(SRG_ROOT_ENTRY, path_val, real_path, current_pkg, ctx->uid,
                               ctx->pid);
        return -EPERM;
    }
    return 0;
}

/* 判定内核（**唯一决策点**）。对外一律经下方的 fw_route 包装调用——包装只做
   "把已经做出的决定如实转述给事件通道"，不参与判定，也不改变返回值。 */
static int fw_route_inner(struct fuse_context* ctx, const char* path_val, NspPathDecision* rr,
                          bool* nsp_ok, char* current_pkg, int* user_id, char* sub_path,
                          char* real_path, bool* is_redir, bool* monitor_out, VfsOpKind op,
                          NspAclOp acl_op, bool acl_is_dir, int acl_mask) {
    *nsp_ok = false;
    /* user_id 必须先置 -1：fw_parse_path 只在路径含完整 <uid>/ 用户层时才写它，
       挂载点根（"/"）等无用户层路径不会赋值——漏置会让调用方拿到未初始化值，
       下游（如 readdir 的 user_id<0 判定）据此误判为"在用户层内" */
    *user_id = -1;
    *is_redir = false;
    sub_path[0] = '\0';
    real_path[0] = '\0';
    strcpy(current_pkg, "unknown");
    /* 用户层剥离与虚拟路径归一由框架自算：与规则引擎共用
       common_parse_user_layer（唯一实现，含数字串溢出 fail-closed），
       故 V3 起不经 ABI 回传——模块只回传它真正能决定的字段 */
    if (fw_parse_path(path_val, user_id, sub_path, PATH_MAX) != 0) return -ENOENT;
    /* uid→包名与 MONITOR 开关都由框架自算，不取模块返回值：
       - 包名是配置语义的输入（段匹配键、日志标签），模块缺失时也必须有值；
       - MONITOR 是**配置开关**而非路径决策，若跟着「模块是否给出有效决策」一起
         丢，就会出现「文件读写一切正常、IO 监控日志静默归零」——历史上正是把
         开关绑在 nsp_ok 上的后果。三层合并（应用显式 > 类别显式 > 全局，含
         [USER_APPS:<uid>]/[SYSTEM_APPS]）在 fw_config_monitor_for 内完成，
         与模块同语义但不依赖模块。
       开关不经决策结构回传（它不是路径决策，V4 起 NspPathDecision 已无该字段），
       由本函数经 monitor_out 单独给出。 */
    *monitor_out = fw_config_monitor_for(ctx->uid, ctx->pid);
    fw_pkg_resolve(ctx->uid, ctx->pid, current_pkg, 128);
    /* ---- 访问控制唯一执行点（对齐 Android 原生 FUSE 的用户态策略层）----
       位置与 AOSP 一致：先判「这个调用者能不能碰这条路径」，再谈规则决策。
       - Android 的 emulated FUSE 故意不加 default_permissions（vold 原注释：
         不让内核在路由到 daemon 之前做低层权限检查），属主/权限由 daemon 合成；
         我们的挂载参数因此与之等价，策略全在本调用上。
       - 判定逻辑只在 fw_acl_decide 一份（fw_acl.c）；这里不得再写任何 if。
       - 拒绝码分工见 fw_acl.h：ENOENT=看不见、EACCES=存在但不许、EPERM=结构层不许。 */
    {
        int acl_rc = fw_acl_check(ctx->uid, ctx->pid, path_val, acl_op, acl_is_dir, acl_mask);
        if (acl_rc != 0) return acl_rc;
    }
    /* fw_rules_resolve 内建：无 <uid>/ 用户层的路径（挂载点根）由引擎自己置
       valid=false，机构与「模块未命中」一致——调用方只看 rr->valid。决策结构
       由引擎整体初始化，调用方无需预置。 */
    NspQueryCtx nsp_q = {.uid = ctx->uid, .pid = ctx->pid, .gid = ctx->gid, .path = path_val};
    fw_rules_resolve(&nsp_q, rr);
    if (rr->valid) {
        *nsp_ok = true;
        strcpy(real_path, rr->real_path);
        *is_redir = rr->is_redirect;
        /* ---- 决策强制（单点）---- */
        if (rr->appear_missing)
            return rr->deny_errno ? -rr->deny_errno : -ENOENT; /* HIDE_ERRNO 可换码 */
        if (op == VFS_OP_MUTATE) {
            int rc = vfs_check_read_only(rr, ctx->uid);
            if (rc != 0) {
                /* 拒绝日志也收口在此：原先每个变更回调各写一条
                   <OP>_RO_DENIED，同一声明散成 11 处重复代码 */
                log_fuse_err("RO_DENIED", path_val, -rc);
                return rc;
            }
        }
        return vfs_storage_root_guard(ctx, path_val, current_pkg, *user_id, real_path, op);
    }
    /* 框架直通回退（无规则模块 / 模块未命中）：路径决策退回默认真实路径。
       监控开关已在入口由框架定值，此处无需也不得再改写——改写即等于把开关
       重新绑回「模块是否给出有效决策」上。 */
    fw_default_real_path(*user_id, sub_path, real_path, PATH_MAX);
    return vfs_storage_root_guard(ctx, path_val, current_pkg, *user_id, real_path, op);
}

/* 对外决策入口：内核判定 + 拒绝埋点。
   write_denied 的语义是「这次变更没落盘」，所以只在变更操作上转述；具体
   errno（EROFS/HIDE→ENOENT/ACL→EACCES|EPERM）与 op（create/mkdir/rename）
   的取舍在 fw_events_note_write_denied 内，本函数不写任何判定。 */
static int fw_route(struct fuse_context* ctx, const char* path_val, NspPathDecision* rr,
                    bool* nsp_ok, char* current_pkg, int* user_id, char* sub_path, char* real_path,
                    bool* is_redir, bool* monitor_out, VfsOpKind op, NspAclOp acl_op,
                    bool acl_is_dir, int acl_mask) {
    int rc = fw_route_inner(ctx, path_val, rr, nsp_ok, current_pkg, user_id, sub_path, real_path,
                            is_redir, monitor_out, op, acl_op, acl_is_dir, acl_mask);
    if (rc < 0 && op == VFS_OP_MUTATE && fw_events_active())
        fw_events_note_write_denied(ctx->uid, ctx->pid, path_val, acl_op, rc);
    return rc;
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

/* ================= 后端分派统一收口（C5） =================
 * 八个回调（getattr/open/create/mkdir/unlink/rmdir/truncate/readdir）原先各抄
 * 一遍同一串「lookup → 判空 → 围栏 → 三类判据（FAULT / BADFN / 业务 errno）
 * → guard → put」。A20 的三个漏网点（回传长度钳制、backend_put_before_guard
 * 顺序约束、业务 errno 豁免）全都出在这份复制里——复制几份就漏几处。
 *
 * 这里把「拿到 ops 之后的收尾」抽成一条窄原语，让每处调用点只剩
 * 「lookup + 一次 put + 一次统一收尾」：
 *
 *   backend_dispatch_after  —— 通用收尾。调用方在围栏返回后**已**交还在途
 *       引用（`module_backend_put(bops)`）再调用它；它按 brc 分三类处置，
 *       返回 true 表示「已处理，调用方应直接 VFS_RETURN(*out_rc)」，
 *       false 表示「brc == 0，继续走成功路径」。
 *
 * 分类核心 backend_dispatch_classify 只有这一份定义——「哪些码算业务失败」
 * 不再各回调各判一遍，正是 C5 要防的漂移。
 *
 * readdir 未走此原语：它的分页循环有五个早退分支，每个分支的「上报码 +
 * 人可读消息」都不同（FAULT→-EIO、"条目名未终止"→-EIO、业务 errno→原样…），
 * 且须在置毒前 `backend_put_before_guard` 交还引用。强行套通用原语会让
 * 调用点比展开版更绕，故保留其显式写法；但「业务 errno 判定」**仍复用**
 * backend_rc_is_business 单点定义。 */

static inline int backend_dispatch_classify(int bslot, const char* op, int brc, const char* sub_path,
                                            const char* what) {
    if (brc == NSP_FENCE_FAULT) {
        /* 模块在围栏内崩溃：置毒卸载（规则/能力自动失效）并落盘 ban */
        module_guard_fault(bslot, op, sub_path);
        return -EIO;
    }
    if (brc != 0) {
        /* BADFN = 函数指针缺失（按未实现处理，不算违约）；
           业务 errno（-4095..0）是 backend_* 的**契约**，原样回传；
           其余（正数 / 超出 errno 范围）才是契约违规 → 计错误熔断。 */
        if (brc != NSP_FENCE_BADFN && !backend_rc_is_business(brc))
            module_guard_error(bslot, op, brc, sub_path, what);
        return brc < 0 ? brc : -EIO;
    }
    return 0; /* 成功 */
}

/* 通用收尾：调用方已 put。true = 已处理（*out_rc 为 FUSE 返回码）。 */
static inline bool backend_dispatch_after(int bslot, const char* op, int brc, const char* sub_path,
                                          const char* what, int* out_rc) {
    int rc = backend_dispatch_classify(bslot, op, brc, sub_path, what);
    if (rc != 0) {
        *out_rc = rc;
        return true;
    }
    return false;
}

#define VFS_SETUP_CORE_EX(path_val, op_kind, acl_op, acl_is_dir, acl_mask)        \
    struct fuse_context* ctx = fuse_get_context();                                \
    if (!ctx) return -EIO; /* 不可达：libfuse 在每个回调内均设置上下文 */          \
    NspPathDecision rr;                                                           \
    bool nsp_ok = false;                                                          \
    char current_pkg[128];                                                        \
    int path_user_id;                                                             \
    char sub_path[PATH_MAX];                                                      \
    char p[PATH_MAX];                                                             \
    bool is_redir;                                                                \
    bool monitor_on; /* IO 监控开关：配置语义，由 fw_route 单独给出 */             \
    int fw_rc = fw_route(ctx, path_val, &rr, &nsp_ok, current_pkg, &path_user_id, \
                         sub_path, p, &is_redir, &monitor_on, op_kind, acl_op,    \
                         acl_is_dir, acl_mask);                                   \
    if (fw_rc != 0) return fw_rc;                                                 \
    (void)is_redir; /* 部分回调不使用 is_redir，抑制未使用警告 */

/* 缺省入口：按读写种类给一个粗粒度 ACL 操作。需要精确拒绝码的回调
   （create/unlink/rename/setattr/access…）改用 VFS_SETUP_CORE_OP/ACCESS。
   ACL 的**判定**始终只有 fw_acl_decide 一处，这里只选「操作种类」。 */
#define VFS_SETUP_CORE(path_val, op_kind)                                         \
    VFS_SETUP_CORE_EX(path_val, op_kind,                                          \
                      ((op_kind) == VFS_OP_MUTATE ? NSP_ACL_OP_GENERIC_WRITE        \
                                                  : NSP_ACL_OP_GENERIC_READ),      \
                      false, 0)

#define VFS_SETUP_CORE_OP(path_val, op_kind, acl_op)                              \
    VFS_SETUP_CORE_EX(path_val, op_kind, acl_op, false, 0)

#define VFS_SETUP_CORE_ACCESS(path_val, op_kind, acl_mask, acl_is_dir)            \
    VFS_SETUP_CORE_EX(path_val, op_kind, NSP_ACL_OP_ACCESS, acl_is_dir, acl_mask)

#define VFS_RETURN(val) \
    do {                \
        return val;     \
    } while (0)

/* 框架版 I/O 监控日志：由框架记录目标应用操作的【原始路径】；
   target_path 为模块 resolve 可选返回的【目标路径】（REDIRECT 命中时
   非空，否则 NULL），附加到日志尾部。monitor 开关由 fw_route 单点给出，
   且由框架自算（fw_config_monitor_for 的三层合并），与规则模块是否加载无关。 */
/* 监控日志目标路径展示归一：仅剥 STORAGE_BASE（/data/media）存储根前缀，
   其余保持绝对路径（g_real_root 测试根、FTP 目标等非存储根路径原样返回）。
   /data/media/0/x → /0/x：user_id 层即展示起点，与 orig_path（sub_path）
   的相对口径对齐。边界：恰好等于存储根时回 "/"；非完整前缀（如
   /data/mediafoo）不剥 */
static const char* log_strip_storage_base(const char* path) {
    if (!path) return path;
    size_t bl = sizeof(STORAGE_BASE) - 1;
    if (strncmp(path, STORAGE_BASE, bl) != 0) return path;
    if (path[bl] == '/') return path + bl;
    if (path[bl] == '\0') return "/";
    return path;
}

static void vfs_log_io(const char* pkg, uid_t uid, const char* op, const char* orig_path,
                       const char* target_path, bool monitor_on) {
    /* 热路径提前过滤：MONITOR 关闭且非 DEBUG 级别时零开销返回。
       LOG_IO 为通道标记（0x81）恒 > g_min_log_level，log_internal 不会过滤
       它，故格式化仅在 monitor_on 或 DEBUG MAP 分支才真正需要。
       monitor_on 由 fw_route 单点给出（框架按 uid→包名做三层合并，不取模块
       返回值），调用方不得再用 nsp_ok 门控——那正是历史上「模块未命中即静默
       停记」的来源。 */
    if (!monitor_on && g_min_log_level != LOG_DEBUG) return;
    const char* t = log_strip_storage_base(target_path);
    if (monitor_on) {
        if (t && t[0]) {
            log_internal(LOG_IO, "[%s(%u)] [%s] %s -> %s", pkg, uid, op, orig_path, t);
        } else {
            log_internal(LOG_IO, "[%s(%u)] [%s] %s", pkg, uid, op, orig_path);
        }
    }
    if (t && t[0] && g_min_log_level == LOG_DEBUG) {
        log_internal(LOG_DEBUG, "[MAP] %s: '%s' -> '%s'", op, orig_path, t);
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

/* 为合成目录 stat 生成非零 inode（原 vfs_core.h static inline）。
   正常路径哈希恒为奇数（h | 1），故 NULL 哨兵取偶数 2——既非 0（use_ino=1
   下 0 会原样进内核），也不与根节点号 1（FUSE_ROOT_ID）混淆，且永不与
   正常哈希碰撞 */
static inline ino_t synthetic_inode(const char* path) {
    if (!path) return 2;
    unsigned long h = 5381;
    int c;
    while ((c = (unsigned char)*path++)) h = ((h << 5) + h) + c;
    return (ino_t)(h | 1);
}

/* 合成条目 d_ino 派生（框架侧唯一出口）：按「父 sub_path + 名字」拼出子项
   全路径再哈希，与 vfs_getattr 的 synthetic_inode(sub_path) 同一套算法。
   d_ino 与后续 lookup 的 attr ino 不一致时内核反复重查；裸名哈希（如
   synthetic_inode("data")）与全路径哈希（synthetic_inode("/Android/data")）
   是两个值，故此处禁止裸名入哈希 */
static ino_t vfs_readdir_child_ino(const char* parent_sub, const char* name) {
    char child[PATH_MAX];
    if (!parent_sub || parent_sub[0] == '\0' || strcmp(parent_sub, "/") == 0)
        snprintf(child, sizeof child, "/%s", name);
    else {
        /* 父路径归一复用 readdir_base_normalize（与 readdir probe/合成同一出口），
           否则 "/a//name" 双斜杠哈希与 getattr 规范形式不一致，d_ino != st_ino
           复发 lookup 风暴 */
        char base[PATH_MAX];
        readdir_base_normalize(base, sizeof base, parent_sub);
        snprintf(child, sizeof child, "%s/%s", base, name);
    }
    return synthetic_inode(child);
}

/* /Android/media 的骨架兜底：沙盒里的 /Android 取自镜像，镜像里没有 media 条目
   （列举时由 vfs_readdir_fill_android_children 补这一条），而容器本身按真实目录
   让位——两处口径必须同时成立，否则又回到「列表里看得见、按名 stat 却 ENOENT」。
   它只是骨架容器：容器内的 <pkg> 是按名裁决的真实目录，没有 own_pkg 合成，故不
   进数据容器那套判定。 */
static bool android_media_skel(const char* sub_path) {
    return sub_path_is_android_media_container(sub_path);
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
            int drc;
            if (backend_dispatch_after(bslot, "backend_getattr", brc, sub_path, "getattr 返回异常",
                                       &drc))
                VFS_RETURN(drc);
            /* 后端不提供真实属主（uid/gid=0）时继承其本地上级——用户存储根
               /data/media/<uid>/（FTP 虚拟路径在本地不存在，直接父目录 lstat
               必失败，故取用户存储根的真实属主，而非固定 root） */
            /* st_ino 兜底：后端模块普遍只填 mode/size/mtime（FTP 即如此），
               而框架以 use_ino=1 挂载 → libfuse 不会回填 st_ino（见其
               set_stat：仅 !use_ino 时才用 nodeid），**0 会原样进内核**：
               该 inode 的 i_ino 变 0，`ls -i` 显示 0，按 inode 去重的工具
               （find -samefile / rsync / tar）会把不同文件当成同一个。
               故后端未给出非 0 ino 时，用**路径派生**的稳定值兜底——与
               readdir 条目同一套算法，保证「目录项 d_ino == 该路径 getattr
               的 st_ino」，避免内核反复重查。 */
            if (st->st_ino == 0) st->st_ino = synthetic_inode(sub_path);
            /* 类型位契约：后端必须给出 S_IFMT（文件/目录），缺失时内核按无类型
               处理——目录在文件管理器中显示为文件且无法点击，子路径却仍可进入。
               fail-closed：判契约违规（EIO + 熔断计数），不把错类型送进内核。 */
            if ((st->st_mode & S_IFMT) == 0) {
                module_guard_error(bslot, "backend_getattr", EIO, sub_path,
                                   "getattr 未给出文件类型位");
                VFS_RETURN(-EIO);
            }
            if (st->st_uid == 0 && st->st_gid == 0) {
                int root_uid = (path_user_id >= 0) ? path_user_id : 0;
                char root_path[PATH_MAX];
                common_storage_root(root_uid, root_path, sizeof(root_path));
                struct stat pst;
                if (lstat(root_path, &pst) == 0) {
                    st->st_uid = pst.st_uid;
                    st->st_gid = pst.st_gid;
                }
            }
            VFS_RETURN(0);
        }
    }
    if (lstat(p, st) == -1) {
        int err = errno;
        /* open-unlink 后名字已不存在：先查删除时留下的属性快照（内核的 fstat
           不总带 fh，实测 fi 为 NULL），再退回句柄 fstat。缺了这层，fstat(2)
           会拿到 ENOENT——Android 自带 FUSE 在同样场景下 fstat 是正常的。 */
        if (hidden_stat_get(path, st)) {
            VFS_RETURN(0);
        }
        if (fi && fi->fh > 0 && !(fi->fh & NSP_FH_BACKEND_FLAG) && fstat((int)fi->fh, st) == 0) {
            VFS_RETURN(0);
        }
        if ((err == ENOENT || err == EACCES) &&
            (is_android_skel_dir(sub_path) || android_media_skel(sub_path) ||
             (is_virtual_own_pkg_dir(sub_path, current_pkg) &&
              nsp_listed_own_pkg(ctx->uid, sub_path, current_pkg)) ||
             rr.virtual_kind == NSP_VK_ANCESTOR || rr.virtual_kind == NSP_VK_TARGET)) {
            /* 虚拟目录（无真实底层文件，如 FTP 前缀/重定向祖先）：权限继承
               上级目录（父路径的真实 mode/uid/gid），而非固定 root/访问者 */
            memset(st, 0, sizeof(struct stat));
            st->st_ino = synthetic_inode(sub_path);
            st->st_mode = S_IFDIR;
            st->st_nlink = 2;
            st->st_size = 4096;
            struct stat pst;
            /* 逐级上溯到最近存在的祖先：重定向落点不存在时整条链都是合成的，
               直接父目录 lstat 不到是常态；只问一层会让时间戳留 0（1970-01-01） */
            if (nsp_stat_nearest_ancestor(p, &pst)) {
                st->st_mode |= (pst.st_mode & 07777);
                st->st_uid = pst.st_uid;
                st->st_gid = pst.st_gid;
                /* 时间戳同样继承上级：留 0 会让客户端显示 1970-01-01 */
                st->st_atime = pst.st_atime;
                st->st_mtime = pst.st_mtime;
                st->st_ctime = pst.st_ctime;
            } else {
                /* 上级也取不到（挂载点还没就绪，或整条链都不存在）：权限位仍要有个
                   真实出处，否则凭空造出的 0755 会在 0770 的树上表现成"文件管理器
                   看得到、open 又被拒"。取本次调用的用户存储根（<base>/<user_id>）
                   的真实 mode；连它也 lstat 不到时保持 0——属主未知（root/未知），
                   不伪造为访问者属主。 */
                char uroot[PATH_MAX];
                common_storage_root(path_user_id >= 0 ? path_user_id : 0, uroot, sizeof(uroot));
                struct stat rst;
                if (uroot[0] && lstat(uroot, &rst) == 0)
                    st->st_mode |= (rst.st_mode & 07777);
                else
                    st->st_mode |= 0755;
            }
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
    /* 属性一律原样上报底层真实值。旧的「默认伪造模式」（属主改写为访问者、
       重定向目录强制 0777、skel 目录强制 0755 + 访问者属主）已删除：
       挂载未开 default_permissions，内核本就不做 DAC 判定（fuse_permission
       对 open/read/write 直接放行，仅 access(2) 才下发 FUSE_ACCESS），模块
       也不具备 POSIX DAC——伪造属主拦不住任何访问，纯属误导读取方。 */
    VFS_RETURN(0);
}

static int vfs_access(const char* path, int mask) {
    vfs_flush_pending_closes();
    /* is_dir 只能保守取 true：access 在路由解析之前判，此时拿不到 stat。
       代价仅是「文件的 X_OK 不被单独拒」——AOSP 因 MS_NOEXEC 恒拒，我们留到
       内核真正 exec 时拒绝（多一层，但不会误伤目录的 X_OK）。 */
    VFS_SETUP_CORE_ACCESS(path, VFS_OP_READ, mask, true);
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
            (is_android_skel_dir(sub_path) || android_media_skel(sub_path) ||
             (is_virtual_own_pkg_dir(sub_path, current_pkg) &&
              nsp_listed_own_pkg(ctx->uid, sub_path, current_pkg)) ||
             rr.virtual_kind == NSP_VK_ANCESTOR || rr.virtual_kind == NSP_VK_TARGET)) {
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

/* readdir d_ino 派生的 base 归一化：NULL/空串/"/" 归一为 ""（readdir_join
   根语义），其余剥掉尾部 '/'（长度>1 才剥）——与 getattr 侧 fw_parse_path
   的规范化对齐，避免 "/a/" + name 拼出 "/a//name" 双斜杠哈希漂移 */
static void readdir_base_normalize(char* dst, size_t cap, const char* src) {
    if (!src || src[0] == '\0' || strcmp(src, "/") == 0) {
        dst[0] = '\0';
        return;
    }
    size_t bl = strlen(src);
    if (bl >= cap) bl = cap - 1;
    memcpy(dst, src, bl);
    dst[bl] = '\0';
    while (bl > 1 && dst[bl - 1] == '/') dst[--bl] = '\0';
}

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

/* readdir_join 的带检查版本：放不下（含恰好占满，需留 NUL）返回 -1。
   列举可见性判定用它——截断路径拿去做 probe/lstat 可能命中另一个真实文件
   （fail-open），必须让调用方 fail-closed 跳过该条目（C2）。 */
static int readdir_join_checked(char* dst, size_t cap, const char* base, const char* name) {
    size_t bl = strlen(base);
    size_t nl = strlen(name);
    if (bl + 1 + nl + 1 > cap) return -1;
    memcpy(dst, base, bl);
    dst[bl] = '/';
    memcpy(dst + bl + 1, name, nl + 1);
    return 0;
}

/* ================= readdir 分阶段实现 =================
 * vfs_readdir 拆为：后端分派 → 本地目录扫描（probe 过滤/去重/filler）
 * → 骨架与虚拟目录合成 → . / .. 收尾。各阶段共享 VfsReaddirCtx，
 * 任一 filler 返回非 0（内核缓冲已满）即短路结束本次 readdir（返回 0）。
 * 断点续扫：单目录一次列不完时内核带 offset（上次收到的条目 off）再次调用；
 * 所有发射经 vfs_emit 单点编号（off 从 1 起），offset>0 时跳过去重后的前
 * offset 个条目。去重（ht）在编号之前，故跨调用序列稳定（同目录无并发
 * 修改时；并发增删下的重复/遗漏是 offset cookie 的固有语义）。 */
typedef struct {
    struct fuse_context* ctx;
    const char* fuse_path; /* 未剥离 <uid>/ 的 FUSE 层路径（readdir 条目 ino 与
                              getattr 同源解析用，见 vfs_readdir_entry_ino） */
    const char* sub_path;  /* 剥离 <uid>/ 后的虚拟路径 */
    const char* real_path; /* 本地真实目录（opendir/lstat 用） */
    const char* current_pkg;
    void* buf;
    fuse_fill_dir_t filler;
    DirHashTable ht; /* 条目去重表 */
    uint64_t emit_next; /* 下一条目的 off（从 1 起） */
    uint64_t emit_skip; /* 仍需跳过的已发条目数（= 入参 offset） */
    bool is_root;    /* sub_path 为挂载点根 */
    bool is_android_dir;
    bool media_skel; /* /Android/media 这一条由框架合成：仅整树镜像口径 */
    bool hide_others; /* 跨应用隔离生效（沙盒开启 + 非 root/未知访问者） */
    int path_user_id; /* 路由解析出的 user_id（<0 = 无用户层）；可见性单点用 */
    bool has_data, has_obb, has_media, has_android, has_pkg;
} VfsReaddirCtx;

/* 本地路径发射 choke 点：编号 → 跳过（断点续扫）→ filler。
   返回 false = 内核缓冲已满，调用方短路结束。 */
static bool vfs_emit(VfsReaddirCtx* d, const char* name, const struct stat* st) {
    uint64_t off = d->emit_next++;
    if (off <= d->emit_skip) return true;
    return d->filler(d->buf, name, st, (off_t)off, 0) == 0;
}

/* 后端路径发射（VfsReaddirCtx 外的轻量版：同编号/跳过语义）。
   返回 1=跳过（已发过），0=已发射，-1=内核缓冲已满。 */
static int vfs_emit_raw(void* buf, fuse_fill_dir_t filler, uint64_t* next, uint64_t skip,
                        const char* name, const struct stat* st) {
    uint64_t off = (*next)++;
    if (off <= skip) return 1;
    return filler(buf, name, st, (off_t)off, 0) != 0 ? -1 : 0;
}

/* 上报后端错误/崩溃前先交还本次调用的在途引用：置毒（module_guard_fault 与
   达阈值的 module_guard_error）要等该槽位在途引用归零才 dlclose，而当前线程
   若仍攥着自己这份引用等待归零，必然 2s 超时 → 跳过 dlclose，模块映射与自有
   线程永不回收。置空 *ops 后调用方随后的 module_backend_put 是空操作。
   其余回调（getattr/open/create/mkdir/unlink/rmdir/read/write/release/flush/
   rename/truncate）都在上报前先 put/release_slot，只有 readdir 因多分支早退
   需要这个显式交还。 */
static void backend_put_before_guard(const NspModuleOps** ops) {
    if (!ops) return;
    module_backend_put(*ops);
    *ops = NULL;
}

/* readdir 后端分派：rr.is_ftp 且路径命中 BACKEND 模块时由模块方法返回条目，
   框架负责 . / .. 与 filler 输出。返回 true = 已处理（*rc_out 为 FUSE 返回码）；
   false = 未命中后端，交回本地目录路径。
   V5 分页：按 VFS_READDIR_PAGE 逐页拉取（offset 累加），直到短页/0 页/filler
   满——大目录无条数上限（V4 的 512 整批上限已删除）。VFS_READDIR_MAX_TOTAL
   是恶意后端无限产条目的 DoS 熔断（超限 E2BIG loud 报错）；正常后端
   （含 FTP 单 LIST 缓存）在短页处自然收尾，走不到该分支。 */
#define VFS_READDIR_PAGE      256
#define VFS_READDIR_MAX_TOTAL 65536
static bool vfs_readdir_backend(struct fuse_context* ctx, const char* fuse_path, const char* sub_path,
                                const char* current_pkg, int path_user_id, bool is_ftp, void* buf,
                                fuse_fill_dir_t filler, uint64_t skip, int* rc_out) {
    if (!is_ftp) return false;
    const NspModuleOps* bops = NULL;
    if (module_backend_lookup(sub_path, &bops) != 0) return false;
    if (!bops->backend_readdir) {
        /* 模块未提供 readdir 回调：释放 lookup 在途引用后走本地目录路径 */
        module_backend_put(bops);
        return false;
    }
    /* 页缓冲堆分配（FUSE 线程栈在 Android 常为 1MB，栈上放数组有风险）。
       calloc 清零防御后端未填充字段残留垃圾。 */
    NspDirEntry* entries = calloc(VFS_READDIR_PAGE, sizeof(NspDirEntry));
    if (!entries) {
        module_backend_put(bops); /* calloc 失败：释放引用再报错 */
        *rc_out = -ENOMEM;
        return true;
    }
    int bslot = module_ops_slot(bops);
    /* POSIX readdir 恒含 . / ..（与本地文件系统 readdir 路径一致）。
       点条目传 nullptr：libfuse fill_dir 遇空 stat 即填 FUSE_UNKNOWN_INO，
       内核视其为未知、后续按名 lookup 取 getattr 的真实 ino。此处若传
       memset 全 0 的 stat（含 st_ino=0），0 会随 use_ino=1 原样进内核，
       与后端 getattr 侧的 synthetic 兜底语义矛盾（见 vfs_readdir_fill_dots
       同一写法）。编号 1/2（断点续扫 skip 覆盖点条目）。 */
    uint64_t next = 1;
    /* A16：rc/offset/total 的声明必须在首个 goto done **之前**——旧实现把
       `int rc = 0;` 放在两处 goto 之后，filler 对 . / .. 满缓冲时跳转越过
       初始化，done: 处 `*rc_out = rc` 读未初始化对象（C11 6.2.4p6），该值
       直接成为 vfs_readdir 返回码，为正数时 libfuse 错误语义失真。 */
    uint64_t offset = 0;
    size_t total = 0;
    int rc = 0;
    if (vfs_emit_raw(buf, filler, &next, skip, ".", nullptr) < 0) goto done;
    if (vfs_emit_raw(buf, filler, &next, skip, "..", nullptr) < 0) goto done;
    /* 后端分页起点对齐 skip（点条目占 off 1/2，后端条目从 off 3 起）：
       大 offset 续扫时免空翻前面页——编号连续性由 next += offset 保持
       （跳过的条目仍占号，跨调用序列稳定）。 */
    offset = (skip > 2) ? skip - 2 : 0;
    next += offset;
    for (;;) {
        int n = nsp_fence_backend_readdir(bslot, "backend_readdir", bops->backend_readdir,
                                          sub_path, entries, VFS_READDIR_PAGE, offset);
        if (n == NSP_FENCE_FAULT) {
            backend_put_before_guard(&bops);
            module_guard_fault(bslot, "backend_readdir", sub_path);
            rc = -EIO;
            break;
        }
        if (n == NSP_FENCE_BADFN) {
            rc = -EIO;
            break;
        }
        if (n < 0) {
            if (!backend_rc_is_business(n)) {
                backend_put_before_guard(&bops);
                module_guard_error(bslot, "backend_readdir", n, sub_path, "readdir 返回异常");
            }
            rc = n;
            break;
        }
        if (n == 0) break; /* 到末尾 */
        if (n > VFS_READDIR_PAGE) {
            backend_put_before_guard(&bops);
            module_guard_error(bslot, "backend_readdir", 0, sub_path, "返回条目数超限(越界写)");
            rc = -EIO;
            break;
        }        for (int i = 0; i < n; i++) {
            /* 条目名跨 ABI 由模块填写：未终止的名字会被 filler 当野指针读，
               故逐条校验（超长名由后端整条跳过，框架侧只防未终止） */
            if (!nsp_guard_dir_entry_ok(&entries[i])) {
                backend_put_before_guard(&bops);
                module_guard_error(bslot, "backend_readdir", 0, sub_path,
                                   "条目名未终止(越界写)");
                rc = -EIO;
                goto done;
            }
            struct stat st;
            memset(&st, 0, sizeof st);
            st.st_mode = entries[i].is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644);
            /* d_ino 必须非 0（use_ino=1 下直接进内核）且与该路径 getattr 一致：
               经 vfs_readdir_child_ino 派生，与 getattr 的 synthetic_inode 同源 */
            st.st_ino = vfs_readdir_child_ino(sub_path, entries[i].name);
            /* 可见性单点（A4）：后端条目与本地条目同一过滤语义。此前该路径
               **零过滤** → HIDE/重定向目标条目在列举里可见而 stat ENOENT，
               既违反 architecture.md §4.4 又构成名字泄露。
               被过滤条目**仍消耗一个编号**（next++），使「后端 raw offset ==
               发射编号 - 3」恒成立，分页 resume 才能按 raw offset 直接续扫；
               若过滤条目不占号，resume 会漏项/重复。 */
            char vis_sub[2048], vis_fuse[2048];
            if (vfs_entry_visibility(sub_path, fuse_path, entries[i].name, current_pkg,
                                     path_user_id, ctx ? ctx->uid : 0, vis_sub, sizeof vis_sub,
                                     vis_fuse, sizeof vis_fuse) != NSP_VIS_EMIT) {
                next++;
                continue;
            }
            int er = vfs_emit_raw(buf, filler, &next, skip, entries[i].name, &st);
            if (er < 0) goto done; /* 内核缓冲满 */
        }
        total += (size_t)n;
        if (n < VFS_READDIR_PAGE) break; /* 短页 = 末尾 */
        if (total > VFS_READDIR_MAX_TOTAL) {
            /* 后端持续满页（正常应在短页/0 页收尾）：疑似无限产条目，熔断收尾。
               用 > 而非 >=：恰好 64K 条是合法目录（下一页短页/0 页自然收尾）；
               与 FTP 侧 FTP_LIST_CACHE_MAX=65537 的 +1 哨兵对齐（>64K 才熔断）。
               属框架侧防御（非常规业务失败），计错误后 loud 报错 */
            backend_put_before_guard(&bops);
            module_guard_error(bslot, "backend_readdir", 0, sub_path, "条目数超限(疑似无限产出)");
            rc = -E2BIG;
            break;
        }
        offset += (uint64_t)n;
    }
done:
    module_backend_put(bops);
    free(entries);
    *rc_out = rc;
    return true;
}

static void vfs_readdir_ctx_init(VfsReaddirCtx* d, struct fuse_context* ctx, const char* fuse_path,
                                 const char* sub_path, const char* real_path, const char* current_pkg,
                                 int path_user_id, void* buf, fuse_fill_dir_t filler) {
    d->ctx = ctx;
    d->fuse_path = fuse_path;
    d->sub_path = sub_path;
    d->real_path = real_path;
    d->current_pkg = current_pkg;
    d->path_user_id = path_user_id;
    d->buf = buf;
    d->filler = filler;
    vfs_hash_init(&d->ht);
    d->is_root = (strcmp(sub_path, "/") == 0 || sub_path[0] == '\0');
    /* 根据 g_disable_sandbox 强制跳过沙盒屏蔽逻辑；无用户层（user_id<0）同理 */
    bool skip_sandbox = (path_user_id < 0) || g_disable_sandbox;
    /* 骨架补齐不能依赖用户层是否剥离：无用户层的挂载上同样要补 data/obb */
    d->is_android_dir = (!skip_sandbox && sub_path_is_storage_android_dir(sub_path));
    /* 沙盒里的 /Android 取自镜像，镜像里没有真实的 media 目录——那一条由框架补；
       未开沙盒时 /Android 就是真实目录，媒体目录本来就在，列举自然带上（补一条也
       只是与 data/obb 同一套骨架口径）。 */
    d->media_skel = (!skip_sandbox && sub_path_is_storage_android_dir(sub_path));
    d->hide_others = (!skip_sandbox && current_pkg[0] && strcmp(current_pkg, "system") != 0 &&
                      strcmp(current_pkg, "unknown") != 0);
    d->has_data = d->has_obb = d->has_media = d->has_android = d->has_pkg = false;
}

/* 合成/虚拟条目 d_ino 与 getattr 同源解析（inode 同源不变量：目录项 d_ino
   == getattr st_ino）。vfs_readdir_child_ino 的纯 synthetic 只在「真实路径
   不存在」时与 getattr 一致；重定向虚拟目录（如 /网盘 → /Download）的
   getattr 直接 lstat 解析后的真实目标并报告真实 ino，故此处逐条目镜像
   getattr 的本地分派：fw_route 解析子项 → lstat 真实路径，命中即真实 ino；
   失败（虚拟目录无底层文件）才落 synthetic 全路径哈希（与 getattr 虚拟
   分支的 synthetic_inode(sub_path) 同源）。后端路径（FTP 前缀等）不逐条
   发起网络查询：FTP 的 backend_getattr 只填 mode/size/mtime（ino=0 →
   框架 synthetic 兜底），直接 synthetic 即与 getattr 一致；模块未提供
   backend_getattr 时同 getattr 一样落到本地 lstat。 */
static ino_t vfs_readdir_entry_ino(VfsReaddirCtx* d, const char* name) {
    char child_sub[PATH_MAX], child_fuse[PATH_MAX];
    /* 子项 sub_path 拼接走 readdir_join（文件内唯一出口），根（"" 或 "/"）
       传空 base 得 "/name"——与 scan_local 的 is_root 分支同语义。
       base 先剥尾部 '/'（长度>1）：非规范 sub_path（如 "/Android/data/"）
       会拼出 "//name"，与 getattr 规范形式的哈希不一致 */
    char sub_base[PATH_MAX], fuse_base[PATH_MAX];
    readdir_base_normalize(sub_base, sizeof sub_base, d->sub_path);
    readdir_base_normalize(fuse_base, sizeof fuse_base, d->fuse_path);
    readdir_join(child_sub, sizeof child_sub, sub_base, name);
    readdir_join(child_fuse, sizeof child_fuse, fuse_base, name);
    NspPathDecision rr;
    bool nsp_ok = false, is_redir = false, monitor_on = false;
    char current_pkg[128], sub[PATH_MAX], p[PATH_MAX];
    int path_user_id = -1;
    /* 逐条目路由：这里只做读类判定（整体列举权限已由 readdir/opendir 把关） */
    if (fw_route(d->ctx, child_fuse, &rr, &nsp_ok, current_pkg, &path_user_id, sub, p,
                 &is_redir, &monitor_on, VFS_OP_READ, NSP_ACL_OP_GENERIC_READ, false, 0) == 0) {
        if (rr.is_ftp) {
            const NspModuleOps* bops = NULL;
            if (module_backend_lookup(sub, &bops) == 0) {
                bool has_getattr = (bops->backend_getattr != NULL);
                module_backend_put(bops);
                /* 后端接管 getattr 且它普遍回 ino=0（框架 synthetic 兜底）：
                   与 vfs_getattr 第 570 行同一算法，用规范 sub 同源 */
                if (has_getattr) return synthetic_inode(sub);
            }
        }
        struct stat st;
        if (lstat(p, &st) == 0 && st.st_ino != 0) return st.st_ino;
        /* lstat 失败：同 getattr 虚拟分支（合成/祖先/目标目录），用 fw_route
           归一后的规范 sub_path 入哈希 */
        return synthetic_inode(sub);
    }
    return synthetic_inode(child_sub);
}

/* 合成条目的 stat 兜底：类型位由调用方给定，时间戳/属主/链接数尽量取真实值
   ——先试同名真实子项，取不到再继承父目录。合成条目若只填 ino/mode，客户端
   拿到的 mtime 是 0（显示成 1970-01-01）、size 是 0，目录还容易被画成文件。 */
static void vfs_synth_stat(VfsReaddirCtx* d, const char* name, mode_t type_mode, struct stat* st) {
    char child[2048];
    struct stat real;
    const struct stat* real_child = nullptr;
    if (readdir_join_checked(child, sizeof child, d->real_path, name) == 0 && lstat(child, &real) == 0)
        real_child = &real;
    /* 直接父目录也缺失时（重定向落点不存在的多级合成链）继续上溯到最近存在的
       祖先：属性来源全空会让时间戳留 0，客户端把条目画成 1970-01-01 */
    struct stat parent;
    const struct stat* parent_stat = nullptr;
    if (lstat(d->real_path, &parent) == 0 || nsp_stat_nearest_ancestor(d->real_path, &parent))
        parent_stat = &parent;
    nsp_synth_stat_fill(st, vfs_readdir_entry_ino(d, name), type_mode, real_child, parent_stat);
}

/* 合成目录条目输出（经 ht 去重）。返回 false = filler 缓冲已满，须立即结束 */
static bool vfs_readdir_emit_dedup(VfsReaddirCtx* d, const char* name) {
    if (!vfs_hash_insert(&d->ht, name)) return true; /* 已存在：跳过 */
    struct stat st;
    vfs_synth_stat(d, name, S_IFDIR | 0755, &st);
    return vfs_emit(d, name, &st);
}

/* 合成目录条目输出（不因 ht 已有同名条目而跳过）：data/obb 骨架沿用原语义——
   物理扫描未出现即补。发射后把名字登记进 ht，否则同一名字又被后续虚拟前缀
   （如 REDIRECT 到 /Android/data 的虚拟条目）走 emit_dedup 再发一次，
   内核侧会看到同名条目出现两遍。返回 false = filler 缓冲已满 */
static bool vfs_readdir_emit_raw(VfsReaddirCtx* d, const char* name) {
    struct stat st;
    vfs_synth_stat(d, name, S_IFDIR | 0755, &st);
    bool ok = vfs_emit(d, name, &st);
    if (ok) (void)vfs_hash_insert(&d->ht, name);
    return ok;
}

/* 本地目录扫描：probe 条目级过滤（hidden/redirect_target）+ ht 去重 +
   lstat + filler，并记录 Android/data/obb/自身包名骨架项是否已出现。
   dp 由调用方打开并负责关闭。返回 false = filler 缓冲已满，须立即结束。 */
static bool vfs_readdir_scan_local(VfsReaddirCtx* d, DIR* dp) {
    char item_sub_path[2048], item_fuse_path[2048], item_real_path[2048];
    struct dirent* de;
    while ((de = readdir(dp)) != nullptr) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        /* 可见性判定走框架单点（C2）：路径归一/过长 fail-closed/uid 目录豁免/
           hidden+redirect_target 探测/Android/data|obb 自身包名，三条列举路径
           共用同一份语义，杜绝再次漂移 */
        if (vfs_entry_visibility(d->sub_path, d->fuse_path, de->d_name, d->current_pkg,
                                 d->path_user_id, d->ctx->uid, item_sub_path, sizeof item_sub_path,
                                 item_fuse_path, sizeof item_fuse_path) != NSP_VIS_EMIT)
            continue;
        /* 骨架名判定（与后继 fill_* 合成条件同源）：lstat 失败时不上架 NULL 条目、
           也不置 has_* 标记，交由 fill 阶段合成标准目录条目（S_IFDIR|0755 + 同源
           ino）。否则 DT_UNKNOWN 条目会让管理器显示为文件且无法点击，而按名
           stat（getattr 虚拟分支）又是目录——线上实例：lower 层 EACCES 致 lstat
           失败时 has_* 已预置，fill 合成被跳过，列表里只剩无类型条目。 */
        /* 骨架名判定与访问者身份、用户层无关：root（hide_others=false）与无用户层
           挂载同样命中，否则这几条路径正好退化成无类型条目。 */
        bool skel = (d->is_root && strcmp(de->d_name, "Android") == 0) ||
                    ((strcmp(de->d_name, "data") == 0 || strcmp(de->d_name, "obb") == 0) &&
                     (d->is_android_dir || sub_path_is_storage_android_dir(d->sub_path))) ||
                    (d->media_skel && strcmp(de->d_name, "media") == 0) ||
                    (d->hide_others && strcmp(de->d_name, d->current_pkg) == 0 &&
                     sub_path_is_android_container(d->sub_path));
        struct stat st;
        memset(&st, 0, sizeof(st));
        readdir_join(item_real_path, 2047, d->real_path, de->d_name);
        /* 真实路径拼接必须可容纳检查：base 已接近缓冲区上限时，截断路径会命中
           目录自身（lstat 成功、拿到父目录的 S_IFDIR），整个目录的条目就被画成
           文件夹。放不下时按 d_type 合成，与 lstat 失败同一条路径。 */
        bool joined = readdir_join_checked(item_real_path, sizeof item_real_path, d->real_path, de->d_name) == 0;
        if (!joined || lstat(item_real_path, &st) != 0) {
            if (skel) {
                /* 骨架名：lstat 失败也按目录上架（getattr 对同一路径有骨架兜底，
                   两侧口径必须一致），并置 has_* 免得 fill 阶段重复补一条 */
                if (d->is_root && strcmp(de->d_name, "Android") == 0)
                    d->has_android = true;
                else if (strcmp(de->d_name, "data") == 0)
                    d->has_data = true;
                else if (strcmp(de->d_name, "obb") == 0)
                    d->has_obb = true;
                else if (strcmp(de->d_name, "media") == 0)
                    d->has_media = true;
                else
                    d->has_pkg = true;
                if (!vfs_readdir_emit_dedup(d, de->d_name)) return false;
                continue;
            }
            /* 非骨架条目：lstat 失败（下层 EACCES/ENOENT）时按 getdents 给出的
               d_type 合成条目——无类型条目会让管理器显示为文件且无法点击，而按名
               getattr 却可能是真实类型。d_type 也是 DT_UNKNOWN 时才退回 NULL。 */
            if (de->d_type == DT_DIR || de->d_type == DT_REG || de->d_type == DT_LNK) {
                struct stat dst;
                vfs_synth_stat(d, de->d_name,
                               (de->d_type == DT_DIR)   ? (S_IFDIR | 0755)
                               : (de->d_type == DT_LNK) ? (S_IFLNK | 0777)
                                                        : (S_IFREG | 0644),
                               &dst);
                if (vfs_hash_insert(&d->ht, de->d_name)) {
                    if (!vfs_emit(d, de->d_name, &dst)) return false;
                }
                continue;
            }
            if (vfs_hash_insert(&d->ht, de->d_name)) {
                if (!vfs_emit(d, de->d_name, nullptr)) return false;
            }
            continue;
        }
        if (d->is_root && strcmp(de->d_name, "Android") == 0) d->has_android = true;
        if (d->is_android_dir || sub_path_is_storage_android_dir(d->sub_path)) {
            if (strcmp(de->d_name, "data") == 0)
                d->has_data = true;
            else if (strcmp(de->d_name, "obb") == 0)
                d->has_obb = true;
            else if (strcmp(de->d_name, "media") == 0)
                d->has_media = true; /* 镜像里真有这一条时不再补 */
        }
        if (d->hide_others && strcmp(de->d_name, d->current_pkg) == 0 &&
            sub_path_is_android_container(d->sub_path))
            d->has_pkg = true;
        if (vfs_hash_insert(&d->ht, de->d_name)) {
            if (!vfs_emit(d, de->d_name, &st)) return false;
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

/* /Android 下 data/obb 骨架补齐（无用户层/沙盒关闭时不合成）。
   整树镜像口径另补 media：镜像里的 /Android 只有应用自己建过的条目，三个容器
   中只有它没有对应真实目录，缺了这一条应用就少看一个容器（容器本身按真实目录
   让位，故 stat 由 getattr 的骨架兜底同口径给结果）。 */
static bool vfs_readdir_fill_android_children(VfsReaddirCtx* d) {
    if (!d->is_android_dir) return true;
    if (!d->has_data && !vfs_readdir_emit_raw(d, "data")) return false;
    if (!d->has_obb && !vfs_readdir_emit_raw(d, "obb")) return false;
    if (d->media_skel && !d->has_media && !vfs_readdir_emit_raw(d, "media")) return false;
    return true;
}

/* /Android/data|obb 下访问者自身包名骨架补齐（跨应用隔离下仅见自身） */
static bool vfs_readdir_fill_own_pkg(VfsReaddirCtx* d) {
    if (!(d->hide_others && !d->has_pkg && sub_path_is_android_container(d->sub_path))) return true;
    bool ok = vfs_readdir_emit_dedup(d, d->current_pkg);
    /* 发出去了才登记：getattr/access/opendir 的 own_pkg 兜底只认「这一条真的
       被列举过」，直接 stat 一个从未列举的路径仍按真实结果失败 */
    if (ok) nsp_listed_mark_own_pkg(d->ctx->uid, d->sub_path, d->current_pkg);
    return ok;
}

/* 虚拟目录补充：模块 readdir_extra 返回条目数组，框架 ht 去重 + filler。
   条目只给 st_ino 与目录类型位——fuse_add_direntry 不读 uid/gid 与权限位，
   属主/权限由 getattr 决定（虚拟路径无底层文件，getattr 侧继承用户存储根）。
   缓冲动态翻倍（初容 128，上限 VIRT_MAX）：虚拟前缀数随模块数增长，
   V4 的栈上 MAX_MODULES*8=128 固定上限会静默丢虚拟条目。堆分配亦避开
   FUSE 线程栈压力。超上限（8192 同目录虚拟前缀， absurd）则 loud 告警
   后截断——真实文件条目不受影响（本函数只产虚拟合成条目）。 */
#define VIRT_INIT_CAP 128
#define VIRT_MAX      8192
static bool vfs_readdir_fill_virtual(VfsReaddirCtx* d, int path_user_id) {
    size_t cap = VIRT_INIT_CAP;
    NspDirEntry* virt = malloc(cap * sizeof *virt);
    if (!virt) return true; /* OOM：跳过虚拟补充（目录仍可用，不报错） */
    int vn = 0;
    for (;;) {
        NspQueryCtx vq = {.uid = d->ctx->uid,
                          .pid = d->ctx->pid,
                          .gid = d->ctx->gid,
                          .path = d->sub_path};
        vn = fw_rules_readdir_extra(&vq, d->sub_path, path_user_id, d->current_pkg, d->is_root,
                                    virt, (int)cap);
        if (vn < 0) vn = 0;
        /* 满容 = 可能还有：翻倍重取（readdir_extra 为纯内存计算，重调廉价） */
        if ((size_t)vn < cap || cap >= VIRT_MAX) break;
        size_t ncap = cap * 2;
        if (ncap > VIRT_MAX) ncap = VIRT_MAX;
        NspDirEntry* grown = realloc(virt, ncap * sizeof *grown);
        if (!grown) break; /* OOM：用已有容量结果（短页收尾，不静默丢已取） */
        virt = grown;
        cap = ncap;
    }
    if ((size_t)vn >= cap && cap >= VIRT_MAX)
        LOG_WRN("虚拟目录条目超上限(%d)，超出部分跳过", VIRT_MAX);
    /* 纵深防御：钳制 vn 防越界读 */
    if (vn < 0) vn = 0;
    if ((size_t)vn > cap) vn = (int)cap;
    bool ok = true;
    for (int vi = 0; vi < vn; vi++) {
        if (virt[vi].name[0] == '\0') continue;
        if (!vfs_hash_insert(&d->ht, virt[vi].name)) continue;
        struct stat st_dir;
        /* 类型位必须带 S_IFDIR | 权限位：权限全 0 的目录条目在部分管理器里
           会被画成不可进入的条目；时间戳同样取真实值而非 0 */
        vfs_synth_stat(d, virt[vi].name, S_IFDIR | 0755, &st_dir);
        if (!vfs_emit(d, virt[vi].name, &st_dir)) {
            ok = false; /* 内核缓冲满：短路后继阶段（与旧语义一致） */
            break;
        }
    }
    free(virt);
    return ok;
}

/* POSIX readdir 收尾：恒含 . / ..（与本地文件系统 readdir 路径一致） */
static bool vfs_readdir_fill_dots(VfsReaddirCtx* d) {
    if (!vfs_emit(d, ".", nullptr)) return false;
    if (!vfs_emit(d, "..", nullptr)) return false;
    return true;
}

static int vfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset,
                       struct fuse_file_info* fi, enum fuse_readdir_flags flags) {
    vfs_flush_pending_closes();
    (void)flags;
    (void)fi;
    VFS_SETUP_CORE_OP(path, VFS_OP_READ, NSP_ACL_OP_READDIR);
    vfs_log_io(current_pkg, ctx->uid, "READDIR", sub_path,
               (nsp_ok && is_redir) ? rr.real_path : NULL, monitor_on);
    LOG_DBG_PERF("[READDIR_ENTRY] path=%s real=%s", path, p);

    /* 断点续扫：内核 offset = 上次收到的条目 off（vfs_emit 编号），本轮跳过
       已发条目后继续。offset<=0 视为从头（内核首扫传 0）。 */
    uint64_t skip = (offset > 0) ? (uint64_t)offset : 0;

    /* 后端分派：readdir 由模块方法返回条目，框架负责 filler */
    int brc = 0;
    if (vfs_readdir_backend(ctx, path, sub_path, current_pkg, path_user_id, rr.is_ftp, buf, filler,
                            skip, &brc))
        VFS_RETURN(brc);

    VfsReaddirCtx d;
    vfs_readdir_ctx_init(&d, ctx, path, sub_path, p, current_pkg, path_user_id, buf, filler);
    d.emit_next = 1;
    d.emit_skip = skip;
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
    /* 物理扫描已发出自身包名条目（真实目录存在，或其 lstat 失败按骨架名上架）：
       同样算「列举过」，按名 getattr 必须与列表口径一致 */
    if (d.has_pkg && sub_path_is_android_container(d.sub_path))
        nsp_listed_mark_own_pkg(d.ctx->uid, d.sub_path, d.current_pkg);
    vfs_hash_free(&d.ht);
    VFS_RETURN(0);
}

static int vfs_open(const char* path, struct fuse_file_info* fi) {
    FTP_DBG("vfs_open: 入口 path=%s\n", path);
    vfs_flush_pending_closes();
    /* 写意图由 flags 决定（O_RDONLY 打开 RO 路径必须放行）；ACL 只看写/读这一维 */
    const NspAclOp acl_open_op = (fi->flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC))
                                     ? NSP_ACL_OP_WRITE_OPEN
                                     : NSP_ACL_OP_GENERIC_READ;
    VFS_SETUP_CORE_OP(path, VFS_OP_READ, acl_open_op);
    vfs_log_io(current_pkg, ctx->uid, "OPEN", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL,
               monitor_on);
    if (g_strip_o_direct && (fi->flags & O_DIRECT)) fi->flags &= ~O_DIRECT;
    /* open 归类 VFS_OP_READ（O_RDONLY 打开 RO 路径必须放行），只在 flags 表明
       要写时才按变更语义处理：
         - 只读策略走 vfs_check_read_only 单点；
         - 存储根守卫也要按 MUTATE 再走一次：否则对**已存在的**存储根一级条目
           （如线上 /data/media 顶层那个 root:root 垃圾文件）可被 open(O_WRONLY/
           O_TRUNC/O_APPEND) 以 root 身份截断/改写——守卫不能只看路由的 op。 */
    {
        int accmode = fi->flags & O_ACCMODE;
        if (accmode == O_WRONLY || accmode == O_RDWR || (fi->flags & O_CREAT) ||
            (fi->flags & O_TRUNC) || (fi->flags & O_APPEND)) {
            int ro_rc = vfs_check_read_only(&rr, ctx->uid);
            if (ro_rc != 0) {
                log_fuse_err("OPEN_RO_DENIED", path, -ro_rc);
                VFS_RETURN(ro_rc);
            }
            int srg_rc = vfs_storage_root_guard(ctx, path, current_pkg, path_user_id, p,
                                                VFS_OP_MUTATE);
            if (srg_rc != 0) VFS_RETURN(srg_rc);
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
            int drc;
            if (backend_dispatch_after(bslot, "backend_open", brc, sub_path, "open 返回异常", &drc))
                VFS_RETURN(drc);
            /* FTP 路径：句柄为模块小整数 ID（非 fd），不设 FD 透传等本地
               文件系统才可用的优化（passthrough 仅对下方本地 open 的 fd）；
               设 direct_io 绕过内核 page cache——FUSE 内核在 close 后可能
               失效 page cache，但 dentry 缓存仍命中第二次 open 导致 read
               返回空（复用缓存的 fh 但 page cache 已空）。
               fh 高位编码模块槽位：read/write/flush/release/fsync 经
               module_backend_acquire_slot 无锁快速分派，免每 IO 路径解析
               与线性扫描（模块卸载时快照置空→快速失败，不悬垂） */
            fi->fh =
                h | NSP_FH_BACKEND_FLAG | ((uint64_t)(bslot & (NSP_FH_BACKEND_SLOT_MAX - 1)) << NSP_FH_BACKEND_SLOT_SHIFT);
            if ((fi->flags & O_ACCMODE) != O_RDONLY) fi->fh |= NSP_FH_WRITE_INTENT_FLAG;
            fi->direct_io = 1;
            FTP_DBG("vfs_open: 后端命中 sub=%s fh=%llu slot=%d flags=%o direct_io=1\n", sub_path,
                    (unsigned long long)fi->fh, bslot, fi->flags);
            VFS_RETURN(0);
        }
    }
    /* open 不创建文件（O_CREAT 由 create 回调处理），mode 参数无意义；旧实现在
       is_redir 时传 0666，只会在 O_CREAT 意外出现时替调用方决定权限。 */
    int fd = open(p, fi->flags | O_CLOEXEC, 0);
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
    VFS_SETUP_CORE_OP(path, VFS_OP_MUTATE, NSP_ACL_OP_CREATE);
    vfs_log_io(current_pkg, ctx->uid, "CREATE", sub_path,
               (nsp_ok && is_redir) ? rr.real_path : NULL, monitor_on);
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
            int drc;
            if (backend_dispatch_after(bslot, "backend_create", brc, sub_path, "create 返回异常",
                                       &drc))
                VFS_RETURN(drc);
            fi->fh =
                h | NSP_FH_BACKEND_FLAG | ((uint64_t)(bslot & (NSP_FH_BACKEND_SLOT_MAX - 1)) << NSP_FH_BACKEND_SLOT_SHIFT);
            if ((fi->flags & O_ACCMODE) != O_RDONLY) fi->fh |= NSP_FH_WRITE_INTENT_FLAG;
            VFS_RETURN(0);
        }
    }
    /* 创建 mode 一律用调用方的：ALLOW 命中与 SANDBOX 重定向下 is_redir 恒为真，
       旧实现据此固定 0666，等于把调用方 mode（内核已按 umask 归一）整个丢掉，
       umask 与应用指定的 0600 在 create 路径上永远不生效。 */
    int fd = open(p, fi->flags | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd == -1) {
        if (errno == ENOENT) {
            char *p_dup = strdup(p), *p_dir = dirname(p_dup);
            /* 父目录补建走守卫出口：永不创建存储根一级条目（见 common.h） */
            if (common_mkdir_within_storage(p_dir, 0775) == 0)
                fd = open(p, fi->flags | O_CREAT | O_EXCL | O_CLOEXEC, mode);
            free(p_dup);
        }
        if (fd == -1) {
            int err = errno;
            log_fuse_err("CREATE", path, err);
            if (err != EEXIST) vfs_log_io_err(current_pkg, "CREATE", sub_path, "errno=%d", err);
            VFS_RETURN(-err);
        }
    }
    nsp_new_entry_attrs(p, mode);
    fi->fh = fd;
    /* 事件通道埋点：create 已落盘（后端分支在上面提前返回，不外发——rpath 无意义） */
    if (fw_events_active())
        fw_events_note_write_done(ctx->uid, ctx->pid, path, FW_EV_OP_CREATE, NULL);
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
    VFS_SETUP_CORE_OP(path, VFS_OP_MUTATE, NSP_ACL_OP_MKDIR);
    vfs_log_io(current_pkg, ctx->uid, "MKDIR", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL,
               monitor_on);
    /* 后端分派：mkdir 由模块方法创建（rr.is_ftp 短路，避免非 FTP 路径付出
       无条件 rwlock + backend_match 扫描） */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0 && bops && bops->backend_mkdir) {
        int bslot = module_ops_slot(bops);
        int brc =
            nsp_fence_backend_mkdir(bslot, "backend_mkdir", bops->backend_mkdir, sub_path, mode);
        module_backend_put(bops);
        int drc;
        if (backend_dispatch_after(bslot, "backend_mkdir", brc, sub_path, "mkdir 返回异常", &drc))
            VFS_RETURN(drc);
        VFS_RETURN(0);
    }
    /* fallback：lookup 成功但未走后端分支时释放引用，防止 backend_refs 泄漏
       导致模块无法热卸载（loader 等待 backend_refs == 0） */
    if (bops) module_backend_put(bops);
    /* 同 create：is_redir 时固定 0775 会把内核按 umask 归一过的 mode 丢掉
       （父目录补建另有自己的 mode，见 common_mkdir_within_storage）。 */
    int ret = mkdir(p, mode);
    if (ret == -1) {
        if (errno == ENOENT) {
            char *p_dup = strdup(p), *parent = dirname(p_dup);
            /* 父目录补建走守卫出口：永不创建存储根一级条目（见 common.h） */
            if (common_mkdir_within_storage(parent, 0775) == 0)
                ret = mkdir(p, mode);
            free(p_dup);
        }
        if (ret == -1) {
            int err = errno;
            log_fuse_err("MKDIR", path, err);
            if (err != EEXIST) vfs_log_io_err(current_pkg, "MKDIR", sub_path, "errno=%d", err);
            VFS_RETURN(-err);
        }
    }
    nsp_new_entry_attrs(p, mode);
    if (fw_events_active()) fw_events_note_write_done(ctx->uid, ctx->pid, path, FW_EV_OP_MKDIR, NULL);
    VFS_RETURN(0);
}

static int vfs_unlink(const char* path) {
    VFS_SETUP_CORE_OP(path, VFS_OP_MUTATE, NSP_ACL_OP_DELETE);
    vfs_log_io(current_pkg, ctx->uid, "UNLINK", sub_path,
               (nsp_ok && is_redir) ? rr.real_path : NULL, monitor_on);
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
            int drc;
            if (backend_dispatch_after(bslot, "backend_unlink", brc, sub_path, "unlink 返回异常",
                                       &drc))
                VFS_RETURN(drc);
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
    VFS_SETUP_CORE_OP(path, VFS_OP_MUTATE, NSP_ACL_OP_RMDIR);
    vfs_log_io(current_pkg, ctx->uid, "RMDIR", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL,
               monitor_on);
    if (rr.virtual_kind == NSP_VK_ANCESTOR || rr.virtual_kind == NSP_VK_TARGET) {
        if (!fw_virtual_dir_empty(path, sub_path, p, current_pkg, path_user_id, ctx->uid)) {
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
            int drc;
            if (backend_dispatch_after(bslot, "backend_rmdir", brc, sub_path, "rmdir 返回异常",
                                       &drc))
                VFS_RETURN(drc);
            VFS_RETURN(0);
        }
    }
    int ret = rmdir(p);
    if (ret == -1) {
        int err = errno;
        /* 非空目录一律返回 ENOTEMPTY（POSIX），与上面的虚拟路径分支语义一致。
           此前对 ENOTEMPTY 递归删除整个子树，等于「rmdir 静默变成 rm -r」——
           依赖 rmdir 失败的调用方（rmdir(1)、清理逻辑、探测空目录）会误以为
           目录已空并连带丢失全部内容。真正的递归删除只应出现在显式要求它的
           路径上（跨设备 rename 的 EXDEV 回退）。 */
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
                if (rc == 0) {
                    /* 契约：got 不得超过请求的 size——libfuse 只为本次读备了 size
                       字节缓冲，回传超长会被当有效数据取走（堆越界读）；且须落在
                       int 正值域：FUSE read 回包长度是 int，got > INT_MAX 经 (int)
                       变负会被上层当 -errno。与 readdir 的「条目数超限」同源防御。 */
                    if (got > size || got > (size_t)INT_MAX) {
                        module_guard_error(slot, "backend_read", 0, path,
                                           "回传长度超过请求(越界读)");
                        return -EIO;
                    }
                    return (int)got;
                }
                return rc < 0 ? rc : -EIO;
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
                if (rc == 0) {
                    /* 契约：wrote 不得超过请求的 size——回报「写入量大于请求量」会
                       让 libfuse/内核认为多写了字节（调用方据此推进文件偏移）；且须
                       落在 int 正值域（FUSE write 回包长度是 int）。 */
                    if (wrote > size || wrote > (size_t)INT_MAX) {
                        module_guard_error(slot, "backend_write", 0, path,
                                           "回传写入量超过请求(越界写)");
                        return -EIO;
                    }
                    return (int)wrote;
                }
                return rc < 0 ? rc : -EIO;
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
    /* 已 unlink 仍打开的本地文件：写入会改变 size/mtime，刷新属性快照，
       使随后的 fstat 拿到真实值（而不是删除瞬间的旧值）。 */
    hidden_stat_refresh(path, (int)fi->fh);
    /* 事件通道埋点：写已落盘。fuse_get_context 的 TLS 读只在开关打开时发生
       （关闭时上面那次原子读就直接返回，不添任何热路径开销）。op 用
       close_write：一次 open→多次 write→close 的序列在 200ms 合并里收敛成
       一条，扫描侧不会被逐 4KB 的写放大成事件风暴。 */
    if (fw_events_active()) {
        struct fuse_context* wctx = fuse_get_context();
        fw_events_note_write_done(wctx->uid, wctx->pid, path, FW_EV_OP_CLOSE_WRITE, NULL);
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
    /* 本地 open-unlink：最后一个句柄关闭，属性快照使命结束（名字早已删除） */
    hidden_stat_remove(path);
    close(fi->fh);
    /* 事件通道埋点：写句柄关闭（只对写意图句柄——只读打开不是"有东西落盘"）。
       与 vfs_write 的成功埋点同 op，200ms 合并后对同一文件只留一条。 */
    if (fw_events_active() && (fi->flags & O_ACCMODE) != O_RDONLY) {
        struct fuse_context* rctx = fuse_get_context();
        /* libfuse 在 release 上不保证填好调用者身份（实测 uid=pid=0）。没有身份
           就不发布：事件里的 uid/pkg 是扫描侧归因的依据，宁可少一条也不发
           "system 写了这个文件"的假事件。真正的数据变更由 vfs_write 的埋点覆盖
           （同 op=close_write，200ms 合并后仍是同一条）。 */
        if (rctx && rctx->pid != 0)
            fw_events_note_write_done(rctx->uid, rctx->pid, path, FW_EV_OP_CLOSE_WRITE, NULL);
    }
    return 0;
}

static int vfs_fsync(const char* path, int datasync, struct fuse_file_info* fi) {
    /* 后端句柄：fsync 必须真正把数据交给后端（上传收尾），否则依赖 fsync 持久化
       的调用方（SQLite synchronous=FULL、编辑器保存）会拿到「成功」而数据仍在模块
       缓冲里。语义与 FLUSH 一致：调用 backend_flush 收尾数据、不销毁句柄。 */
    if (fi->fh & NSP_FH_BACKEND_FLAG) {
        int slot = (int)((fi->fh & NSP_FH_BACKEND_SLOT_MASK) >> NSP_FH_BACKEND_SLOT_SHIFT);
        return vfs_backend_finish_data(slot, fi->fh, path,
                                       (fi->fh & NSP_FH_WRITE_INTENT_FLAG) != 0);
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

/* 后端句柄的「数据落盘」收尾：调用模块 backend_flush（数据收尾/上传，**不销毁
   句柄**），成功则失效路径缓存（否则紧随的读取会命中旧属性/旧 dentry）。
   FSYNC 与 FLUSH 共用——两者都要求「数据已落盘」，且 backend_flush 可重复调用
   （FUSE 的 FLUSH 会因 dup/fork 对同一句柄多次触发）。返回 0 或负 errno。 */
static int vfs_backend_finish_data(int slot, uint64_t fh, const char* path, bool write_intent) {
    const NspModuleOps* bops = NULL;
    /* 槽位已被置毒/卸载（快照置空）：数据从未交给后端，**不能**报成功——
       依赖 fsync 持久化的调用方（SQLite synchronous=FULL、编辑器保存）会
       误以为已落盘。与同族的 vfs_read/vfs_write 一致返回 -EIO（R10）。
       vfs_release 的宽容返回 0 保留：release 是幂等销毁、不宣称数据落盘。 */
    if (module_backend_acquire_slot(slot, &bops) != 0) return -EIO;
    int rc = 0;
    if (bops->backend_flush)
        rc = nsp_fence_backend_flush(slot, "backend_flush", bops->backend_flush,
                                     fh & NSP_FH_HANDLE_MASK);
    module_backend_release_slot(slot);
    if (rc == NSP_FENCE_FAULT) {
        module_guard_fault(slot, "backend_flush", path);
        rc = -EIO;
    } else if (rc != 0 && rc != NSP_FENCE_BADFN && !backend_rc_is_business(rc))
        module_guard_error(slot, "backend_flush", rc, path, "flush 返回异常");
    if (rc == 0) {
        struct fuse_context* ctx = fuse_get_context();
        const bool writable = write_intent && ctx && ctx->pid != 0;
        /* 写意图句柄的数据收尾 = 后端侧的文件已经"落地"（FTP 上传完成）。此刻补一条
           媒体刷新请求：后端内容不产生本地 write 事件，扫描侧没有别的时机会知道这个
           路径刚长出媒体文件。只在有活订阅者时发布（见 fw_events_note_media_refresh）。
           刷新请求必须建立在一个**本地**文件之上——扫描侧的每一跳都按本地路径工作，
           落点下没有真实文件时它只会扫到空；顺序也不能换，新文件出现后旧 dentry/
           属性要先丢掉（物化见 fw_ingest.h）。 */
        if (writable) (void)fw_ingest_materialize(slot, path, ctx->uid, ctx->pid);
        if (ctx) vfs_inval_path(ctx->fuse, path);
        if (writable) fw_events_note_media_refresh(ctx->uid, ctx->pid, path, FW_REFRESH_FTP_UPLOAD);
    }
    return rc < 0 ? rc : 0;
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
        return vfs_backend_finish_data(slot, fi->fh, path,
                                       (fi->fh & NSP_FH_WRITE_INTENT_FLAG) != 0);
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
               (nsp_ok && is_redir) ? rr.real_path : NULL, monitor_on);
    ssize_t res = readlink(p, buf, size - 1);
    if (res == -1) {
        log_fuse_err("READLINK", path, errno);
        VFS_RETURN(-errno);
    }
    buf[res] = '\0';
    VFS_RETURN(0);
}

static int vfs_opendir(const char* path, struct fuse_file_info* fi) {
    VFS_SETUP_CORE_OP(path, VFS_OP_READ, NSP_ACL_OP_OPENDIR);
    vfs_log_io(current_pkg, ctx->uid, "OPENDIR", sub_path,
               (nsp_ok && is_redir) ? rr.real_path : NULL, monitor_on);
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
        (is_android_skel_dir(sub_path) || android_media_skel(sub_path) ||
         (is_virtual_own_pkg_dir(sub_path, current_pkg) &&
          nsp_listed_own_pkg(ctx->uid, sub_path, current_pkg)) ||
         rr.virtual_kind == NSP_VK_ANCESTOR || rr.virtual_kind == NSP_VK_TARGET)) {
        VFS_RETURN(0);
    }
    log_fuse_err("OPENDIR", path, err);
    VFS_RETURN(-err);
}

static int vfs_symlink(const char* target, const char* linkpath) {
    VFS_SETUP_CORE_OP(linkpath, VFS_OP_MUTATE, NSP_ACL_OP_SYMLINK);
    vfs_log_io(current_pkg, ctx->uid, "SYMLINK", sub_path,
               (nsp_ok && is_redir) ? rr.real_path : NULL, monitor_on);
    if (symlink(target, p) == -1) {
        if (errno == ENOENT) {
            char *p_dup = strdup(p), *p_dir = dirname(p_dup);
            if (common_mkdir_within_storage(p_dir, 0775) == 0 && symlink(target, p) == 0) {
                free(p_dup);
                /* 符号链接的 mode 在内核恒为 0777，这里只做属主与 SELinux 收敛 */
                nsp_new_entry_attrs(p, 0);
                VFS_RETURN(0);
            }
            free(p_dup);
        }
        log_fuse_err("SYMLINK", linkpath, errno);
        VFS_RETURN(-errno);
    }
    nsp_new_entry_attrs(p, 0);
    VFS_RETURN(0);
}

/* 递归删除（跨设备搬移的清理/删源用）。返回码统一为 0 / -errno——旧实现
   opendir 失败回 -errno 而 unlink/rmdir 失败回 -1，调用方无法区分（§A2）。 */
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
        if (lstat(buf, &statbuf) != 0) {
            r = -errno;
            break;
        }
        if (S_ISDIR(statbuf.st_mode))
            r = recursive_rmdir(buf);
        else
            r = unlink(buf) == 0 ? 0 : -errno;
    }
    closedir(d);
    if (!r) r = rmdir(path) == 0 ? 0 : -errno;
    return r;
}

static int recursive_copy_dir(const char* src, const char* dst, uid_t uid, gid_t gid,
                              bool* created) {
    struct stat st;
    if (lstat(src, &st) != 0) return -errno;
    if (mkdir(dst, st.st_mode & 07777) != 0) return -errno;
    if (created) *created = true; /* dst 是本次创建的：失败清理只许碰它 */
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
        /* lstat 失败必须报错：旧实现静默跳过该条目仍返回成功，随后调用方
           删掉源树 → 条目永久丢失（§A2） */
        if (lstat(s_path, &s_st) != 0) {
            r = -errno;
            break;
        }
        if (S_ISDIR(s_st.st_mode)) {
            r = recursive_copy_dir(s_path, d_path, uid, gid, NULL);
        } else if (S_ISREG(s_st.st_mode)) {
            int fd_src = open(s_path, O_RDONLY | O_CLOEXEC);
            if (fd_src >= 0) {
                /* 目标位于本次新建的临时树内，正常情况**不存在**：O_EXCL 让
                   任何预置对象（符号链接/同名文件）以 EEXIST 失败闭合，绝不
                   跟随链接或覆盖——临时目录可能继承源目录的 0777，攻击者可
                   在其内预置条目（R2 同族）。 */
                int fd_dst = open(d_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                                  s_st.st_mode & 0777);
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
        } else if (S_ISLNK(s_st.st_mode)) {
            /* 符号链接必须复制链接本身：旧实现静默跳过，随后删源即永久丢失 */
            char target[PATH_MAX];
            ssize_t tl = readlink(s_path, target, sizeof(target) - 1);
            if (tl < 0) {
                r = -errno;
            } else {
                target[tl] = '\0';
                if (symlink(target, d_path) != 0)
                    r = -errno;
                else
                    lchown(d_path, s_st.st_uid, s_st.st_gid);
            }
        } else {
            /* 其余类型（fifo/socket/设备）无法在此安全重建：拒绝而非静默跳过——
               返回成功会让调用方删掉源树，条目永久丢失 */
            LOG_WRN("跨设备复制：不支持的条目类型（mode=0%o）: %s", s_st.st_mode & 07777, s_path);
            r = -EOPNOTSUPP;
        }
    }
    closedir(d);
    return r;
}

/* libfuse 的「删除仍打开的文件」隐藏名：".fuse_hidden" + 16 位十六进制
   （格式 %08x%08x = nodeid + 全局计数器）。识别它是为了在**本地**路径上
   绕过隐藏名机制——本地 backing 支持 POSIX 的「先删名、后关句柄」，不需要
   改名占位；后端路径仍走隐藏名（远端删掉会让下载中的句柄失去数据源）。 */
static bool is_fuse_hidden_name(const char* name) {
    static const char prefix[] = ".fuse_hidden";
    if (!name || strncmp(name, prefix, sizeof(prefix) - 1) != 0) return false;
    const char* p = name + sizeof(prefix) - 1;
    int hex = 0;
    while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
        p++;
        hex++;
    }
    return hex == 16 && *p == '\0';
}

/* 目标名是 libfuse 的 open-unlink 隐藏名吗？libfuse 只在 unlink 仍打开的文件时
   生成它（rmdir 不走隐藏名），所以「目标是隐藏名」等价于「这是一次删除」。
   判定必须放在 fw_route 之前：rename 会按 RENAME_SRC 过 ACL，而顶层条目的
   「不可改名」结构规则会把「删除仍打开的顶层文件」误拒成 EPERM。 */
static bool rename_is_open_unlink(const char* to, unsigned int flags) {
    if (flags != 0 || !to) return false;
    const char* base = strrchr(to, '/');
    base = base ? base + 1 : to;
    return is_fuse_hidden_name(base);
}

static int vfs_rename_copy_file(const char* src, const char* dst, struct stat* st) {
    int fd_src = open(src, O_RDONLY | O_CLOEXEC);
    if (fd_src < 0) return -errno;
    /* 临时名由 xdev_temp_name 生成（不可预测），但目标父目录可能对普通应用
       可写：创建必须原子且失败闭合——O_EXCL 拒绝任何既有对象（含符号链接），
       O_NOFOLLOW 再堵一层；**绝不 O_TRUNC**（旧实现会跟随攻击者预置的同名
       符号链接，以 root 把源内容写进任意可写文件，R2）。 */
    /* 建文件的 mode 参数取源条目完整的 07777，与上面的目录拷贝
       （mkdir(dst, st.st_mode & 07777)）同一口径。最终值由随后的 fchmod 决定，
       这里只是不在创建瞬间用比源更窄的权限位建一个中间态。 */
    int fd_dst =
        open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, st->st_mode & 07777);
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

/* 跨设备搬移的临时名：必须与目标**同父目录**（rename(2) 才能原子就位），
   且不可预测。目标父目录可能对普通应用可写，可预测名（旧实现是
   "<p_to>.nsp_xdev_<pid>"）等于给攻击者一个预置符号链接/文件的窗口：root
   daemon 会跟随链接把源内容写进任意可写文件（R2）。
   这里借 mkstemp 的随机后缀只生成**名字**，占位文件立即删除；真正的创建由
   mkdir / open(O_EXCL|O_NOFOLLOW) / symlink 原子完成——任何预置对象都会以
   EEXIST 失败闭合，绝不会被跟随或复用（即使攻击者赢下 unlink→创建之间的
   竞态，结果也只是本次搬移失败）。返回 0 或负 errno。 */
static int xdev_temp_name(const char* p_to, char* out, size_t outsz) {
    int n = snprintf(out, outsz, "%s.nsp_xdev_XXXXXX", p_to);
    if (n < 0 || (size_t)n >= outsz) return -ENAMETOOLONG;
    int fd = mkstemp(out); /* 就地写入随机后缀 */
    if (fd < 0) return -errno;
    close(fd);
    if (unlink(out) != 0) return -errno;
    return 0;
}

/* 事件通道埋点：rename 成功。两条路径各自成条（契约：rename 的 src/dst 各成
   一条事件记录），真实落盘路径由事件线程按当时的规则解析。 */
static void vfs_rename_event(const char* from, const char* to, uid_t uid, pid_t pid) {
    if (!fw_events_active()) return;
    fw_events_note_write_done(uid, pid, to, FW_EV_OP_RENAME, from);
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
    bool mon_from = false, mon_to = false;
    /* 目标是隐藏名时这次调用其实是 unlink：from 按 DELETE 过 ACL——顶层条目的
       「不可改名」结构规则不适用于删除，AOSP 也只限制改名。 */
    const bool open_unlink = rename_is_open_unlink(to, flags);
    const NspAclOp src_acl_op = open_unlink ? NSP_ACL_OP_DELETE : NSP_ACL_OP_RENAME_SRC;
    int rrc = fw_route(ctx, from, &r1, &ok1, pkg_from, &u_from, sub_from, p_from, &redir_from,
                       &mon_from, VFS_OP_MUTATE, src_acl_op, false, 0);
    if (rrc != 0) return rrc;
    rrc = fw_route(ctx, to, &r2, &ok2, pkg_to, &u_to, sub_to, p_to, &redir_to, &mon_to,
                   VFS_OP_MUTATE, NSP_ACL_OP_RENAME_DST, false, 0);
    if (rrc != 0) return rrc;
    vfs_log_io(pkg_from, ctx->uid, "RENAME_FROM", sub_from,
               (ok1 && redir_from) ? r1.real_path : NULL, mon_from);
    vfs_log_io(pkg_to, ctx->uid, "RENAME_TO", sub_to, (ok2 && redir_to) ? r2.real_path : NULL,
               mon_to);
    /* 本地路径的 open-unlink：libfuse 发现文件仍打开时，会先把它改名成
       .fuse_hidden<16hex>，等最后一个句柄 RELEASE 后再删。本地 backing 是
       真实文件系统，unlink 打开中的文件完全合法（已打开的 fd 继续可读），
       所以直接删源、不产生隐藏名——与 Android 自带 FUSE 的可见行为一致，
       也不会在目录里留下「被改名却没删掉」的文件。后端路径不做此处理：
       远端立即删除会让正在下载/上传的句柄失去数据源，仍由隐藏名兜底。 */
    if (open_unlink && !r1.is_ftp && !r2.is_ftp) {
        const char* base = strrchr(sub_to, '/');
        base = base ? base + 1 : sub_to;
        if (is_fuse_hidden_name(base)) {
            /* 先留属性快照再删：删完名字就没了，而内核随后仍可能对打开句柄
               发 GETATTR（fstat）。快照以 FUSE 侧隐藏名为键，getattr/write/
               release 收到的 path 都是同一个名字。 */
            struct stat snap;
            const bool have_snap = lstat(p_from, &snap) == 0;
            /* libfuse 不为目录生成隐藏名：真收到目录说明应用自己把隐藏名当
               改名目标，仍按 AOSP 的结构规则拒绝（源端已按 DELETE 放行，
               故在此收口），免得「顶层目录改名为隐藏名」绕开不可改名规则。 */
            if (have_snap && S_ISDIR(snap.st_mode)) {
                log_fuse_err("RENAME_HIDDEN_DIR", from, EPERM);
                return -EPERM;
            }
            if (have_snap) hidden_stat_put(to, &snap);
            if (unlink(p_from) == 0) {
                log_open_unlink_direct(sub_from);
                return 0;
            }
            int err = errno;
            hidden_stat_remove(to);
            log_fuse_err("UNLINK_HIDDEN", from, err);
            return -err;
        }
    }
    /* 后端分派：from/to 命中后端时由模块方法重命名（两端须同一后端模块） */
    const NspModuleOps* bf_ops = NULL;
    const NspModuleOps* bt_ops = NULL;
    bool bf_hit = (ok1 && r1.is_ftp && module_backend_lookup(sub_from, &bf_ops) == 0);
    bool bt_hit = (ok2 && r2.is_ftp && module_backend_lookup(sub_to, &bt_ops) == 0);
    if (bf_hit || bt_hit) {
        /* 后端 rename 不带 flags：带 flags 的语义（NOREPLACE/EXCHANGE）无法表达，
           明确拒绝而非让模块按普通 rename 处理（否则目标被静默覆盖，§A1） */
        if (flags) {
            if (bf_hit) module_backend_put(bf_ops);
            if (bt_hit) module_backend_put(bt_ops);
            return -EINVAL;
        }
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
    /* 带 flags 的 rename（FUSE_RENAME2）：语义无法用普通 rename 表达，
       失败**禁止退化**——NOREPLACE 目标已存在时退化成普通 rename 会静默覆盖
       目标，EXCHANGE 失败后退化成单向移动会丢源（§A1）。原样返回 errno。 */
    if (flags) {
#ifdef SYS_renameat2
        if (syscall(SYS_renameat2, AT_FDCWD, p_from, AT_FDCWD, p_to, flags) == 0) {
            /* EXCHANGE 两个名字都换了树，故两端都重挂（普通 rename 下 from 已不存在，
               重挂函数按 lstat 失败直接返回）；属主与目标父目录一致的条目一律不动 */
            nsp_rehome_moved_entry(p_to);
            nsp_rehome_moved_entry(p_from);
            vfs_rename_event(from, to, ctx->uid, ctx->pid);
            return 0;
        }
        int ferr = errno;
#else
        int ferr = EINVAL; /* 本平台无 renameat2：flags 语义不可满足 */
#endif
        LOG_WRN("rename flags=0x%x 未生效（errno=%d），拒绝退化: %s -> %s", flags, ferr, p_from,
                p_to);
        return -ferr;
    }
    /* 无 flags：走普通 rename + 跨设备(EXDEV)回退。strdup 须判 NULL（§A3） */
    char* p_to_dup = strdup(p_to);
    if (!p_to_dup) return -ENOMEM;
    char* p_to_dir = dirname(p_to_dup);
    /* 目标父目录补建走守卫出口：永不创建存储根一级条目（见 common.h） */
    int mkdir_res = common_mkdir_within_storage(p_to_dir, 0775);
    int mkdir_err = mkdir_res != 0 ? errno : 0;
    free(p_to_dup); /* p_to_dir 随之失效：此后只许用 p_to 打日志 */
    if (mkdir_res != 0) {
        if (mkdir_err == 0) mkdir_err = EIO;
        LOG_ERR("重命名创建目标父目录失败: %s (errno=%d)", p_to, mkdir_err);
        return -mkdir_err; /* 旧实现 free 后用 p_to_dir 打日志（UAF）且取残留 errno */
    }
    if (rename(p_from, p_to) == 0) {
        /* 跨树搬移（应用私有树 -> /sdcard）落位后重挂属性：rename 不产生新条目，
           否则条目带着来源树的属主与 0600 落地，共享存储里除写入者谁也打不开 */
        nsp_rehome_moved_entry(p_to);
        vfs_rename_event(from, to, ctx->uid, ctx->pid);
        return 0;
    }
    int err = errno;
    if (err == EXDEV) {
        struct stat st;
        if (lstat(p_from, &st) != 0) return -errno;
        /* 跨设备搬移：先复制到同父目录下的**不可预测**临时名，成功后再就位。
           不可预测 + 创建原子（open(O_EXCL|O_NOFOLLOW) / mkdir / symlink 的
           EEXIST 失败闭合）是安全前提：目标父目录可能对普通应用可写，旧实现
           的可预测名 "<p_to>.nsp_xdev_<pid>" 允许攻击者预置符号链接，root
           daemon 会跟随它把源内容写进任意可写文件（R2）。
           临时名同时保证「失败清理只影响本次产物」。 */
        char tmp_to[PATH_MAX];
        int trc = xdev_temp_name(p_to, tmp_to, sizeof(tmp_to));
        if (trc != 0) return trc;
        int copy_res;
        bool src_is_dir = S_ISDIR(st.st_mode);
        bool tmp_created = false; /* 只清理**本次创建**的残留（R2） */
        if (S_ISREG(st.st_mode))
            copy_res = vfs_rename_copy_file(p_from, tmp_to, &st);
        else if (src_is_dir)
            copy_res = recursive_copy_dir(p_from, tmp_to, ctx->uid, ctx->gid, &tmp_created);
        else if (S_ISLNK(st.st_mode)) {
            /* 符号链接搬移：重建链接本身（不跟随目标）；symlink 对已存在的
               名字以 EEXIST 失败闭合 */
            char target[PATH_MAX];
            ssize_t tl = readlink(p_from, target, sizeof(target) - 1);
            if (tl < 0) {
                copy_res = -errno;
            } else {
                target[tl] = '\0';
                copy_res = symlink(target, tmp_to) == 0 ? 0 : -errno;
                if (copy_res == 0) {
                    tmp_created = true;
                    lchown(tmp_to, st.st_uid, st.st_gid);
                }
            }
        } else {
            copy_res = -EOPNOTSUPP; /* 其余类型不支持跨设备搬移 */
        }
        if (copy_res != 0) {
            /* 只清理本次创建的临时产物：创建本身失败（EEXIST 等）时
               tmp_created 为 false，绝不碰别人的同名对象 */
            if (tmp_created) recursive_rmdir(tmp_to);
            LOG_ERR("跨设备复制失败: %s -> %s (err=%d)", p_from, p_to, copy_res);
            return copy_res;
        }
        /* 就位：直接 rename(tmp_to, p_to)，目标冲突由 POSIX 裁决
           （ENOTEMPTY/EISDIR/EEXIST）。**不得预删目标**：旧实现对既有非空
           目录 recursive_rmdir(p_to) 会把调用方的目标子树整棵删掉再返回成功
           （R1，数据丢失）；同父目录 rename 本身原子，目标要么原样保留、
           要么被本次搬移完整替换。 */
        if (rename(tmp_to, p_to) != 0) {
            int e = errno;
            if (src_is_dir)
                recursive_rmdir(tmp_to);
            else
                unlink(tmp_to);
            LOG_ERR("跨设备搬移：临时产物就位失败: %s -> %s (err=%d)", tmp_to, p_to, e);
            return -e;
        }
        /* 就位即落进目标树：复制阶段带回的是源条目的属主与 mode（fchown/fchmod 照抄
           源属性），这里与同设备 rename 一样按目标父目录重挂；在删源之前做，失败也
           不影响搬移结果 */
        nsp_rehome_moved_entry(p_to);
        /* 就位成功后才删源；删源失败**不得**回删目标（否则两边都不完整），
           如实回报错误并保留完整的目标 */
        int rm_res = src_is_dir ? recursive_rmdir(p_from)
                                : (unlink(p_from) == 0 ? 0 : -errno);
        if (rm_res != 0) {
            LOG_ERR("跨设备搬移：源删除失败（目标已完整，保留）: %s (err=%d)", p_from, rm_res);
            return rm_res;
        }
        vfs_rename_event(from, to, ctx->uid, ctx->pid);
        return 0;
    }
    log_fuse_err("RENAME", from, err);
    return -err;
}

/* ===== 官方 FUSE 语义补齐（对齐 Android 原生 FUSE 的可观察行为） =====
   Android MediaProvider FUSE（fuse-passthrough）对本地 backing 直接支持
   fallocate/hardlink 等 VFS 操作；此前缺省回调经 libfuse 回 ENOSYS，应用侧
   （fallocate 下载器/游戏、cp -al 硬链接）要么性能退化要么失败。以下回调对
   本地 backing 直接转发；FTP/SFTP 后端无对应能力时按 errno 契约返回
   -EOPNOTSUPP（内核/应用按"文件系统不支持"处理，与官方语义一致）。 */

static int vfs_fallocate(const char* path, int mode, off_t offset, off_t length,
                         struct fuse_file_info* fi) {
    VFS_SETUP_CORE(path, VFS_OP_MUTATE);
    /* 后端路径：模块表无 fallocate 能力（ABI V5），按不支持闭合 */
    if (rr.is_ftp) VFS_RETURN(-EOPNOTSUPP);
    /* 与 vfs_write/vfs_fsync 同一口径：本地打开句柄就放在 fi->fh。用它而非重新
       按名 open——文件被 unlink 后仍持句柄时（编辑器/下载器的常见顺序）按名 open
       会 ENOENT，句柄视角才与本地文件语义一致。 */
    bool own_fd = false;
    int fd = -1;
    if (fi && fi->fh > 0 && !(fi->fh & NSP_FH_BACKEND_FLAG)) {
        fd = (int)fi->fh;
    } else {
        fd = open(p, O_WRONLY);
        own_fd = true;
    }
    if (fd == -1) {
        int err = errno;
        log_fuse_err("FALLOCATE", path, err);
        VFS_RETURN(-err);
    }
    int ret = fallocate(fd, mode, offset, length);
    int err = errno; /* fallocate 成功时 errno 可能被改写，先存 */
    if (own_fd) close(fd);
    if (ret == -1) {
        log_fuse_err("FALLOCATE", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_link(const char* from, const char* to) {
    VFS_SETUP_CORE_OP(from, VFS_OP_MUTATE, NSP_ACL_OP_LINK);
    char p_to[PATH_MAX];
    NspPathDecision r2;
    bool ok2 = false, redir_to = false, mon_to = false;
    char sub_to[PATH_MAX], pkg_to[128];
    int u_to = -1;
    int rrc = fw_route(ctx, to, &r2, &ok2, pkg_to, &u_to, sub_to, p_to, &redir_to, &mon_to,
                       VFS_OP_MUTATE, NSP_ACL_OP_LINK, false, 0);
    if (rrc != 0) return rrc;
    /* 跨后端：硬链接要求同一文件系统与同一目录语义，官方口径 EXDEV */
    if (r2.is_ftp || rr.is_ftp) VFS_RETURN(-EXDEV);
    /* 不走 nsp_new_entry_attrs：硬链接不产生新 inode，这里改 mode/属主等于改
       源文件（同一 inode），那是 chmod/chown 回调的事，不是建条目的属性收尾。 */
    int ret = link(p, p_to);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("LINK", from, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_mknod(const char* path, mode_t mode, dev_t rdev) {
    VFS_SETUP_CORE_OP(path, VFS_OP_MUTATE, NSP_ACL_OP_MKNOD);
    /* 能力判定纯转发：设备节点能否建立由内核/SELinux 决定（应用无 CAP_MKNOD
       时自然 EPERM），不在此处额外设限。
       属性收尾与 create/mkdir 同一出口：旧实现既不 lchown 也不 chmod，mknod
       出来的节点属主是 root、mode 是 mode & ~umask，与同目录下 create 出来的
       条目（属主=父目录属主、mode=调用方 mode）方向完全相反。 */
    int ret = mknod(p, mode, rdev);
    if (ret == -1 && errno == ENOENT) {
        /* 沙盒/REDIRECT 的虚拟父目录可能尚未落盘；只经守卫出口补父，
           不创建缺失的存储根一级组件，也不重试权限或其他业务错误。 */
        char* p_dup = strdup(p);
        if (p_dup) {
            if (common_mkdir_within_storage(dirname(p_dup), 0775) == 0)
                ret = mknod(p, mode, rdev);
            int err = errno;
            free(p_dup);
            errno = err;
        }
    }
    if (ret == -1) {
        int err = errno;
        log_fuse_err("MKNOD", path, err);
        VFS_RETURN(-err);
    }
    nsp_new_entry_attrs(p, mode);
    VFS_RETURN(0);
}

static int vfs_fsyncdir(const char* path, int datasync, struct fuse_file_info* fi) {
    (void)fi;
    VFS_SETUP_CORE(path, VFS_OP_READ);
    if (rr.is_ftp) VFS_RETURN(-EOPNOTSUPP);
    int fd = open(p, O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        int err = errno;
        log_fuse_err("FSYNCDIR", path, err);
        VFS_RETURN(-err);
    }
    int ret = datasync ? fdatasync(fd) : fsync(fd);
    int err = errno;
    close(fd);
    /* 纯转发：本地目录 fsync 不会失败，失败即真实错误，原样回给应用 */
    if (ret == -1) {
        log_fuse_err("FSYNCDIR", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

/* ACL chmod 的丢弃结果不变，观测沿用框架首个/每 1024 次的有界计数。 */
static void chmod_acl_drop_note(const char* path, mode_t mode) {
    static atomic_ulong seq;
    unsigned long n = atomic_fetch_add_explicit(&seq, 1, memory_order_relaxed) + 1;
    if (n == 1 || (n & 1023u) == 0)
        LOG_WRN("丢弃带 ACL 条目的 chmod: path=%s mode=%04o（累计 %lu 次）",
                path, (unsigned)(mode & 07777), n);
}

static int vfs_chmod(const char* path, mode_t mode, struct fuse_file_info* fi) {
    (void)fi;
    /* 与 AOSP 的取舍：普通条目上我们的 backing 是真实文件系统，属性可以真的保存
       下来，故照旧下发，只把访问控制交给 SETATTR 判定。但结构条目（卷根、用户根、
       /Android/{data,obb,media}、用户根下一级条目）例外，与 AOSP 的 handle_setattr
       一样丢弃 mode 变更并静默成功：这些条目的 mode 由存储层与 daemon 决定，不归
       任何应用——放行等于给每个应用一个把 /sdcard/Download 改成 0700/2700 的开关，
       一旦改掉，此后其它应用在该目录里全被 DAC 拒（比权限继承写坏更难排查，因为
       没有任何调用栈可看）。 */
    VFS_SETUP_CORE_OP(path, VFS_OP_MUTATE, NSP_ACL_OP_SETATTR);
    if (fw_acl_is_structure_entry(path)) {
        LOG_WRN("丢弃结构条目的 chmod: path=%s mode=%04o", path, (unsigned)(mode & 07777));
        VFS_RETURN(0);
    }
    /* 带 POSIX ACL 的条目同样丢弃：chmod(2) 会就地改写 ACL 的 mask 条目，把
       文件管理器按 ACL 设好的 a_* 权限压回 mode 位模型。AOSP 遇到已存在的
       system.posix_acl_access 也是丢弃 mode 变更。 */
    if (lgetxattr(p, "system.posix_acl_access", NULL, 0) > 0) {
        chmod_acl_drop_note(path, mode);
        VFS_RETURN(0);
    }
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
    VFS_SETUP_CORE_OP(path, VFS_OP_MUTATE, NSP_ACL_OP_SETATTR);
    /* 结构条目同 chmod：属主由存储层决定，丢弃变更并静默成功（AOSP 口径）。 */
    if (fw_acl_is_structure_entry(path)) {
        LOG_WRN("丢弃结构条目的 chown: path=%s uid=%u gid=%u", path, (unsigned)uid,
                (unsigned)gid);
        VFS_RETURN(0);
    }
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
    VFS_SETUP_CORE_OP(path, VFS_OP_MUTATE, NSP_ACL_OP_SETATTR);
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
            int drc;
            if (backend_dispatch_after(bslot, "backend_truncate", brc, sub_path, "truncate 返回异常",
                                       &drc))
                VFS_RETURN(drc);
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
    /* 由 common 唯一出口合成：--root=<dir> 时统计该文件系统（此前硬编码
       STORAGE_BASE，测试根/迁移根下 df 与写前查空间拿到另一文件系统的容量，
       可能"显示有空但实际写满"或反之）。root 为空回退 STORAGE_BASE，与
       common_default_real_path 同口径。 */
    char root[PATH_MAX];
    common_default_real_path(-1, "", root, sizeof(root));
    if (root[0] == '\0') return -ENAMETOOLONG; /* 超长失败闭合 */
    int ret = statvfs(root, st);
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
                size_t len = sizeof(NSP_DEFAULT_FILE_CONTEXT);
                if (size == 0) {
                    VFS_RETURN((int)len);
                }
                if (size < len) {
                    VFS_RETURN(-ERANGE);
                }
                memcpy(value, NSP_DEFAULT_FILE_CONTEXT, len);
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
    VFS_SETUP_CORE_OP(path, VFS_OP_MUTATE, NSP_ACL_OP_SETXATTR);
    int ret = lsetxattr(p, name, value, size, flags);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("SETXATTR", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_removexattr(const char* path, const char* name) {
    VFS_SETUP_CORE_OP(path, VFS_OP_MUTATE, NSP_ACL_OP_SETXATTR);
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
    /* 只投递 EXIT（comm 线程仍存活），日志在 main 尾部
       module_system_shutdown() 之后再关——否则模块 exit 钩子、卸载失败告警、
       provider 收尾日志全被丢弃（此前 log_close 先于卸载，退出期日志为空）。 */
    char msg[256];
    snprintf(msg, sizeof(msg), "FUSE_EXIT %d", getpid());
    nsp_comm_post(NSP_CH_IPC, msg, strlen(msg) + 1);
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
    /* 安全契约（B3）：探测目录（/tmp、/data/local/tmp）对所有用户可写，名字可预测。
       用 O_CREAT|O_EXCL 拒绝攻击者预置的同名文件；用 O_NOFOLLOW 拒绝其预置的符号
       链接（否则 root daemon 会把 fd 作为 backing 交给 ioctl → 打开任意路径）。
       残留同名（上次异常退出）先 unlink 再独占创建（unlink 不跟随符号链接，安全）。 */
    int test_fd = open(probe_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (test_fd < 0 && errno == EEXIST) {
        unlink(probe_path);
        test_fd = open(probe_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    }
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
    /* GNU：init 阶段无会话 fd，探测推迟到首次 open 时补执行一次。
       用原子 exchange 做 test-and-set：多 worker 并发首次 open 时只有一个线程
       进入探测，其余直接复用其结果（B3：原先 bool 检查-清零存在并发重入）。 */
    bool expected_pending = true;
    if (atomic_compare_exchange_strong(&g_pt_probe_pending, &expected_pending, false)) {
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
#if defined(TARGET_ANDROID) && defined(FUSE_CAP_OVER_IO_URING)
    /* 同 worker 下一回调清 backing fd 依赖同步 reply。预构建库也必须禁
       异步 SQE 回复，不能只依赖 Meson 子项目的 enable-io-uring=false。 */
    fuse_unset_feature_flag(conn, FUSE_CAP_OVER_IO_URING);
    conn->want &= ~(unsigned)FUSE_CAP_OVER_IO_URING;
#endif
    /* 缓存超时不在此处写死：`fuse_new` 已按 libfuse 默认值填好 conf
       （entry/attr=1.0、negative=0.0）**并已解析用户经 -o 传入的值**
       （fuse.c: 默认值 → fuse_opt_parse → fuse_fs_init 才回调本函数），
       此处再无条件赋值会覆盖用户的 -o attr_timeout=... 等设置。
       特别注意 negative_timeout：libfuse 默认 0.0（不缓存 ENOENT），旧代码
       把它抬到 0.5，正是"上传成功后立即 open 命中陈旧负缓存报 ENOENT"的根因
       （FTP 后端只能靠 open 内 2×10ms 重试兜底）。保持默认 0 后该竞态消失；
       后端自有 stat 缓存（含负条目）吸收内核层未命中的重复查询，无吞吐回退。
       需要负缓存时该 -o 子项会被 main() 单点剥离（nodeid=0 上送崩溃防御，见 strip_negative_timeout_opt）。 */
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
    atomic_store(&g_pt_probe_pending, true);
    LOG_DBG("FUSE Passthrough: GNU 下 ioctl 探测推迟到首次文件 open");
#endif

passthrough_done:
skip_passthrough:
    if (g_passthrough_enabled) {
        LOG("FUSE Passthrough: 🟢 启用成功");
    } else if (atomic_load(&g_pt_probe_pending)) {
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
            g_passthrough_enabled ? "启用" : (atomic_load(&g_pt_probe_pending) ? "延迟探测" : "标准FUSE回退"));
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

#endif

#ifdef TARGET_ANDROID
/* 放弃挂接的原因日志：vfs_backing_setup 是**每个 dentry 查找**都会走的回调
   （内核不缓存"这个路径没挂上 backing"的结论，下一次查找再来问），于是热点子树
   （媒体扫描器遍历规则根下所有条目）会把同一行刷成日志洪水——线上实测
   /0/MM1TT 一条路径就能占满 sys.log。
   「此路径需规则仲裁」是**稳定事实**而非瞬时事件，逐条上报没有信息增量，故按
   原因限频：首次立即报（带真实路径），其后每小时最多补一行，带这段时间被抑制的
   条数与最近一条路径样本。
   注意：LOG_DBG 在 log_internal 里**不受级别过滤**（前身 LOG_MON 要求监控日志
   恒可见，见该函数注释），所以限频是这里唯一的抑制手段，别指望 --log-level。 */
enum { BACKING_DECLINE_RULE = 0, BACKING_DECLINE_GLOBAL_DAC, BACKING_DECLINE_N };
static const char* const g_backing_decline_what[BACKING_DECLINE_N] = {
    "规则需仲裁，放弃挂接",
    "全局实例按调用方凭证 DAC，不挂接（见 vfs_backing_setup 注释）",
};
/* nsp_log_gate 非线程安全：FUSE 多 worker 并发进 vfs_backing_setup，故加锁。
   该分支本就回退全量 mediation（内核不再走 backing），一把短锁的代价可忽略。 */
static pthread_mutex_t g_backing_decline_mu = PTHREAD_MUTEX_INITIALIZER;
static NspLogGate g_backing_decline_gate[BACKING_DECLINE_N];
#define BACKING_DECLINE_QUIET_SEC 3600

static void backing_decline_log(int reason, const char* path) {
    unsigned quiet = 0;
    char sample[NSP_LOG_GATE_SAMPLE_MAX];
    pthread_mutex_lock(&g_backing_decline_mu);
    bool emit = nsp_log_gate(&g_backing_decline_gate[reason], path, BACKING_DECLINE_QUIET_SEC,
                             &quiet);
    snprintf(sample, sizeof sample, "%s", g_backing_decline_gate[reason].sample);
    pthread_mutex_unlock(&g_backing_decline_mu);
    if (!emit) return;
    if (quiet > 0)
        LOG_DBG("FUSE backing: %s（自上次上报以来另有 %u 次，最近 %s）",
                g_backing_decline_what[reason], quiet, sample);
    else
        LOG_DBG("FUSE backing: %s %s（同原因已限频，其后每小时最多一行）",
                g_backing_decline_what[reason], path);
}

/* backing 直通挂接（内核 bpf_setup 上行回调）：只挂 backing fd，不挂系统 BPF
   策略程序——后者按调用方独立裁决且 verdict 最终（daemon 零感知），线上实例：
   空规则下 root 按名 stat 他包 data 目录被它以 ENOENT 拒绝（直接访问 backing
   则正常），且 SANDBOX/REDIRECT/HIDE/RO 对该子树整体失效。故：

   - **全局实例（默认，服务所有被注入应用）：一个 dentry 也不挂接**，全部回落
     daemon 全权 mediation。原因在 DAC 而不在规则：backing 之后的下层 I/O 由内核
     在**发起请求的应用进程上下文**里直接打到真实文件（lookup / create / opendir
     都按调用方凭证判 DAC），而 /data/media/0 整棵树归 MediaProvider（10277:1023、
     属组 media_rw），普通应用既不在属主也不在属组——同组位也只能靠 0770 的组
     权限过。线上实测：应用段只写 ALLOW /Download
     （或不写任何路径规则）时该路径命中 backing 直通，create 随即被内核以 EACCES
     拒绝，观感就是「注入之后反而写不进 /Download，拿掉模块就正常」。而 backing
     结论是**按 dentry 缓存**的，同一 dentry 由不同 uid 的应用共用，无法按调用方
     分别裁决；共享实例上这条路只能整体关掉（要全仲裁本就可用 --no-bpf，现在
     全局实例等于恒全仲裁）。
   - **media 实例（--media-fuse，调用方恒为 MediaProvider 自身）**：保留直通，按
     路径门 fw_backing_mediation_required_for() 逐路径裁决——命中（自身/其下/
     直接父）即 declined（-ENOENT，内核回退 mediation），未命中则 backing-only
     挂接。远祖先（/、/0、/Android 等）不强制仲裁；SANDBOX ON 时整树要求仲裁
     （隐私模式）。该实例只有 MediaProvider 一个调用方，其 uid 10277 就是
     /data/media/0 树的所有者，DAC 成立，加速才安全。
   已挂接 dentry 对运行期新增规则不感知（与此前同约束，历史行为一致）。 */
static int vfs_backing_setup(const char* path, struct fuse_entry_param* e) {
    if (g_bpf_disabled) return -ENOSYS;
    if (!path || !e) return -EINVAL;

    char real[PATH_MAX];

    if (!g_is_media_fuse) {
        /* 全局实例永不挂接：dentry 由所有应用共用，而下层 I/O 按调用方凭证
           做 DAC（见函数头注释）。 */
        backing_decline_log(BACKING_DECLINE_GLOBAL_DAC, path);
        return -ENOENT;
    }
    if (fw_backing_mediation_required_for(path)) {
        /* 媒体实例：调用方单一，仅规则需仲裁此路径时 declined。 */
        backing_decline_log(BACKING_DECLINE_RULE, path);
        return -ENOENT;
    }

    /* backing 路径经 common 唯一出口合成：g_real_root 为空（injector 已不再
       传 --root=）时回退 STORAGE_BASE，与 common_default_real_path 同口径；
       此前裸拼在空 root 下产出虚拟路径（/0/...），open 恒 ENOENT，BPF  backing
       静默丢失（线上实例）。user_id=-1 保留 <uid>/ 层原样。 */
    common_default_real_path(-1, path, real, sizeof(real));
    if (real[0] == '\0') return -ENAMETOOLONG; /* 超长 fail-closed */
    if (!S_ISDIR(e->attr.st_mode)) return -ENOTDIR;

    int bfd = open(real, O_CLOEXEC | O_DIRECTORY | O_RDONLY);
    if (bfd < 0) {
        LOG_DBG("FUSE backing: open(%s) = %s", real, strerror(errno));
        return -errno;
    }

    /* 线程所有权建立失败则保持 mediation；尚未发布的 fd 可以直接关，不能
       先填 reply 字段再失败（内核可能取得被关闭/复用的 fd 号）。 */
    if (!vfs_defer_close(bfd)) {
        close(bfd);
        return -ENOMEM;
    }
    /* 只挂 backing，不挂系统策略程序（bpf_action 保持 KEEP=0）：见函数头注释 */
    e->backing_action = FUSE_ACTION_REPLACE;
    e->backing_fd = (uint64_t)bfd;
    LOG_DBG_PERF("FUSE backing: %s (fd=%d, media=%d)", real, bfd, g_is_media_fuse);

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
    .fallocate = vfs_fallocate,
    .link = vfs_link,
    .mknod = vfs_mknod,
    .fsyncdir = vfs_fsyncdir,
#ifdef TARGET_ANDROID
    .bpf_setup = vfs_backing_setup,
#endif
};

/* -o negative_timeout 熔断（防御 nodeid=0 上送崩溃）：
   libfuse 负缓存分支在 LOOKUP 未命中且 negative_timeout!=0 时以 e.ino=0
   成功回包（fuse.c fuse_lib_lookup）；现代内核（proto>=4）把 nodeid=0 原样
   入缓存，后续 FORGET(0) 触发 get_node(0) abort → SIGABRT（线上实例）。
   本文件系统做实时重定向/规则热重载，负缓存语义本就错误，故在此单点剥离
   该 -o 子项（同串其余子项保留；串空则整项丢弃），恒以 libfuse 默认 0.0
   运行。覆盖 FUSE_EXTRA_ARGS 与手工启动两种形态：`-o a,negative_timeout=N,b`
   与 `-o` + `a,negative_timeout=N,b`。 */
static bool fuse_opt_item_match(const char* item, const char* name) {
    size_t n = strlen(name);
    return strncmp(item, name, n) == 0 && (item[n] == '\0' || item[n] == '=');
}

/* 原地过滤逗号串中的目标子项（只缩短不增长）；返回过滤后是否非空 */
static bool filter_opt_list(char* opts, const char* name) {
    char* w = opts;
    bool first = true;
    for (char* p = opts;;) {
        char* comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        char save = p[len];
        p[len] = '\0';
        if (!fuse_opt_item_match(p, name)) {
            if (!first) *w++ = ',';
            memmove(w, p, len);
            w += len;
            first = false;
        }
        p[len] = save;
        if (!comma) break;
        p = comma + 1;
    }
    *w = '\0';
    return w != opts;
}

/* 剥离 fuse_argv 中的 -o negative_timeout 子项；返回整理后的 argc */
static int strip_negative_timeout_opt(char** av, int ac) {
    bool stripped = false;
    int w = 0;
    for (int r = 0; r < ac; r++) {
        char* a = av[r];
        char* opts = NULL;
        bool separate = false;
        if (strcmp(a, "-o") == 0 && r + 1 < ac) {
            opts = av[r + 1];
            separate = true;
        } else if (strncmp(a, "-o", 2) == 0 && a[2] != '\0') {
            opts = a + 2;
        }
        if (opts && strstr(opts, "negative_timeout") != NULL) {
            size_t before = strlen(opts);
            bool nonempty = filter_opt_list(opts, "negative_timeout");
            if (strlen(opts) != before) stripped = true;
            if (!nonempty) {
                if (separate) r++; /* 连值 token 一并丢弃 */
                continue;          /* 整项丢弃 */
            }
        }
        av[w++] = a;
    }
    if (stripped)
        LOG_WRN("FUSE: 已剥离 -o negative_timeout（负缓存以 ino=0 回包，内核缓存 "
                "nodeid=0 后触发 abort），保持 libfuse 默认 0.0");
    return w;
}

int main(int argc, char* argv[]) {
    char rules_path[PATH_MAX] = {0};
    char* fuse_argv[argc + 1];
    int fuse_argc = 0;
    if (argc > 0) fuse_argv[fuse_argc++] = argv[0];
    for (int i = 1; i < argc; i++) {
        /* --mode= 已删除（g_mode 从未被读取，redirect 是唯一形态）：
           旧版对任何取值实际都跑 redirect，故忽略与旧行为完全一致；
           曾改为显式拒绝，但线上出现新旧混装（旧 injector + 新 daemon）
           导致 daemon 连续拒启（log(7) 3 秒内 15 次），改回警告忽略。
           解析尚在 log_init 之前，日志走 stderr（injector 重定向至
           fuse_crash.log，可查）。 */
        if (strncmp(argv[i], "--mode=", 7) == 0) {
            fprintf(stderr, "fuse_daemon: 忽略已删除的参数 %s（恒为 redirect 语义）\n", argv[i]);
            continue;
        } else if (strncmp(argv[i], "--root=", 7) == 0) {
            strncpy(g_real_root, argv[i] + 7, PATH_MAX - 1);
            g_real_root[PATH_MAX - 1] = '\0';
            /* 归一尾部 '/'：--root=<dir>/ 会让后续每条真实路径都带 '//'，
               存储根守卫的一级条目判定与 common_mkdir_within_storage 的切片
               随之错位（守卫静默失效）——在入口一次归一，运行期不再有尾斜杠 */
            size_t rl = strlen(g_real_root);
            while (rl > 1 && g_real_root[rl - 1] == '/') g_real_root[--rl] = '\0';
        } else if (strncmp(argv[i], "--rules=", 8) == 0) {
            strncpy(rules_path, argv[i] + 8, PATH_MAX - 1);
        } else if (strncmp(argv[i], "--ready-fd=", 11) == 0) {
            g_ready_fd = atoi(argv[i] + 11);
        } else if (strncmp(argv[i], "--global-root-fd=", 17) == 0) {
            /* --global-root-fd 已删除（daemon 侧从未使用该 fd）：同 --mode，
               混装下拒绝会致连续拒启，改警告忽略（stderr 可查）。 */
            fprintf(stderr, "fuse_daemon: 忽略已删除的参数 %s\n", argv[i]);
            continue;
        } else if (strcmp(argv[i], "--strip-o-direct") == 0) {
            g_strip_o_direct = true;
#ifdef TARGET_ANDROID
        } else if (strcmp(argv[i], "--no-bpf") == 0) {
            g_bpf_disabled = true;
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
            g_fuse_threads_explicit = true;
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
    /* 未显式指定时按宿主核数取默认（见 fuse_threads.h）：worker 太少会被单个
       应用的冷启动打满队列，太多只是让线程互抢 CPU。注入器也可经配置下发。 */
    if (!g_fuse_threads_explicit) {
        g_fuse_threads = nsp_default_fuse_threads((int)sysconf(_SC_NPROCESSORS_ONLN));
    }
    prctl(PR_SET_NAME, "fuse_daemon", 0, 0, 0);
    log_init("fuse_daemon");
    /* 负缓存熔断单点（nodeid=0 上送崩溃防御）：须在 log_init 之后，
       剥离告警（LOG_WRN）走日志系统，未初始化会被丢弃 */
    fuse_argc = strip_negative_timeout_opt(fuse_argv, fuse_argc);
    fuse_argv[fuse_argc] = nullptr;
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
    /* 模块目录必须先告知配置读取侧：模块自有配置（<modules_dir>/<名>/<名>.conf）
       由框架读取后经视图下发，路径与加载器同一取值（--modules-dir= 可覆盖） */
    config_set_modules_dir(g_modules_dir_arg[0] ? g_modules_dir_arg : NULL);
    /* 内建规则引擎先就绪：它把派生缓存作废注册进配置发布临界区（此后每次发布自动作废） */
    fw_rules_init(rules_path, g_disable_sandbox);
    /* 全局沙盒开启时的可观测性：沙盒把应用对用户根的访问整树重定向到
       <base>/<uid>/Android/data/<pkg>/<SANDBOX_DIR>，只有显式 ALLOW 的目录例外。
       默认目录（Download/DCIM/Music…）一旦不在 ALLOW 里，应用写进去的文件会落在
       自己沙盒里——写入成功、其它应用看不见、报 ENOENT 而不是 EACCES，现场极难
       自查。这里只在启动时点明这个前提，不改变任何路由（改沙盒作用域是策略变更，
       不在权限缺陷的修复范围内）。 */
    if (g_global_cfg.sandbox)
        LOG_WRN("全局 SANDBOX ON：未被 ALLOW 覆盖的用户根目录会整树重定向到应用沙盒"
                "（<存储根>/<用户id>/Android/data/<包名>/<沙盒目录>），文件落盘但其它应用"
                "看不见；需要哪些目录共享，就在规则里为它们写 ALLOW");
    /* 顶层目录体检：<base>/<uid> 下的默认目录权限被写坏（属组位丢失，d---------
       形态）时改回 drwxrwx---，非默认目录只记日志。放在导出视图之前：视图一旦
       导出，应用就会按错误权限读写，事后修正不会让已经失败的调用重试。 */
    {
        char sbase[PATH_MAX];
        common_storage_base(sbase, sizeof(sbase));
        fw_acl_repair_storage_toplevel(sbase);
    }
    /* 热插拔模块系统：扫描模块目录并启动监控线程（只剩后端模块形态） */
    module_system_init(rules_path, g_modules_dir_arg[0] ? g_modules_dir_arg : NULL);

    if (g_disable_sandbox) {
        LOG("沙盒特性已强制禁用");
    }

#ifdef TARGET_ANDROID
    if (g_bpf_disabled) {
        LOG("FUSE backing: 已被 --no-bpf 参数禁用（标准 FUSE 全仲裁模式）");
    } else if (is_fuse_bpf_supported()) {
        if (g_is_media_fuse)
            LOG("FUSE backing: 直通就绪（仅 backing，无系统策略程序）");
        else
            LOG("FUSE backing: 全局实例全量 mediation（下层 DAC 按调用方凭证，不挂 backing）");
    } else {
        LOG_WRN("FUSE backing: 内核不支持，直通挂接不可用，将以标准 FUSE 模式运行");
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
            /* 事件通道（nsp_fs_events / nsp_fs_query）：必须在 fuse_daemonize
               之后建立——后台化会 fork，fork 不保留任何已存在线程。默认
               [GLOBAL] FUSE_EVENTS OFF 时这里立即返回，零线程零 socket。
               启动失败不致命：通道是附加能力，起不来不影响挂载与 IO。

               归属只给全局实例：媒体实例（--media-fuse）只服务 MediaProvider
               自己的挂载，事件本来就该由全局实例发布。此前两个实例都往同一个
               抽象名上 bind，谁先绑谁赢——输的那条实例的应用事件永远发不出去，
               且只有一条 WARN 滚在日志里（用户视角：事件功能随机哑掉）。 */
            if (g_is_media_fuse) {
                LOG("媒体实例不建立事件通道：归属固定为全局实例");
            } else if (fw_events_start() != 0) {
                LOG_WRN("FUSE 事件通道启动失败（不影响挂载与 IO）");
            }
            char thread_desc[64];
            if (fopts.singlethread || g_fuse_threads == 0)
                snprintf(thread_desc, sizeof thread_desc, "单线程");
            else if (g_fuse_threads == -1)
                snprintf(thread_desc, sizeof thread_desc, "libfuse 默认(10)");
            else if (g_fuse_threads_explicit)
                snprintf(thread_desc, sizeof thread_desc, "%d 线程（显式）", g_fuse_threads);
            else
                snprintf(thread_desc, sizeof thread_desc, "%d 线程（按核数自动）",
                         g_fuse_threads);
            LOG("FUSE 会话就绪: 挂载点=%s, worker 线程数=%s", fopts.mountpoint, thread_desc);
            /* COPY_FILE_RANGE 一律交回内核：本文件不实现 copy_file_range，
               而 libfuse 高层的 fuse_fs_copy_file_range() 在判断操作是否存在
               之前就先取线程上下文（fuse_get_context），缺上下文时解空指针崩溃。
               关掉低层派发后内核收到 ENOSYS 即永久改走 read/write 循环。 */
            if (fuse_disable_copy_file_range != NULL) {
                fuse_disable_copy_file_range(f);
                LOG("FUSE copy_file_range: 关闭派发，内核回退 read/write");
            } else {
                LOG_DBG("libfuse 未提供 fuse_disable_copy_file_range，"
                        "COPY_FILE_RANGE 仍可能进入高层回退路径");
            }
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
            /* 单线程循环由 main 执行，return main 不运行线程 TSD 析构。 */
            vfs_flush_pending_closes();
            fuse_remove_signal_handlers(se);
        }
        fuse_unmount(f);
        fuse_destroy(f);
    }
    if (lcfg) fuse_loop_cfg_destroy(lcfg);
    free(fopts.mountpoint);
    fuse_opt_free_args(&fa);
    /* mt 模式把 fuse_loop_mt 的任何非零返回压成 8，而 8 只表示"线程池里某个
       worker 出过错"，与单线程 rc 不同源；旧实现连同 8 一起静默——会话被中止
       （挂载被卸载、连接被 abort）导致 daemon 退出时，日志里一个字都没有，
       现场只能看到 injector 侧的"挂载点不可达"，归因断在这里。退出原因必须
       留痕：正常退出（rc=0）仍不记，避免每次重载都刷一行。 */
    if (fmain_rc) {
        if (fmain_rc == 8) {
            LOG_WRN("FUSE 会话退出: 线程池返回非零（会话被中止或 worker 出错）");
        } else {
            LOG_ERR("FUSE 会话退出: rc=%d", fmain_rc);
        }
    }
    /* 退出前卸载模块（并停配置监听线程、释放引擎缓存）：
       ① 模块的 exit 应在进程退出前正常调用；
       ② 更要紧的是**别把模块留在映射里**——`exit()` → `_dl_fini` 会遍历所有仍
       映射的 .so 并调用其析构器（.fini_array），若该 .so 曾被就地覆盖（映射页
       因 truncate 失效、重定位丢失）就会跳到未重定位地址而崩在退出瞬间。
       module_system_shutdown 内部对失效镜像走"不调 exit、直接 dlclose"。 */
    fw_events_stop(); /* 先停自己的线程，再卸模块（模块卸载会等其线程退出） */
    module_system_shutdown();
    /* 日志关闭必须在模块卸载之后：module_system_shutdown 内部的 exit 钩子、
       镜像失效/ban 告警、provider 收尾统计都要落盘。log_close 自身的"最尽力
       drain + join comm 线程"语义不变，只是位置后移。 */
    log_close();
    return fmain_rc;
}
