/*
 * tests/fixtures/ns_combined_rollback_driver.c
 *
 * do_combined_mount 合并挂载的确定性失败注入驱动（回滚 / 源预检 / 传播隔离 /
 * 挂载后校验 / 后台通道静默）。
 *
 * 做法：把实际源码 src/injector/ns_utils.c 整体 #include 进本 TU（经
 * -DNS_UTILS_SRC= 传入路径）—— 同一翻译单元内 static 的 do_combined_mount
 * 对本文件可见，可直接调用；再用 -Wl,--wrap=mount/umount2/statfs 拦截挂载与
 * 文件系统类型原语，代码路径全走真实实现，只有内核对 mount/statfs 的裁决被
 * 替换成可控返回值。时序不依赖命名空间、FUSE、特权与调度运气。
 *
 * 覆盖：
 *   A. 源 bind 失败 + 族根可用 → 第二次 mount 以族根为源回滚，target 还原为
 *      族根视图，日志含「已回滚」，返回原始 errno（不再让应用停留在裸状态）。
 *   B. 源 bind 失败 + 族根不可用 → 不回滚、只报「回滚未成功」，返回原始 errno。
 *   C. 对照：源 bind 成功 → 不触发任何回滚挂载，且挂载后校验通过。
 *   D. 目标视图未就绪（readiness_ms=0）→ 在任何卸载之前返回 ENOENT。
 *   E. 后台通道（NSP_READINESS_QUIET）→ 缺失属预期：静默（无 WARN/ERROR）、
 *      不写 error.log、不宣称「交由重试队列」，只留一条 DEBUG 说明。
 *   F. 对照：同缺失但走权威尝试（readiness_ms=0）→ 仍须 WARN + 「交由重试队列」。
 *   G. 源预检（统计 §源不是 FUSE 挂载）→ **零卸载、零挂载**，返回 ENODEV：
 *      旧实现会先把 target 拆掉再挂，源是空目录时 bind "成功" → 应用存储全空。
 *   H. 挂载后校验失败（目标未变成 FUSE 视图）→ 卸载本次挂载 + 族根回滚 + EIO，
 *      绝不把"挂上了却什么都没有"留给应用。
 *   I. 传播隔离：MS_PRIVATE 必须在**第一次卸载之前**发出（共享挂载组上的卸载
 *      事件会传播到 zygote/其它应用的命名空间，真机表现为"整机存储都空了"）。
 *
 * 回归价值：移除回滚分支（旧实现只 return err）→ A 必失败；把后台通道静默换回
 * 旧的 WARN 口径（HEAD 实现）→ E3/E4/E5 必失败；去掉源预检 → G2/G3 必失败；
 * 去掉挂载后校验 → H1/H2 必失败；去掉 MS_PRIVATE → I1 必失败。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "common.h"
#include "fast_search.h"
#include "inject_target.h"
#include "injector.h"
#include "ns_global_replace.h"
#include "ns_utils.h"

#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif
#define TMPFS_MAGIC_FAKE 0x01021994

/* ══════════════ 测试可控的 mock 状态 ══════════════ */

#define MAX_MOUNT_CALLS 16

static int g_mount_calls;
static char g_mount_src[MAX_MOUNT_CALLS][256];
static char g_mount_tgt[MAX_MOUNT_CALLS][256];
/* 让挂载源为 <mock_fail_source> 的那次 mount 失败（其余成功） */
static const char* g_fail_source;
static char g_logbuf[8192];
/* ns_read_mountinfo_pid 的合成返回：族根挂载点（NULL 表示不提供） */
static const char* g_family_root;
/* 传播隔离（mount(NULL, target, MS_PRIVATE|MS_REC)）记账 */
static int g_private_calls;
static int g_private_seq = -1; /* 私有化发生时已发生的 umount2 次数（-1=未调用） */
static int g_umount_calls;
/* statfs 裁决：源/目标分别可被伪造成非 FUSE（预检失败 / 挂载后校验失败） */
static bool g_source_not_fuse;
static bool g_target_not_fuse;
static int g_statfs_calls;
/* umount2 的 flags 记账（快路径必须用 MNT_DETACH 一次摘整棵子树） */
static int g_umount_flags[MAX_MOUNT_CALLS];
/* MS_PRIVATE 返回值控制：0=目标是挂载点（快路径，不读 mountinfo）；
   -1 + EINVAL=目标不是挂载点（首次注入的普通目录，必须枚举子树） */
static int g_private_result;
/* 挂载点收集调用记账：单目标（旧实现各扫一遍）与多目标（一次扫描收两棵子树） */
static int g_collect_single_calls;
static int g_collect_multi_calls;

/* 按级别计数：断言"未就绪不算失败"必须能区分 DEBUG 说明与 WARN/ERROR 报错 */
static int g_warn_lines;
static int g_err_lines;

static void record_log(const char* fmt, ...) {
    size_t used = strlen(g_logbuf);
    if (used + 2 >= sizeof g_logbuf) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_logbuf + used, sizeof g_logbuf - used, fmt, ap);
    va_end(ap);
}

static bool log_has(const char* needle) { return strstr(g_logbuf, needle) != nullptr; }

/* 统计日志里某标记出现的次数（限速用例要数行数，不能只看"有没有"） */
static int count_occurrences(const char* hay, const char* needle) {
    int n = 0;
    size_t nlen = strlen(needle);
    for (const char* p = hay; (p = strstr(p, needle)) != nullptr; p += nlen) n++;
    return n;
}

/* 项目内 log_internal：只做记录，不落盘/不走日志环 */
void log_internal(LogLevel level, const char* format, ...) {
    if (level >= LOG_WARN) g_warn_lines++;
    if (level >= LOG_ERROR) g_err_lines++;
    size_t used = strlen(g_logbuf);
    if (used + 2 >= sizeof g_logbuf) return;
    va_list ap;
    va_start(ap, format);
    vsnprintf(g_logbuf + used, sizeof g_logbuf - used, format, ap);
    va_end(ap);
}

/* ══════════════ 挂载 / statfs 原语拦截 ══════════════ */

int __wrap_mount(const char* source, const char* target, const char* fstype, unsigned long flags,
                 const void* data) {
    (void)fstype;
    (void)data;
    if ((flags & MS_PRIVATE) && source == nullptr) {
        /* 传播隔离调用：单独记账，并记录"已经发生了几次卸载"（用于断言顺序） */
        g_private_calls++;
        if (g_private_seq < 0) g_private_seq = g_umount_calls;
        if (g_private_result != 0) {
            errno = EINVAL; /* 真实内核语义：目标不是挂载点 */
            return -1;
        }
        return 0;
    }
    if (g_mount_calls < MAX_MOUNT_CALLS && source && target) {
        snprintf(g_mount_src[g_mount_calls], sizeof g_mount_src[0], "%s", source);
        snprintf(g_mount_tgt[g_mount_calls], sizeof g_mount_tgt[0], "%s", target);
    }
    g_mount_calls++;
    if (g_fail_source && source && strcmp(source, g_fail_source) == 0) {
        errno = ENOENT; /* 应用 ns 内源不可见：真实内核语义 */
        return -1;
    }
    return 0;
}

int __wrap_umount2(const char* target, int flags) {
    (void)target;
    if (g_umount_calls < MAX_MOUNT_CALLS) g_umount_flags[g_umount_calls] = flags;
    g_umount_calls++;
    return 0; /* 卸载一律成功：聚焦挂载失败后的回滚分支 */
}

int __wrap_statfs(const char* path, struct statfs* buf) {
    g_statfs_calls++;
    memset(buf, 0, sizeof *buf);
    if (g_source_not_fuse && path && strcmp(path, "/mnt/nsp_global") == 0) {
        buf->f_type = TMPFS_MAGIC_FAKE;
        return 0;
    }
    if (g_target_not_fuse && path && strcmp(path, "/mnt/nsp_global") != 0) {
        buf->f_type = TMPFS_MAGIC_FAKE;
        return 0;
    }
    buf->f_type = FUSE_SUPER_MAGIC;
    return 0;
}

/* ══════════════ 其余外部依赖的最小桩 ══════════════ */

uid_t get_app_uid(int pid) {
    (void)pid;
    return 10123; /* user 0（uid/100000 == 0） */
}

char* read_file_dynamic(const char* path, size_t* out_size, size_t max_size) {
    (void)path;
    (void)max_size;
    const char* text = "1 0 8:1 / /tmp/nonexistent-root rw - tmpfs none rw\n";
    char* copy = strdup(text);
    if (out_size && copy) *out_size = strlen(copy);
    return copy;
}

int mkdir_recursive(const char* dir) {
    (void)dir;
    return 0;
}

const char* fast_strstr(const char* haystack, const char* needle) { return strstr(haystack, needle); }

bool ns_is_digit_char(char c) { return c >= '0' && c <= '9'; }

bool ns_is_family_root(const char* mp) { return strstr(mp, "/emulated") != nullptr; }

int ns_parse_family_root(const char* mp, int* user_id) {
    if (strncmp(mp, "/mnt/user/", 10) == 0)
        *user_id = 0;
    else if (strncmp(mp, "/mnt/installer/", 15) == 0)
        *user_id = 0;
    else if (strncmp(mp, "/mnt/androidwritable/", 21) == 0)
        *user_id = 0;
    else
        *user_id = -1;
    if (strstr(mp, "/emulated")) return 2; /* family 2：/mnt/user/... */
    return -1;
}

int ns_read_mountinfo_pid(int pid, NsMountEntry** out) {
    (void)pid;
    if (!out) return -1;
    *out = nullptr;
    if (!g_family_root) return 0;
    NsMountEntry* entries = calloc(1, sizeof *entries);
    if (!entries) return -1;
    snprintf(entries[0].mount_point, sizeof entries[0].mount_point, "%s", g_family_root);
    *out = entries;
    return 1;
}

/* C7：do_combined_mount 的子挂载点收集经 ns_collect_mounts_under_pid 收口。
   本用例聚焦「合并挂载失败后的回滚」，与收集到的子挂载点无关——桩返回 0
   （无子挂载点），与上方 read_file_dynamic 桩返回不含匹配项的内容等价。 */
int ns_collect_mounts_under_pid(int pid, const char* base, char (*out)[NS_MOUNT_PATH_MAX],
                                int max, const char* who) {
    g_collect_single_calls++;
    (void)pid;
    (void)base;
    (void)out;
    (void)max;
    (void)who;
    return 0;
}

/* do_combined_mount 现在一次扫描收多棵子树（备份树 + 目标树）：桩返回"没有
   子挂载点"。本驱动的 MS_PRIVATE 桩返回 0（等价于"目标已是挂载点"→快路径），
   因此不会触达扫描；保留桩是为了本 TU 能独立链接。 */
int ns_collect_mounts_multi(int pid, NsCollectTarget* targets, int ntargets) {
    g_collect_multi_calls++;
    (void)pid;
    for (int i = 0; i < ntargets; i++) targets[i].n = 0;
    return 0;
}

void ns_mountinfo_last_stats(NsMountinfoStats* out) {
    if (out) memset(out, 0, sizeof *out);
}

int ns_scan_mountinfo_prefixed(int pid, const char* const* prefixes, int nprefixes,
                               NsMountinfoLineFn cb, void* ctx) {
    (void)pid;
    (void)prefixes;
    (void)nprefixes;
    (void)cb;
    (void)ctx;
    return 0;
}

/* ns_utils.c 的成功回调会清重试记账；本用例不涉及重试队列 */
void retry_mount_succeeded(int pid) { (void)pid; }

/* ══════════════ 实际源码（static do_combined_mount 由此可见） ══════════════ */

#include NS_UTILS_SRC

/* ══════════════ 用例 ══════════════ */

static int g_fail;

static void check(const char* name, bool ok, const char* detail) {
    printf("  %s %s", ok ? "[PASS]" : "[FAIL]", name);
    if (!ok && detail && *detail) printf(" — %s", detail);
    printf("\n");
    if (!ok) g_fail = 1;
}

static void reset_case(const char* fail_source, const char* family_root) {
    g_mount_calls = 0;
    g_logbuf[0] = '\0';
    g_warn_lines = 0;
    g_err_lines = 0;
    g_private_calls = 0;
    g_private_seq = -1;
    g_umount_calls = 0;
    g_source_not_fuse = false;
    g_target_not_fuse = false;
    g_statfs_calls = 0;
    g_private_result = 0;
    g_collect_single_calls = 0;
    g_collect_multi_calls = 0;
    memset(g_umount_flags, 0, sizeof g_umount_flags);
    g_fail_source = fail_source;
    g_family_root = family_root;
}

static int run_combined_with(const char* target, int readiness_ms) {
    struct CombinedMountArgs args = {
        .pkg = "com.test.target",
        .source = "/mnt/nsp_global",
        .target = target,
        .backup = "/var/fuse-proxy/backup/storage",
        .preserve_paths = nullptr,
        .preserve_count = 0,
        /* 存活检查用自己：就绪门控在 readiness>0 时会 kill(pid,0) 探活，
           pid 1 在非 root 下返回 EPERM（会被判成"目标已退出"） */
        .target_pid = getpid(),
        .app_uid = 10123,
        .readiness_ms = readiness_ms,
    };
    return do_combined_mount(&args);
}

int main(void) {
    printf("── do_combined_mount 合并挂载（失败注入 / 源预检 / 传播隔离 / 校验） ──\n");
    /* 目标用一个真实存在的临时目录：不依赖宿主是否有 /storage/emulated */
    char tgt_tmpl[] = "/tmp/nsp_cm_target_XXXXXX";
    if (!mkdtemp(tgt_tmpl)) {
        printf("  [FAIL] 无法创建临时目标目录\n结果: 存在失败\n");
        return 1;
    }
    const char* target = tgt_tmpl;
    const char* missing = "/nonexistent/nsp_emulated";

    /* A. 源 bind 失败 + 族根可用 → 以族根回滚 */
    reset_case("/mnt/nsp_global", "/mnt/user/0/emulated");
    errno = 0;
    int rc = run_combined_with(target, 0);
    check("A1 源 bind 失败返回原始 errno(ENOENT)", rc == ENOENT,
          rc == ENOENT ? "" : "返回码与预期不符");
    check("A2 发生第二次 mount（回滚）", g_mount_calls >= 2,
          g_mount_calls >= 2 ? "" : "未触发回滚挂载");
    if (g_mount_calls >= 2) {
        bool src_ok = strcmp(g_mount_src[0], "/mnt/nsp_global") == 0;
        bool rb_src_ok = strcmp(g_mount_src[1], "/mnt/user/0/emulated") == 0;
        bool rb_tgt_ok = strcmp(g_mount_tgt[1], target) == 0;
        check("A3 首挂载源=项目 FUSE，回滚源=族根且目标不变", src_ok && rb_src_ok && rb_tgt_ok,
              "调用记录不符");
    } else {
        check("A3 首挂载源=项目 FUSE，回滚源=族根且目标不变", false, "调用记录不足");
    }
    check("A4 日志报告已回滚（非裸状态）", log_has("已回滚") && !log_has("回滚未成功"),
          log_has("已回滚") ? "" : "缺少回滚成功日志");

    /* B. 源 bind 失败 + 族根不可用 → 不回滚、loud 报错 */
    reset_case("/mnt/nsp_global", nullptr);
    errno = 0;
    rc = run_combined_with(target, 0);
    check("B1 仍返回原始 errno(ENOENT)", rc == ENOENT, "");
    check("B2 族根本不可用时不发生回滚挂载", g_mount_calls == 1,
          g_mount_calls == 1 ? "" : "意外发起了回滚挂载");
    check("B3 loud 报告回滚未成功", log_has("回滚未成功"), log_has("回滚未成功") ? "" : "缺少报错");

    /* C. 对照：源可挂载 → 不触发回滚，且挂载后校验通过 */
    reset_case(nullptr, "/mnt/user/0/emulated");
    errno = 0;
    rc = run_combined_with(target, 0);
    check("C1 源可挂载时成功返回 0", rc == 0, "");
    check("C2 成功路径只挂载一次（无回滚）", g_mount_calls == 1,
          g_mount_calls == 1 ? "" : "成功路径出现了多余挂载");
    check("C3 无回滚日志", !log_has("已回滚") && !log_has("回滚未成功"), "");
    check("C4 挂载后做了 statfs 校验", g_statfs_calls >= 2,
          g_statfs_calls >= 2 ? "" : "缺少源预检或挂载后校验");

    /* D. 目标视图未就绪（readiness_ms=0）→ 必须在**任何卸载之前**就返回 ENOENT：
          权威通道把"未就绪"当作失败信号，若这里先把应用卸载成裸状态再失败，
          应用会失去 /storage/emulated。 */
    reset_case(nullptr, nullptr);
    errno = 0;
    rc = run_combined_with(missing, 0);
    check("D1 目标缺失 + 预算0 → 立即 ENOENT", rc == ENOENT,
          rc == ENOENT ? "" : "未按未就绪返回 ENOENT");
    check("D2 目标缺失时零挂载调用（判定早于卸载/挂载）", g_mount_calls == 0,
          g_mount_calls == 0 ? "" : "目标缺失仍发起了挂载");
    check("D3 目标缺失时零卸载调用", g_umount_calls == 0, "目标缺失仍卸载了挂载点");
    check("D4 日志报告缺失而非回滚", log_has("缺失") && !log_has("已回滚"),
          log_has("缺失") ? "" : "缺少缺失日志");

    /* E. 后台通道（NSP_READINESS_QUIET，异步扫描/失败重试）：目标 ns 尚未被
          vold 装配是**预期**状态，由重试队列稍后补挂。旧实现按普通失败记
          WARN + error.log 并宣称"交由重试队列"，真机表现为"错误刷屏"。 */
    reset_case(nullptr, nullptr);
    errno = 0;
    rc = run_combined_with(missing, NSP_READINESS_QUIET);
    check("E1 后台通道目标缺失 → 立即 ENOENT", rc == ENOENT,
          rc == ENOENT ? "" : "未按预期未就绪返回 ENOENT");
    check("E2 未就绪时零挂载调用", g_mount_calls == 0, "目标缺失仍发起了挂载");
    check("E3 未就绪不记 WARN/ERROR（不是失败）", g_warn_lines == 0 && g_err_lines == 0,
          "未就绪仍按失败记了 WARN/ERROR");
    check("E4 不宣称“交由重试队列”、不用失败式措辞",
          !log_has("重试队列") && !log_has("缺失("), "仍出现旧失败措辞");
    check("E5 以 DEBUG 说明后台通道语义", log_has("后台通道"), "缺少后台通道说明");

    /* F. 对照：同一缺失但走权威尝试（POST/旧通道，readiness_ms=0）→ 必须 loud，
          否则真实故障会被静默（E 的静默只能限后台通道）。 */
    reset_case(nullptr, nullptr);
    errno = 0;
    rc = run_combined_with(missing, 0);
    check("F1 权威尝试目标缺失 → ENOENT", rc == ENOENT, "");
    check("F2 权威尝试仍 loud（至少一条 WARN）", g_warn_lines >= 1, "真实失败被静默了");
    check("F3 明确交由重试队列", log_has("交由重试队列"), "");

    /* F4/F5. 就地快试预算（POST 的 20ms）：等不到是**常态**——真机 vold 把
           /storage/emulated 装进应用命名空间要 135–150ms。这一档的缺失只能记
           DEBUG：若按权威尝试 loud，真机每次冷启动都会往 error.log 写一条
           "缺失(20ms 内未出现)"（旧 250ms 预算下已有 31 条这种噪声；改成 20ms
           后 202/322 次挂载都会命中）。 */
    reset_case(nullptr, nullptr);
    errno = 0;
    rc = run_combined_with(missing, 20);
    check("F4 就地快试预算（20ms）目标缺失 → 仍 ENOENT（交后台重试）", rc == ENOENT,
          rc == ENOENT ? "" : "未按未就绪返回 ENOENT");
    check("F5 就地快试未就绪不写 WARN/ERROR（不污染 error.log）",
          g_warn_lines == 0 && g_err_lines == 0,
          "20ms 快试的预期未就绪被记成了失败");
    check("F6 就地快试不用失败式措辞、且说明是快试",
          !log_has("重试队列") && !log_has("缺失(") && log_has("就地快试"),
          "措辞与权威尝试未区分");

    /* G. 源预检：源在本命名空间不是 FUSE 挂载（不同 ROM 的 /mnt 传播设置可能只
          把目录传进来、FUSE 没传进来）→ 必须**在卸载之前**放弃：旧实现会先把
          原生视图拆掉，再把空目录 bind 成 /storage/emulated（"假成功空挂载"），
          真机表现即"某些设备 /storage/emulated/0 整个是空的"。 */
    reset_case(nullptr, "/mnt/user/0/emulated");
    g_source_not_fuse = true;
    errno = 0;
    rc = run_combined_with(target, 0);
    check("G1 源非 FUSE → 返回 ENODEV", rc == ENODEV, rc == ENODEV ? "" : "未拒绝不可用的源");
    check("G2 源非 FUSE → 零挂载调用（目标一点没动）", g_mount_calls == 0,
          g_mount_calls == 0 ? "" : "仍对目标发起了 bind");
    check("G3 源非 FUSE → 零卸载调用", g_umount_calls == 0, "先拆了原生视图");
    check("G4 明确报告保持原生视图", log_has("保持原生视图"), "");

    /* H. 挂载后校验：目标没有变成 FUSE 视图（源其实是普通目录/其它 fs）→
          卸载本次挂载 + 族根回滚 + EIO。绝不把"挂上了却什么都没有"留给应用。 */
    reset_case(nullptr, "/mnt/user/0/emulated");
    g_target_not_fuse = true;
    errno = 0;
    rc = run_combined_with(target, 0);
    check("H1 校验失败返回 EIO", rc == EIO, rc == EIO ? "" : "未按校验失败返回 EIO");
    check("H2 校验失败后发起了族根回滚", g_mount_calls >= 2,
          g_mount_calls >= 2 ? "" : "未回滚到原生视图");
    check("H3 loud 报告校验失败", log_has("校验失败"), "");

    /* I. 传播隔离：MS_PRIVATE 必须**先于任何卸载**发出——共享挂载组上的卸载
          事件会传播到 zygote/其它应用的命名空间（真机表现为"整机存储都空了"）。 */
    reset_case(nullptr, "/mnt/user/0/emulated");
    errno = 0;
    rc = run_combined_with(target, 0);
    check("I1 发出了 MS_PRIVATE 传播隔离调用", g_private_calls == 1,
          g_private_calls == 1 ? "" : "缺少传播隔离（卸载/挂载事件会传播出去）");
    check("I2 私有化发生在第一次卸载之前", g_private_seq == 0,
          g_private_seq == 0 ? "" : "私有化晚于卸载");

    /* J. 分段计时（[ns计]）：定位"135ms 花在哪"的唯一手段，但绝不许自己变成
          刷屏源。真机 20:05:18 一秒 633 行的 unlink DEBUG 已经把 sys.log 冲掉了
          一次，同类事故不能再犯。判别点：
            - 共享页（MAP_SHARED）被子进程填满 → 父进程能读到各段耗时；
            - 总耗时 < 20ms 的"健康挂载"只按 1/1024 采样；
            - 总耗时 ≥ 20ms 的慢挂载必打一条，且带段名与合计；
            - 每秒硬上限 20 条，其余折叠并计数。旧实现没有任何分段计时 → J1-J4 全失败。 */
    reset_case(nullptr, "/mnt/user/0/emulated");
    struct NsMountSeg seg;
    memset(&seg, 0, sizeof seg);
    struct CombinedMountArgs jargs = {
        .pkg = "com.test.target",
        .source = "/mnt/nsp_global",
        .target = target,
        .backup = "/var/fuse-proxy/backup/storage",
        .preserve_paths = nullptr,
        .preserve_count = 0,
        .target_pid = 1,
        .app_uid = 10123,
        .readiness_ms = 0,
        .seg = &seg,
    };
    int jrc = do_combined_mount(&jargs);
    int64_t jsum = 0;
    for (int i = 0; i < NSP_SEG_COUNT; i++) jsum += seg.us[i];
    check("J1 成功路径填充分段计时（合计 > 0，父进程可读子进程写的共享页）", jrc == 0 && jsum > 0,
          jrc == 0 ? "分段耗时全为 0：共享页没被写" : "挂载未成功");

    /* J2：快速挂载只按 1/1024 采样（1100 次 <20ms 的挂载最多 2 行） */
    reset_case(nullptr, nullptr);
    struct NsMountSeg fast;
    memset(&fast, 0, sizeof fast);
    for (int i = 0; i < 1100; i++) ns_seg_log("com.test.fast", &fast, 0);
    int fast_lines = count_occurrences(g_logbuf, "[ns计]");
    check("J2 健康挂载（<20ms）按 1/1024 采样：1100 次 ≤ 2 行", fast_lines <= 2,
          "分段计时变成了刷屏源");

    /* J3：慢挂载必打一条，且带段名与合计 */
    reset_case(nullptr, nullptr);
    struct NsMountSeg slow;
    memset(&slow, 0, sizeof slow);
    slow.us[NSP_SEG_READY] = 30 * 1000; /* 30ms 花在就绪门控上 */
    ns_seg_log("com.test.slow", &slow, 31 * 1000);
    check("J3 慢挂载（≥20ms）必打一条且含段名/合计/段外",
          log_has("[ns计]") && log_has("就绪=30ms") && log_has("合计=30ms") && log_has("段外=1ms"),
          "慢挂载没有分段日志");

    /* J4：每秒硬上限（20 条），其余折叠并计数 */
    reset_case(nullptr, nullptr);
    for (int i = 0; i < 100; i++) ns_seg_log("com.test.storm", &slow, 31 * 1000);
    int storm_lines = count_occurrences(g_logbuf, "[ns计]");
    check("J4 每秒最多 20 条分段日志（其余折叠并计数）",
          storm_lines <= NSP_SEG_MAX_PER_SEC && log_has("折叠="),
          "分段日志没有每秒上限");

    /* K. 目标是挂载点（MS_PRIVATE|MS_REC 成功）⇒ 一条 MNT_DETACH 连整棵子树一起摘，
          **完全不读 /proc/self/mountinfo**。真机 [ns计] 实测这一步每次冷启动
          134~136ms（两次整文件扫描），正是"注入后冷启动明显变慢"的主因；
          判别点：旧实现无论目标是不是挂载点都枚举子树（单目标收集 2 次）。 */
    reset_case(nullptr, "/mnt/user/0/emulated");
    errno = 0;
    rc = run_combined_with(target, 0);
    check("K1 目标是挂载点时挂载成功", rc == 0, rc == 0 ? "" : "快路径没走通");
    check("K2 目标是挂载点 ⇒ 零次 mountinfo 收集（不读整文件）",
          g_collect_single_calls == 0 && g_collect_multi_calls == 0,
          "仍然枚举了子树：每次冷启动白读一整份 mountinfo");
    check("K3 备份与目标各一条卸载，且目标那条带 MNT_DETACH（连子树一起摘）",
          g_umount_calls == 2 && (g_umount_flags[1] & MNT_DETACH) != 0,
          "卸载次数/标志不符：整棵子树会漏在挂载点上");
    check("K4 私有化仍先于第一次卸载", g_private_seq == 0, "私有化晚于卸载");

    /* L. 目标不是挂载点（MS_PRIVATE 返回 EINVAL = 首次注入的普通目录）⇒ 必须枚举
          子树，且备份树与目标树共用**一次**扫描（旧实现各扫一遍同一份 mountinfo）。 */
    reset_case(nullptr, "/mnt/user/0/emulated");
    g_private_result = -1;
    errno = 0;
    rc = run_combined_with(target, 0);
    check("L1 目标非挂载点（EINVAL）时仍挂载成功", rc == 0, rc == 0 ? "" : "EINVAL 被当成致命错误");
    check("L2 目标非挂载点 ⇒ 枚举子树，且只扫一次（多目标合并）",
          g_collect_multi_calls == 1 && g_collect_single_calls == 0,
          "扫描次数不是 1：备份树/目标树又各扫了一遍");

    rmdir(target);
    printf("%s\n", g_fail ? "结果: 存在失败" : "结果: 全部通过");
    return g_fail;
}
