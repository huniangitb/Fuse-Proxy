/*
 * tests/fixtures/grepl_status_fast_driver.c
 *
 * 稳态对账快查（src/injector/ns_global_replace.c 的 ns_global_status 快查分支）的
 * 确定性驱动。
 *
 * 做法：把实际源码 ns_mountinfo.c 与 ns_global_replace.c 整体 #include 进本 TU，
 * 用 --wrap 把「文件里有什么」「路径的 dev」「路径的文件系统类型」换成可控值：
 *   --wrap=fopen     判 mountinfo 是否被打开（快查命中就不该打开）
 *   --wrap=opendir / --wrap=readdir / --wrap=closedir  合成 /mnt/<族> 下的用户目录
 *   --wrap=stat      合成每个族根与源的 superblock dev
 *   --wrap=statfs    合成每个族根与源的文件系统类型（FUSE / tmpfs）
 * 扫描、解析、状态判定全部走真实实现。
 *
 * 覆盖：
 *   A. 三族族根与源同为项目 FUSE 且同 dev → REPLACED，且**一次 mountinfo 都没打开**。
 *   B. 任一族根 dev 对不上、或 fstype 不是 FUSE → 回落扫描，按挂载表判 MIXED。
 *   C. 源不是 FUSE（被上层挂载盖住）或 stat 不到 → 回落扫描，结论由挂载表给出。
 *   D. 一条族根都没有 → 回落扫描，空表给 UNKNOWN（不能当 REPLACED）。
 *   E. 族根 stat 出错（非 ENOENT）→ 回落扫描，不猜。
 *   F. 多用户：两个用户的族根都是项目视图 → REPLACED 且零次 mountinfo 打开
 *      （枚举漏掉一个用户就等于让那一族永久跳过对账）。
 *   G. 用户目录里的非纯数字条目被忽略；某族 /emulated 还没建（ENOENT）→ 跳过。
 *   H. 源与族根都还是普通 tmpfs 目录 → 不得判 REPLACED：开机早期 FUSE 未起时
 *      它们同处一个文件系统、dev 相等，只比 dev 会把「一条都还没挂」当成「全换好了」。
 *   I. 源是 FUSE、但源与族根被同一个空 tmpfs 盖住（共享挂载组上的挂载会传播）→
 *      两边 dev 相等却不是项目视图，必须回落扫描（这一条是判定「只比 dev 不够」的
 *      回归点）。
 *
 * 判别性：A/F/G 在旧实现（无快查，直接整份扫描）上必失败——旧实现一定打开 mountinfo，
 * 且这份合成表为空时只会给 UNKNOWN。
 *
 * 退出码：全部通过 0，任一失败 1。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "common.h"
#include "fast_search.h"
#include "nsp_log.h"
#include "ns_global_replace.h"
#include "ns_utils.h"

/* ══════════════ 合成 mountinfo ══════════════ */

#define MI_BUF_SIZE (1u << 20)
static char g_mountinfo[MI_BUF_SIZE];
static size_t g_mountinfo_len;
static int g_mountinfo_opens;

static void mi_reset(void) {
    g_mountinfo_len = 0;
    g_mountinfo[0] = '\0';
    g_mountinfo_opens = 0;
}

/* 追加一行：id parent dev root mount_point opts - fstype source superopts */
static void mi_add(const char* dev, const char* mount_point, const char* fstype,
                   const char* source) {
    char line[1024];
    int n = snprintf(line, sizeof line, "600 599 %s / %s rw,nosuid shared:9 - %s %s rw\n", dev,
                     mount_point, fstype, source);
    if (n <= 0 || g_mountinfo_len + (size_t)n >= MI_BUF_SIZE) return;
    memcpy(g_mountinfo + g_mountinfo_len, line, (size_t)n);
    g_mountinfo_len += (size_t)n;
    g_mountinfo[g_mountinfo_len] = '\0';
}

/* ══════════════ 合成路径属性（stat / statfs / opendir / readdir） ══════════════ */

#define FAKE_MAX 24
#define FUSE_MAGIC 0x65735546UL
#define TMPFS_MAGIC 0x01021994UL

struct FakeStat {
    char path[320];
    dev_t dev;
    int err;      /* 非 0 ⇒ 返回 -1 并设 errno */
    long f_type;  /* statfs 的 f_type；0 ⇒ FUSE（项目视图是常态） */
};
static struct FakeStat g_stats[FAKE_MAX];
static int g_stats_n;

struct FakeDir {
    char path[320];
    int err; /* 非 0 ⇒ opendir 返回 NULL 并设 errno */
    int n;
    int cursor;
    char names[8][64];
};
static struct FakeDir g_dirs[4];
static int g_dirs_n;

static void fs_reset(void) {
    g_stats_n = 0;
    g_dirs_n = 0;
    mi_reset();
}

static struct FakeStat* stat_add_full(const char* path, dev_t dev, int err, long f_type) {
    if (g_stats_n >= FAKE_MAX) return nullptr;
    snprintf(g_stats[g_stats_n].path, sizeof g_stats[0].path, "%s", path);
    g_stats[g_stats_n].dev = dev;
    g_stats[g_stats_n].err = err;
    g_stats[g_stats_n].f_type = f_type;
    return &g_stats[g_stats_n++];
}

/* 项目 FUSE 视图（或按需指定 dev） */
static void stat_add(const char* path, dev_t dev, int err) { (void)stat_add_full(path, dev, err, 0); }

/* 普通目录 / 系统视图：tmpfs 或别的文件系统，不是项目 FUSE */
static void stat_add_tmpfs(const char* path, dev_t dev) {
    (void)stat_add_full(path, dev, 0, (long)TMPFS_MAGIC);
}

static void dir_add(const char* path, int err) {
    if (g_dirs_n >= 4) return;
    memset(&g_dirs[g_dirs_n], 0, sizeof g_dirs[0]);
    snprintf(g_dirs[g_dirs_n].path, sizeof g_dirs[0].path, "%s", path);
    g_dirs[g_dirs_n].err = err;
    g_dirs_n++;
}

static void dir_name(const char* name) {
    struct FakeDir* d = &g_dirs[g_dirs_n - 1];
    if (d->n >= 8) return;
    snprintf(d->names[d->n], sizeof d->names[0], "%s", name);
    d->n++;
}

/* /proc/<pid>/root<相对路径>：避免到处写 pid */
static const char* rootpath(char* buf, size_t n, const char* suffix) {
    snprintf(buf, n, "/proc/%d/root%s", (int)getpid(), suffix);
    return buf;
}

static bool is_proc_path(const char* p) { return p && strncmp(p, "/proc/", 6) == 0; }

/* ══════════════ 拦截 ══════════════ */

FILE* __real_fopen(const char* path, const char* mode);
int __real_stat(const char* path, struct stat* st);
int __real_statfs(const char* path, struct statfs* sfs);
DIR* __real_opendir(const char* path);
struct dirent* __real_readdir(DIR* d);
int __real_closedir(DIR* d);

static bool is_mountinfo_path(const char* path) {
    size_t len = path ? strlen(path) : 0;
    const char* tail = "/mountinfo";
    size_t tl = strlen(tail);
    return len > tl && strncmp(path, "/proc/", 6) == 0 && strcmp(path + len - tl, tail) == 0;
}

FILE* __wrap_fopen(const char* path, const char* mode) {
    if (!is_mountinfo_path(path)) return __real_fopen(path, mode);
    g_mountinfo_opens++;
    return fmemopen(g_mountinfo, g_mountinfo_len, "r");
}

int __wrap_stat(const char* path, struct stat* st) {
    for (int i = 0; i < g_stats_n; i++) {
        if (strcmp(g_stats[i].path, path) != 0) continue;
        if (g_stats[i].err) {
            errno = g_stats[i].err;
            return -1;
        }
        memset(st, 0, sizeof *st);
        st->st_dev = g_stats[i].dev;
        st->st_mode = S_IFDIR | 0755;
        return 0;
    }
    /* 合成树里没有的 /proc 路径 = 不存在；其余路径交回真实文件系统 */
    if (is_proc_path(path)) {
        errno = ENOENT;
        return -1;
    }
    return __real_stat(path, st);
}

int __wrap_statfs(const char* path, struct statfs* sfs) {
    for (int i = 0; i < g_stats_n; i++) {
        if (strcmp(g_stats[i].path, path) != 0) continue;
        if (g_stats[i].err) {
            errno = g_stats[i].err;
            return -1;
        }
        memset(sfs, 0, sizeof *sfs);
        sfs->f_type = (__fsword_t)(g_stats[i].f_type ? g_stats[i].f_type : (long)FUSE_MAGIC);
        return 0;
    }
    if (is_proc_path(path)) {
        errno = ENOENT;
        return -1;
    }
    return __real_statfs(path, sfs);
}

DIR* __wrap_opendir(const char* path) {
    for (int i = 0; i < g_dirs_n; i++) {
        if (strcmp(g_dirs[i].path, path) != 0) continue;
        if (g_dirs[i].err) {
            errno = g_dirs[i].err;
            return NULL;
        }
        g_dirs[i].cursor = 0;
        return (DIR*)(void*)&g_dirs[i];
    }
    if (is_proc_path(path)) {
        errno = ENOENT;
        return NULL;
    }
    return __real_opendir(path);
}

struct dirent* __wrap_readdir(DIR* d) {
    static struct dirent ent;
    for (int i = 0; i < g_dirs_n; i++) {
        if ((void*)d != (void*)&g_dirs[i]) continue;
        if (g_dirs[i].cursor >= g_dirs[i].n) return NULL;
        memset(&ent, 0, sizeof ent);
        snprintf(ent.d_name, sizeof ent.d_name, "%s", g_dirs[i].names[g_dirs[i].cursor++]);
        ent.d_type = DT_DIR;
        return &ent;
    }
    return __real_readdir(d);
}

int __wrap_closedir(DIR* d) {
    for (int i = 0; i < g_dirs_n; i++) {
        if ((void*)d == (void*)&g_dirs[i]) return 0;
    }
    return __real_closedir(d);
}

/* ══════════════ 外部依赖的最小桩 ══════════════ */

void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}

void log_ns_error(const char* format, ...) {
    (void)format;
}

int mkdir_recursive(const char* dir) {
    (void)dir;
    return 0;
}

int run_in_mnt_ns_timeout(int target_pid, int (*func)(void*), void* args, int* child_err,
                          int timeout_ms) {
    (void)target_pid;
    (void)func;
    (void)args;
    (void)timeout_ms;
    if (child_err) *child_err = 0;
    return -1;
}

const char* fast_strstr(const char* haystack, const char* needle) { return strstr(haystack, needle); }

/* ns_utils.c 的 statfs 判据在本驱动里的同构替身（真实现另带 nofollow 与日志），
   走上面的 __wrap_statfs，所以「这一条是不是项目 FUSE」由合成表决定。 */
bool ns_path_is_fuse_mount(const char* path) {
    struct statfs sfs;
    if (statfs(path, &sfs) != 0) return false;
    return (unsigned long)sfs.f_type == FUSE_MAGIC;
}

/* ══════════════ 实际源码 ══════════════ */

#include "ns_mountinfo.c"
#include NS_GLOBAL_REPLACE_SRC

/* ══════════════ 用例 ══════════════ */

static int g_fail;

static void check(const char* name, bool ok, const char* detail) {
    if (!ok) g_fail++;
    printf("case=%-52s ok=%d %s\n", name, ok ? 1 : 0, detail ? detail : "");
}

#define FUSE_SRC "/mnt/nsp_global"
#define RD_DEV makedev(0, 364)   /* 项目 FUSE 的 superblock */
#define SYS_DEV makedev(0, 301)  /* 系统（vold）视图的 superblock */

static void status_case(const char* name, int want, int opens_want_min, int opens_want_max) {
    char detail[160];
    int before = g_mountinfo_opens;
    int st = ns_global_status((int)getpid(), FUSE_SRC);
    int opens = g_mountinfo_opens - before;
    snprintf(detail, sizeof detail, "status=%d want=%d mountinfo_opens=%d", st, want, opens);
    check(name, st == want && opens >= opens_want_min && opens <= opens_want_max, detail);
}

int main(void) {
    char p[320];

    /* A：三族族根都是项目视图 → REPLACED，且不读 mountinfo。
       挂载表故意留空：一旦回落扫描，结论会变成 UNKNOWN，用例即失败。 */
    fs_reset();
    stat_add(rootpath(p, sizeof p, FUSE_SRC), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/user"), 0);
    dir_name("0");
    dir_name("obb"); /* 非纯数字条目：必须被忽略 */
    stat_add(rootpath(p, sizeof p, "/mnt/user/0/emulated"), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/installer"), 0);
    dir_name("0");
    stat_add(rootpath(p, sizeof p, "/mnt/installer/0/emulated"), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/androidwritable"), ENOENT); /* 该 ROM 没有这一族 */
    status_case("A1_all_roots_replaced_without_mountinfo", NSP_GLOBAL_STATUS_REPLACED, 0, 0);
    status_case("A2_repeat_same_state_still_no_mountinfo", NSP_GLOBAL_STATUS_REPLACED, 0, 0);

    /* B1：installer 族根被 vold 重挂回系统视图（dev 变了）→ 回落扫描判 MIXED */
    fs_reset();
    stat_add(rootpath(p, sizeof p, FUSE_SRC), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/user"), 0);
    dir_name("0");
    stat_add(rootpath(p, sizeof p, "/mnt/user/0/emulated"), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/installer"), 0);
    dir_name("0");
    stat_add_tmpfs(rootpath(p, sizeof p, "/mnt/installer/0/emulated"), SYS_DEV);
    dir_add(rootpath(p, sizeof p, "/mnt/androidwritable"), ENOENT);
    mi_add("0:364", FUSE_SRC, "fuse", "fuse_daemon");
    mi_add("0:364", "/mnt/user/0/emulated", "fuse", "fuse_daemon");
    mi_add("0:301", "/mnt/installer/0/emulated", "fuse", "MediaProvider");
    status_case("B1_mismatched_root_falls_back_to_scan", NSP_GLOBAL_STATUS_MIXED, 1, 1);

    /* B2：dev 恰好相同、但 fstype 不是 FUSE → 仍须回落（只比 dev 会把系统视图说成
       项目视图）。结论由挂载表给：扫描只认 dev，故这里仍是 REPLACED——要点是
       opens=1，即「没有自己下结论」 */
    fs_reset();
    stat_add(rootpath(p, sizeof p, FUSE_SRC), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/user"), 0);
    dir_name("0");
    stat_add(rootpath(p, sizeof p, "/mnt/user/0/emulated"), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/installer"), 0);
    dir_name("0");
    stat_add_tmpfs(rootpath(p, sizeof p, "/mnt/installer/0/emulated"), RD_DEV);
    dir_add(rootpath(p, sizeof p, "/mnt/androidwritable"), ENOENT);
    mi_add("0:364", FUSE_SRC, "fuse", "fuse_daemon");
    mi_add("0:364", "/mnt/user/0/emulated", "fuse", "fuse_daemon");
    mi_add("0:364", "/mnt/installer/0/emulated", "tmpfs", "nsp_vold_remount");
    status_case("B2_same_dev_but_not_fuse_falls_back", NSP_GLOBAL_STATUS_REPLACED, 1, 1);

    /* C1：源不是 FUSE（被上层挂载盖住）→ 回落扫描；挂载表里两处同为项目视图 */
    fs_reset();
    stat_add_tmpfs(rootpath(p, sizeof p, FUSE_SRC), RD_DEV);
    dir_add(rootpath(p, sizeof p, "/mnt/user"), 0);
    dir_name("0");
    stat_add(rootpath(p, sizeof p, "/mnt/user/0/emulated"), RD_DEV, 0);
    mi_add("0:364", FUSE_SRC, "fuse", "fuse_daemon");
    mi_add("0:364", "/mnt/user/0/emulated", "fuse", "fuse_daemon");
    status_case("C1_src_not_fuse_falls_back", NSP_GLOBAL_STATUS_REPLACED, 1, 1);

    /* C2：源 stat 失败且挂载表里没有源 → UNKNOWN（回落后仍不得猜 REPLACED） */
    fs_reset();
    dir_add(rootpath(p, sizeof p, "/mnt/user"), 0);
    dir_name("0");
    stat_add(rootpath(p, sizeof p, "/mnt/user/0/emulated"), RD_DEV, 0);
    status_case("C2_src_missing_is_unknown", NSP_GLOBAL_STATUS_UNKNOWN, 1, 1);

    /* D：一条族根都没有（三族目录都不存在）→ 回落扫描，空表 = UNKNOWN */
    fs_reset();
    stat_add(rootpath(p, sizeof p, FUSE_SRC), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/user"), ENOENT);
    dir_add(rootpath(p, sizeof p, "/mnt/installer"), ENOENT);
    dir_add(rootpath(p, sizeof p, "/mnt/androidwritable"), ENOENT);
    status_case("D1_no_roots_is_not_replaced", NSP_GLOBAL_STATUS_UNKNOWN, 1, 1);

    /* E：族根 stat 报 EACCES（判不了）→ 回落扫描，不猜 */
    fs_reset();
    stat_add(rootpath(p, sizeof p, FUSE_SRC), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/user"), 0);
    dir_name("0");
    stat_add(rootpath(p, sizeof p, "/mnt/user/0/emulated"), 0, EACCES);
    dir_add(rootpath(p, sizeof p, "/mnt/installer"), ENOENT);
    dir_add(rootpath(p, sizeof p, "/mnt/androidwritable"), ENOENT);
    mi_add("0:364", FUSE_SRC, "fuse", "fuse_daemon");
    mi_add("0:364", "/mnt/user/0/emulated", "fuse", "fuse_daemon");
    status_case("E1_root_stat_error_falls_back", NSP_GLOBAL_STATUS_REPLACED, 1, 1);

    /* F：多用户 —— 两个用户的族根都是项目视图 → REPLACED 且不读 mountinfo */
    fs_reset();
    stat_add(rootpath(p, sizeof p, FUSE_SRC), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/user"), 0);
    dir_name("0");
    dir_name("999");
    stat_add(rootpath(p, sizeof p, "/mnt/user/0/emulated"), RD_DEV, 0);
    stat_add(rootpath(p, sizeof p, "/mnt/user/999/emulated"), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/installer"), ENOENT);
    dir_add(rootpath(p, sizeof p, "/mnt/androidwritable"), ENOENT);
    status_case("F1_multi_user_all_replaced_no_mountinfo", NSP_GLOBAL_STATUS_REPLACED, 0, 0);

    /* F2：第二个用户还没被接管 → 回落扫描判 MIXED（漏用户就是永久跳过那一族） */
    fs_reset();
    stat_add(rootpath(p, sizeof p, FUSE_SRC), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/user"), 0);
    dir_name("0");
    dir_name("999");
    stat_add(rootpath(p, sizeof p, "/mnt/user/0/emulated"), RD_DEV, 0);
    stat_add_tmpfs(rootpath(p, sizeof p, "/mnt/user/999/emulated"), SYS_DEV);
    dir_add(rootpath(p, sizeof p, "/mnt/installer"), ENOENT);
    dir_add(rootpath(p, sizeof p, "/mnt/androidwritable"), ENOENT);
    mi_add("0:364", FUSE_SRC, "fuse", "fuse_daemon");
    mi_add("0:364", "/mnt/user/0/emulated", "fuse", "fuse_daemon");
    mi_add("0:301", "/mnt/user/999/emulated", "fuse", "MediaProvider");
    status_case("F2_new_user_root_leads_to_mixed", NSP_GLOBAL_STATUS_MIXED, 1, 1);

    /* G：某族 <uid>/emulated 还没建（ENOENT）→ 跳过，其余族根同 dev 仍判 REPLACED */
    fs_reset();
    stat_add(rootpath(p, sizeof p, FUSE_SRC), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/user"), 0);
    dir_name("0");
    stat_add(rootpath(p, sizeof p, "/mnt/user/0/emulated"), RD_DEV, 0);
    dir_add(rootpath(p, sizeof p, "/mnt/installer"), 0);
    dir_name("0");
    stat_add(rootpath(p, sizeof p, "/mnt/installer/0/emulated"), 0, ENOENT);
    dir_add(rootpath(p, sizeof p, "/mnt/androidwritable"), ENOENT);
    status_case("G1_unmounted_root_skipped", NSP_GLOBAL_STATUS_REPLACED, 0, 0);

    /* H：源与族根都还是普通 tmpfs 目录（开机早期 FUSE 没起）→ 不得判 REPLACED */
    fs_reset();
    stat_add_tmpfs(rootpath(p, sizeof p, FUSE_SRC), RD_DEV);
    dir_add(rootpath(p, sizeof p, "/mnt/user"), 0);
    dir_name("0");
    stat_add_tmpfs(rootpath(p, sizeof p, "/mnt/user/0/emulated"), RD_DEV);
    dir_add(rootpath(p, sizeof p, "/mnt/installer"), ENOENT);
    dir_add(rootpath(p, sizeof p, "/mnt/androidwritable"), ENOENT);
    status_case("H1_plain_dirs_never_replaced", NSP_GLOBAL_STATUS_UNKNOWN, 1, 1);

    /* I1：源与族根被同一个空 tmpfs 盖住（共享挂载组上的挂载会传播）→ 两边 dev 相等，
       快查不得据此下结论，必须回落；结论仍由挂载表给（dev 相等 ⇒ REPLACED，与旧实现
       一致，差别只在「是谁判的」） */
    fs_reset();
    stat_add_tmpfs(rootpath(p, sizeof p, FUSE_SRC), RD_DEV);
    dir_add(rootpath(p, sizeof p, "/mnt/user"), 0);
    dir_name("0");
    stat_add_tmpfs(rootpath(p, sizeof p, "/mnt/user/0/emulated"), RD_DEV);
    dir_add(rootpath(p, sizeof p, "/mnt/installer"), ENOENT);
    dir_add(rootpath(p, sizeof p, "/mnt/androidwritable"), ENOENT);
    mi_add("0:364", FUSE_SRC, "tmpfs", "nsp_vold_remount");
    mi_add("0:364", "/mnt/user/0/emulated", "tmpfs", "nsp_vold_remount");
    status_case("I1_env_covered_by_tmpfs_falls_back", NSP_GLOBAL_STATUS_REPLACED, 1, 1);

    /* I2：同一局面但挂载表证明两处仍是项目视图（只是被同 dev 的 tmpfs 短暂盖住又恢复） */
    fs_reset();
    stat_add_tmpfs(rootpath(p, sizeof p, FUSE_SRC), RD_DEV);
    dir_add(rootpath(p, sizeof p, "/mnt/user"), 0);
    dir_name("0");
    stat_add_tmpfs(rootpath(p, sizeof p, "/mnt/user/0/emulated"), RD_DEV);
    dir_add(rootpath(p, sizeof p, "/mnt/installer"), ENOENT);
    dir_add(rootpath(p, sizeof p, "/mnt/androidwritable"), ENOENT);
    mi_add("0:364", FUSE_SRC, "fuse", "fuse_daemon");
    mi_add("0:364", "/mnt/user/0/emulated", "fuse", "fuse_daemon");
    status_case("I2_covered_but_table_says_fuse", NSP_GLOBAL_STATUS_REPLACED, 1, 1);

    printf(g_fail == 0 ? "===== grepl status fast driver: all cases passed =====\n"
                       : "===== grepl status fast driver: %d case(s) failed =====\n",
           g_fail);
    return g_fail == 0 ? 0 : 1;
}
