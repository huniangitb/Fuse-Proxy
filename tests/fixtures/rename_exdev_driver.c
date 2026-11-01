/*
 * tests/fixtures/rename_exdev_driver.c
 *
 * vfs_rename() 跨设备（EXDEV）回退路径的判别驱动：非空目标不得被预删（R1）、
 * 临时名不可预测且创建失败闭合（R2）。
 *
 * 做法：由 tests/test_functional.py 从**实际源码** src/daemon/fuse_daemon.c 里
 * 逐字抽出 recursive_rmdir / recursive_copy_dir / vfs_rename_copy_file /
 * xdev_temp_name / vfs_rename 五个函数，填进下面的
 * __NSP_EXTRACTED_FUNCTIONS__ 占位处再与桩一起编译（-Wl,--wrap=rename
 * 让第一次 rename 强制返回 EXDEV，从而进入跨设备回退）。全路径走真实实现。
 * 可用 FUSE_DAEMON_SRC=<旧源码副本> 让同一驱动在旧实现上复现失败（判别性）。
 *
 * 用例（argv[1]）：
 *   nonempty     目录搬移，目标是非空目录 → ENOTEMPTY，目标子树逐字节保留，
 *                源树保留，父目录无 .nsp_xdev_* 残留。
 *                旧实现 recursive_rmdir(p_to) 删掉目标整棵树并返回 0 → 必失败。
 *   file_over_dir 普通文件搬移，目标是非空目录 → EISDIR，目标子树保留，
 *                源文件保留。旧实现同样先删目标再成功 → 必失败。
 *   symlink      目标不存在，但按旧实现的**可预测临时名**（<p_to>.nsp_xdev_<pid>）
 *                预置符号链接指向受害者文件 → 受害者内容不变、目标不是符号
 *                链接、搬移本身正常完成（源内容落位、源已删）。
 *                旧实现 open(tmp, O_TRUNC) 跟随链接把源内容写进受害者，
 *                随后把符号链接 rename 到目标（rc=0，sentinel=SOURCE，
 *                destination_is_symlink=1）→ 必失败。
 *   plain        正对照：不强制 EXDEV，普通 rename 仍成功（不得被回退路径
 *                的新检查挡住）。
 *
 * 退出码：0 = 全部断言通过；1 = 有失败（逐条打印 RESULT ...）。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define FUSE_USE_VERSION 317
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <fuse3/fuse.h>

#include "fw_acl.h"
#include "fw_events.h"
#include "fw_rules.h"
#include "module_loader.h"

/* ---- 事件通道桩：本驱动只判 rename 的 EXDEV 语义，事件侧一律关闭 ----
   开关恒为 false（fw_events_active() 直接返回 false），但 vfs_rename 里那次
   调用在链接期仍需要一个符号，故给出最小实现。 */
_Atomic bool g_fw_events_hot = false;
void fw_events_note_write_done(uid_t uid, pid_t pid, const char* fuse_path, FwEventOp op,
                               const char* src_fuse) {
    (void)uid;
    (void)pid;
    (void)fuse_path;
    (void)op;
    (void)src_fuse;
}

#define NSP_FH_HANDLE_MASK ((1ULL << 40) - 1)
#define VFS_OP_MUTATE 1

/* ---- 日志：驱动里不落盘，只保留调用点 ---- */
#define LOG_ERR(...) ((void)0)
#define LOG_WRN(...) ((void)0)
#define LOG_DBG(...) ((void)0)

/* vfs_rename 内的本地 open-unlink 快照钩子：本驱动不涉及打开中删除，空实现 */
static void hidden_stat_put(const char* path, const struct stat* st) {
    (void)path;
    (void)st;
}
static void hidden_stat_remove(const char* path) { (void)path; }
static bool hidden_stat_get(const char* path, struct stat* st) {
    (void)path;
    (void)st;
    return false;
}
static void hidden_stat_refresh(const char* path, int fd) {
    (void)path;
    (void)fd;
}
static void log_fuse_err(const char* a, const char* b, int c) {
    (void)a;
    (void)b;
    (void)c;
}
/* open-unlink 直删的观测口（框架侧限速日志，见 fuse_daemon.c 的同名函数）：
   本驱动不考观测行为，与 log_fuse_err 同样桩掉——桩存在时旧源码副本
   （没有该函数）与新源码都能编过，判别性不受影响 */
static void log_open_unlink_direct(const char* path) { (void)path; }

/* ---- FUSE 上下文与路由：驱动直调 vfs_rename，路由恒直通 ---- */
static struct fuse_context g_ctx;
struct fuse_context* fuse_get_context(void) { return &g_ctx; }

static int fw_route(struct fuse_context* c, const char* path, NspPathDecision* r, bool* ok,
                    char* pkg, int* u, char* sub, char* real, bool* redir, bool* mon, int op,
                    NspAclOp acl_op, bool acl_is_dir, int acl_mask) {
    (void)c;
    (void)op;
    (void)acl_op;
    (void)acl_is_dir;
    (void)acl_mask;
    memset(r, 0, sizeof(*r));
    *ok = false;
    *u = 0;
    *redir = false;
    *mon = false;
    strcpy(pkg, "test");
    strcpy(sub, path);
    strcpy(real, path);
    return 0;
}

static void vfs_log_io(const char* a, uid_t b, const char* c, const char* d, const char* e,
                       bool f) {
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
    (void)f;
}

/* ---- 模块层：恒不命中后端（本驱动只测本地 EXDEV 回退） ---- */
int module_backend_lookup(const char* p, const NspModuleOps** out) {
    (void)p;
    (void)out;
    return -1;
}
void module_backend_put(const NspModuleOps* p) { (void)p; }
int module_ops_slot(const NspModuleOps* p) {
    (void)p;
    return 0;
}
int nsp_fence_backend_rename(int a, const char* b, int (*f)(const char*, const char*), const char* c,
                             const char* d) {
    (void)a;
    (void)b;
    (void)f;
    (void)c;
    (void)d;
    return 0;
}
void module_guard_fault(int a, const char* b, const char* c) {
    (void)a;
    (void)b;
    (void)c;
}
void module_guard_error(int a, const char* b, int c, const char* d, const char* e) {
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
}
#define NSP_FENCE_FAULT (-5000)
#define NSP_FENCE_BADFN (-5001)
static bool backend_rc_is_business(int rc) { return rc < 0 && rc >= -4095; }

/* 目标父目录恒存在（驱动自建），此桩不做任何事 */
static int mkdir_recursive_p(const char* p, mode_t m) {
    (void)p;
    (void)m;
    return 0;
}
/* 父目录补建出口（实际实现见 src/core/common.c；vfs_rename 自「存储根一级条目
   守卫」起改经此出口）：目标父目录恒存在，此桩同样不做任何事。守卫语义本身由
   test_storage_root_guard.py 覆盖，这里只需让被测 rename 逻辑可编译运行。 */
int common_mkdir_within_storage(const char* p, mode_t m) {
    (void)p;
    (void)m;
    return 0;
}

/* ---- --wrap=rename：第一次调用强制 EXDEV，进入跨设备回退 ---- */
static int g_force_exdev;
int __real_rename(const char*, const char*);
int __wrap_rename(const char* a, const char* b) {
    if (g_force_exdev) {
        g_force_exdev = 0;
        errno = EXDEV;
        return -1;
    }
    return __real_rename(a, b);
}

/* ══════════ 以下由 test_functional.py 从实际源码逐字填入 ══════════ */
/*__NSP_EXTRACTED_FUNCTIONS__*/

/* ══════════════════════════ 断言辅助 ══════════════════════════ */
static int g_fail;
static const char* g_case = "";

static void bad(const char* what, const char* detail) {
    g_fail++;
    printf("RESULT %s FAIL: %s (%s)\n", g_case, what, detail ? detail : "");
}

static void expect_int(const char* what, long got, long want) {
    if (got != want) {
        char d[128];
        snprintf(d, sizeof d, "got=%ld want=%ld", got, want);
        bad(what, d);
    }
}

static void expect_true(const char* what, bool cond, const char* detail) {
    if (!cond) bad(what, detail);
}

static void seed(const char* path, const char* text) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        perror(path);
        exit(2);
    }
    if (write(fd, text, strlen(text)) != (ssize_t)strlen(text)) exit(2);
    close(fd);
}

/* 读取文本；不存在写 "MISSING"，读取失败写 "ERROR" */
static void slurp(const char* path, char* buf, size_t sz) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        snprintf(buf, sz, "%s", errno == ENOENT ? "MISSING" : "ERROR");
        return;
    }
    ssize_t n = read(fd, buf, sz - 1);
    if (n < 0) n = 0;
    buf[n] = '\0';
    close(fd);
}

static void join(char* out, size_t sz, const char* base, const char* name) {
    snprintf(out, sz, "%s/%s", base, name);
}

/* 父目录里是否残留本次搬移的临时产物（.nsp_xdev_*） */
static int count_xdev_residue(const char* dir) {
    DIR* d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent* p;
    while ((p = readdir(d))) {
        if (strcmp(p->d_name, ".") == 0 || strcmp(p->d_name, "..") == 0) continue;
        if (strstr(p->d_name, ".nsp_xdev_")) n++;
    }
    closedir(d);
    return n;
}

static int dir_entry_count(const char* dir) {
    DIR* d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent* p;
    while ((p = readdir(d))) {
        if (strcmp(p->d_name, ".") == 0 || strcmp(p->d_name, "..") == 0) continue;
        n++;
    }
    closedir(d);
    return n;
}

/* ══════════════════════════ 用例 ══════════════════════════ */
/* 目录搬移撞上非空目标：ENOTEMPTY + 两侧原样（R1） */
static void case_nonempty(const char* stage) {
    char src[PATH_MAX], dst[PATH_MAX], p[PATH_MAX], buf[256];
    join(src, sizeof src, stage, "source_dir");
    mkdir(src, 0700);
    join(p, sizeof p, src, "new");
    seed(p, "NEW");
    join(dst, sizeof dst, stage, "dest_dir");
    mkdir(dst, 0700);
    join(p, sizeof p, dst, "keep");
    seed(p, "KEEP");

    g_force_exdev = 1;
    int rc = vfs_rename(src, dst, 0);
    expect_int("非空目标返回 ENOTEMPTY", rc, -ENOTEMPTY);

    join(p, sizeof p, dst, "keep");
    slurp(p, buf, sizeof buf);
    expect_true("目标子树逐字节保留", strcmp(buf, "KEEP") == 0, buf);
    expect_int("目标目录条目数不变（未被预删/未留残留）", dir_entry_count(dst), 1);

    join(p, sizeof p, src, "new");
    slurp(p, buf, sizeof buf);
    expect_true("源树保留", strcmp(buf, "NEW") == 0, buf);

    expect_int("父目录无 .nsp_xdev_* 残留（本次临时产物已清理）", count_xdev_residue(stage), 0);
}

/* 普通文件搬移撞上非空目录：EISDIR + 两侧原样（R1 同族） */
static void case_file_over_dir(const char* stage) {
    char src[PATH_MAX], dst[PATH_MAX], p[PATH_MAX], buf[256];
    join(src, sizeof src, stage, "source_file");
    seed(src, "SOURCE");
    join(dst, sizeof dst, stage, "dest_dir2");
    mkdir(dst, 0700);
    join(p, sizeof p, dst, "keep");
    seed(p, "KEEP");

    g_force_exdev = 1;
    int rc = vfs_rename(src, dst, 0);
    expect_int("文件撞非空目录返回 EISDIR", rc, -EISDIR);

    join(p, sizeof p, dst, "keep");
    slurp(p, buf, sizeof buf);
    expect_true("目标子树逐字节保留", strcmp(buf, "KEEP") == 0, buf);
    expect_int("目标目录条目数不变", dir_entry_count(dst), 1);

    slurp(src, buf, sizeof buf);
    expect_true("源文件保留", strcmp(buf, "SOURCE") == 0, buf);
    expect_int("父目录无 .nsp_xdev_* 残留", count_xdev_residue(stage), 0);
}

/* 预置旧实现的可预测临时名符号链接：绝不跟随（R2） */
static void case_symlink(const char* stage) {
    char src[PATH_MAX], dst[PATH_MAX], victim[PATH_MAX], legacy[PATH_MAX], buf[256];
    struct stat st;
    join(src, sizeof src, stage, "source_link_file");
    seed(src, "SOURCE");
    join(victim, sizeof victim, stage, "sentinel");
    seed(victim, "SENTINEL");
    join(dst, sizeof dst, stage, "dest_link_file");
    /* 旧实现临时名 = <p_to>.nsp_xdev_<pid>（可预测），攻击者据此预置链接 */
    snprintf(legacy, sizeof legacy, "%s.nsp_xdev_%ld", dst, (long)getpid());
    unlink(legacy);
    if (symlink(victim, legacy) != 0) {
        perror("symlink");
        exit(2);
    }

    g_force_exdev = 1;
    int rc = vfs_rename(src, dst, 0);

    slurp(victim, buf, sizeof buf);
    expect_true("受害者文件内容不变（未跟随符号链接写入）", strcmp(buf, "SENTINEL") == 0, buf);
    if (lstat(dst, &st) != 0) {
        bad("目标应已就位为普通文件", "lstat 失败");
    } else {
        expect_true("目标不是符号链接", !S_ISLNK(st.st_mode), "目标仍是符号链接");
        expect_true("目标是普通文件", S_ISREG(st.st_mode), "目标类型异常");
    }
    slurp(dst, buf, sizeof buf);
    expect_true("源内容已搬到目标", strcmp(buf, "SOURCE") == 0, buf);
    expect_int("搬移成功（受害者未受影响，操作本身合法）", rc, 0);
    expect_true("源已删除", access(src, F_OK) != 0, "源仍存在");
}

/* 正对照：不强制 EXDEV 时普通 rename 仍成功 */
static void case_plain(const char* stage) {
    char src[PATH_MAX], dst[PATH_MAX], buf[256];
    join(src, sizeof src, stage, "plain_src");
    seed(src, "PLAIN");
    join(dst, sizeof dst, stage, "plain_dst");
    unlink(dst);
    g_force_exdev = 0;
    int rc = vfs_rename(src, dst, 0);
    expect_int("普通 rename 成功", rc, 0);
    slurp(dst, buf, sizeof buf);
    expect_true("普通 rename 内容正确", strcmp(buf, "PLAIN") == 0, buf);
    expect_true("普通 rename 源已删除", access(src, F_OK) != 0, "源仍存在");
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "用法: %s <case> <stage-dir>\n", argv[0]);
        return 2;
    }
    g_case = argv[1];
    g_ctx.uid = getuid();
    g_ctx.gid = getgid();
    const char* stage = argv[2];

    if (strcmp(g_case, "nonempty") == 0)
        case_nonempty(stage);
    else if (strcmp(g_case, "file_over_dir") == 0)
        case_file_over_dir(stage);
    else if (strcmp(g_case, "symlink") == 0)
        case_symlink(stage);
    else if (strcmp(g_case, "plain") == 0)
        case_plain(stage);
    else {
        fprintf(stderr, "未知用例: %s\n", g_case);
        return 2;
    }

    if (g_fail == 0) {
        printf("RESULT %s OK\n", g_case);
        return 0;
    }
    return 1;
}
