/* SPDX-License-Identifier: GPL-3.0-or-later */
/* inject_target_tracked_race_driver.c — A25「追踪表无锁遍历」判别驱动
 *
 * 直编 src/injector/inject_target.c（其余依赖以桩替代），在 ASan 下断言：
 * `audit_tracked_apps()` / `audit_and_remount_specific_apps()` /
 * `force_recover_tracked_mounts()` 遍历 `g_tracked_hash` 期间，若另一条路径
 * 并发摘除节点，遍历**不得触碰已释放内存**。
 *
 * 注入窗口（两个钩子，各自覆盖一条遍历路径）：
 *   - `proc_get_cmdline` 桩：audit_* 两条路径每访问一个节点先调它；
 *   - `--wrap=kill` 包装：force_recover 每访问一个节点先调 `kill(pid,0)`。
 * 钩子在第 N 次调用时 `remove_tracked(先前已访问过的节点)`——这正是旧实现最
 * 脆的时序：外层游标 `pp`/`e` 此刻正指向那个节点的 `next` 字段，节点一释放，
 * `pp = &(*pp)->next` 读到的是**悬垂地址**，下一次迭代 `(*pp)->pid` 即
 * heap-use-after-free（ASan 必报）。新实现先在锁内把 pid 快照出来、锁外处理，
 * 遍历与链表增删完全解耦 → 无报告，且摘除照常生效。
 *
 * 假 pid 用 2048 取模同桶（`hash_pid = pid % TRACKED_HASH_SIZE`），`add_tracked`
 * 头插故先加 A 后加 B 得链 B → A（B 先被访问）。
 *
 * 编译：见 tests/test_inject_tracked_race.py
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config_parser.h"
#include "fast_pid.h"
#include "inject_target.h"
#include "injector.h"
#include "mount_manager.h"
#include "ns_utils.h"
#include "nsp_log.h"
#include "sys_pkg.h"
#include "uid_map.h"

/* ================= 框架桩：仅为让 inject_target.c 独立链接 =================
   取值一律「不构成目标应用」（无应用段、无类别段、无通配、全局注入关），
   使被测遍历逻辑走最简分支，不被挂载动作干扰。 */
AppConfig g_global_cfg;
int g_active_user_count;
int g_active_users[MAX_USERS];
InjectMethod g_inject_method = INJECT_METHOD_V1;

void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}

void config_lock_read(void) {}
void config_unlock_read(void) {}
AppConfig* find_app_cfg_locked(const char* pkg, int user_id) {
    (void)pkg;
    (void)user_id;
    return NULL;
}
AppConfig* find_category_cfg_locked(bool is_system_app, int user_id) {
    (void)is_system_app;
    (void)user_id;
    return NULL;
}
bool category_has_rules_locked(bool is_system_app, int user_id) {
    (void)is_system_app;
    (void)user_id;
    return false;
}
bool has_wildcard_enabled_locked(int user_id) {
    (void)user_id;
    return false;
}

bool is_project_fuse_cached(int pid, const char* target_path) {
    (void)pid;
    (void)target_path;
    return false;
}
const char* get_active_mnt_src(void) { return NULL; }
int perform_app_mount(const char* pkg, int pid, uid_t uid, const char* mnt_src,
                      const char* trigger) {
    (void)pkg;
    (void)pid;
    (void)uid;
    (void)mnt_src;
    (void)trigger;
    return 0;
}
int perform_app_restore(const char* pkg, int pid, uid_t uid) {
    (void)pkg;
    (void)pid;
    (void)uid;
    return 0;
}

int ns_bind_mount(int pid, const char* source, const char* target) {
    (void)pid;
    (void)source;
    (void)target;
    return 0;
}
int ns_bind_mount_cross(int pid, const char* source, const char* target) {
    (void)pid;
    (void)source;
    (void)target;
    return 0;
}
int ns_find_family_root(int pid, uid_t app_uid, char* out, size_t outsz) {
    (void)pid;
    (void)app_uid;
    (void)out;
    (void)outsz;
    return -1;
}
int ns_is_mounted(int pid, const char* target_mount, const char* match_fs_name) {
    (void)pid;
    (void)target_mount;
    (void)match_fs_name;
    return 0;
}
int ns_umount_recursive(int pid, const char* target) {
    (void)pid;
    (void)target;
    return 0;
}

void sys_pkg_init(bool allow_pm) { (void)allow_pm; }
void sys_pkg_cleanup(void) {}
bool sys_pkg_is_system(const char* pkg) {
    (void)pkg;
    return false;
}

int uid_map_load(UidMapEntry* entries, int max_entries) {
    (void)entries;
    (void)max_entries;
    return 0;
}
int uid_map_upsert(uid_t uid, const char* pkg) {
    (void)uid;
    (void)pkg;
    return 0;
}

/* ================= 并发变更注入窗口 ================= */

static int g_hook_count;
static int g_hook_at;      /* 第几次钩子调用时触发（0 = 关闭） */
static int g_victim_pid;   /* 那一刻摘除的 pid（须是**已访问过**的节点） */
static int g_hook_from_kill; /* 0 = 只从 proc_get_cmdline 钩；1 = 只从 kill 钩 */

/* 注意：**不能**让两个钩子共用计数。`prune_stale_tracked()` 是在持有
   g_tracked_mutex 的临界区内调 kill(pid,0) 的——若 kill 钩子在此触发
   remove_tracked，就会在同一非递归互斥量上自锁（用例挂死，而非暴露缺陷）。
   故按路径选择钩子来源，另一来源只透传。 */
static void maybe_mutate(int from_kill) {
    if (g_hook_at <= 0 || from_kill != g_hook_from_kill) return;
    if (++g_hook_count != g_hook_at) return;
    remove_tracked(g_victim_pid); /* 与遍历并发摘链：旧实现的 UAF 窗口 */
}

bool proc_get_cmdline(int pid, char* buf, size_t size) {
    maybe_mutate(0);
    if (!buf || size == 0) return false;
    /* 假 pid 一律给一个非空、非 zygote 的 cmdline，让 audit 走「存活」分支 */
    snprintf(buf, size, "com.nsp.race%d", pid);
    return true;
}

int __real_kill(pid_t pid, int sig);
int __wrap_kill(pid_t pid, int sig) {
    if (sig == 0) {
        maybe_mutate(1);
        return 0; /* 假 pid 一律视为存活 */
    }
    return __real_kill(pid, sig);
}

/* ================= 用例 ================= */

#define TRACK_BUCKETS 2048 /* 与 inject_target.c 的 TRACKED_HASH_SIZE 一致 */
#define PID_A (TRACK_BUCKETS * 3 + 7)
#define PID_B (TRACK_BUCKETS * 9 + 7) /* 与 A 同桶，且后加入 → 链首 */
#define PID_C (TRACK_BUCKETS * 11 + 7)

static int g_fail;

static void ck(bool cond, const char* what, const char* detail) {
    printf("%s %s%s%s\n", cond ? "PASS" : "FAIL", what, cond ? "" : ": ",
           cond ? "" : (detail ? detail : ""));
    if (!cond) g_fail = 1;
}

static void reset_hook(int at, int victim, int from_kill) {
    g_hook_count = 0;
    g_hook_at = at;
    g_victim_pid = victim;
    g_hook_from_kill = from_kill;
}

static void clear_tracked(void) {
    g_hook_at = 0;                  /* 清表动作本身不得触发窗口 */
    force_recover_tracked_mounts(); /* 顺带清空追踪表 */
    g_hook_at = 0;
}

/* 窗口时序（链 B → A，B 先被访问）：
 *   audit_* 的外层游标是**槽指针** `pp`：第 1 轮结束时 `pp = &B->next`，
 *     故必须在**第 2 轮**（pid=A）摘掉 **B** —— B 一释放，`pp` 就指进已释放
 *     节点内部，`pp = &(*pp)->next` 即 UAF 读。
 *   force_recover 的游标是**节点指针** `e`：第 2 轮 `e = A`，故在第 2 次
 *     `kill(pid,0)`（pid=A）时摘掉 **A**，随后 `e = e->next` 读已释放的 A。 */
#define HOOK_AT 2

/* A. audit_tracked_apps：第 2 轮摘掉上一轮游标所依赖的 B → 旧实现 UAF */
static void case_audit(void) {
    clear_tracked();
    add_tracked(PID_A); /* 先 A 后 B：头插得链 B → A，B 先被访问 */
    add_tracked(PID_B);
    ck(is_tracked(PID_A) && is_tracked(PID_B), "前置：A/B 均入追踪表", nullptr);

    reset_hook(HOOK_AT, PID_B, 0); /* 第 2 次 proc_get_cmdline（= pid A）时摘 B */
    audit_tracked_apps();
    g_hook_at = 0;

    ck(true, "audit_tracked_apps 并发摘链未触碰已释放内存", nullptr);
    ck(!is_tracked(PID_B), "被并发摘除的节点确实已摘除", "B 仍在表内");
    ck(is_tracked(PID_A), "存活节点保留（不因并发摘除被误删）", "A 被误删");
}

/* B. audit_and_remount_specific_apps：同窗口，另一条遍历路径 */
static void case_remount(void) {
    clear_tracked();
    add_tracked(PID_A);
    add_tracked(PID_B);

    ChangedPkg chg;
    snprintf(chg.pkg_name, sizeof chg.pkg_name, "com.nsp.race%d", PID_A);
    chg.user_id = -1;

    reset_hook(HOOK_AT, PID_B, 0);
    audit_and_remount_specific_apps(&chg, 1);
    g_hook_at = 0;

    ck(true, "audit_and_remount_specific_apps 并发摘链未触碰已释放内存", nullptr);
    ck(!is_tracked(PID_B), "被并发摘除的节点确实已摘除", "B 仍在表内");
}

/* C. force_recover_tracked_mounts：钩子换成 kill(pid,0)（该路径不查 cmdline） */
static void case_force_recover(void) {
    clear_tracked();
    add_tracked(PID_A);
    add_tracked(PID_B);

    reset_hook(HOOK_AT, PID_A, 1); /* 第 2 次 kill(pid,0)（= pid A）时摘 A */
    force_recover_tracked_mounts();
    g_hook_at = 0;

    ck(true, "force_recover_tracked_mounts 并发摘链未触碰已释放内存", nullptr);
    ck(!is_tracked(PID_A) && !is_tracked(PID_B), "收尾整表清空", "仍有残留节点");
}

/* D. 对照：无并发变更时三条路径都不得丢节点（证明用例不是靠"删干净"通过） */
static void case_no_race(void) {
    clear_tracked();
    add_tracked(PID_A);
    add_tracked(PID_B);
    add_tracked(PID_C);

    reset_hook(0, 0, 0);
    audit_tracked_apps();
    ck(is_tracked(PID_A) && is_tracked(PID_B) && is_tracked(PID_C),
       "对照：无并发变更时 audit 不丢节点", "有节点被误删");

    ChangedPkg chg;
    snprintf(chg.pkg_name, sizeof chg.pkg_name, "com.nsp.nonexistent");
    chg.user_id = -1;
    audit_and_remount_specific_apps(&chg, 1);
    ck(is_tracked(PID_A) && is_tracked(PID_B) && is_tracked(PID_C),
       "对照：无并发变更时 remount 不丢节点", "有节点被误删");
}

int main(void) {
    /* 无缓冲：驱动被超时杀掉时也要能看清挂在哪一步（重定向到文件时
       默认全缓冲会把已打印的 PASS 行一起丢掉） */
    setvbuf(stdout, nullptr, _IONBF, 0);
    case_audit();
    case_remount();
    case_force_recover();
    case_no_race();
    printf("%s\n", g_fail ? "RESULT FAIL" : "RESULT OK");
    return g_fail;
}
