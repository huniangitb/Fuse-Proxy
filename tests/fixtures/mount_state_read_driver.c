/*
 * tests/fixtures/mount_state_read_driver.c
 *
 * 挂载状态读取（src/injector/mount_manager.c 的 read_mount_state）的「未知 vs
 * 没有挂载」判据驱动。
 *
 * 做法：把实际源码 mount_manager.c 整体 #include 进本 TU（同 TU 内 static 的
 * read_mount_state 直接可调），把它依赖的外部事实源（探测原语、配置、进程表、
 * 挂载原语）全部换成最小桩；读取内容由 read_file_dynamic 桩按用例喂合成
 * mountinfo。判定逻辑、字段解析、快路径回退全走真实实现。
 *
 * 覆盖：
 *   A. 读取失败 → read_mount_state 返回 false = **结论未知**；对照组 B 证明「读到
 *      了、但目标没挂」是 true + target_is_mounted=false —— 两者必须可区分，
 *      因为把「不知道」当成「没挂载」会让调用方在活着的视图上再挂一层。
 *   C. 目标排在第 5000 行（远超旧上限 4096 的规模）：整文件读取无上限，末行的
 *      目标照样被看见。
 *   D. 读取一律按不设上限（max_size=0）发起：任何固定上限都会在条目多的命名空间
 *      里把目标行截掉。
 *
 * 判别性：把 read_file_dynamic 的 max_size 换成固定上限，C 在超过该上限时失败；
 * 把读取失败当成「没有挂载」（返回 true 且标志清零）会让 A 失败。
 *
 * 退出码：全部通过 0，任一失败 1。
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
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "config_parser.h"
#include "fast_pid.h"
#include "fast_search.h"
#include "inject_target.h"
#include "injector.h"
#include "mount_manager.h"
#include "nsp_log.h"
#include "ns_utils.h"
#include "sys_pkg.h"

/* ══════════════ 可控事实源 ══════════════ */

static char g_mountinfo[4u << 20];
static size_t g_mountinfo_len;
static bool g_read_fails;
static size_t g_read_max_size_seen = (size_t)-1;
static int g_probe_rc = -1; /* 默认让快路径「探测不了」，强制走整文件扫描 */

static void mi_reset(void) {
    g_mountinfo_len = 0;
    g_mountinfo[0] = '\0';
    g_read_fails = false;
    g_read_max_size_seen = (size_t)-1;
}

static void mi_add(const char* dev, const char* mount_point) {
    char line[512];
    int n = snprintf(line, sizeof line, "600 599 %s / %s rw,nosuid shared:9 - fuse fuse_daemon rw\n",
                     dev, mount_point);
    if (n <= 0 || g_mountinfo_len + (size_t)n >= sizeof g_mountinfo) return;
    memcpy(g_mountinfo + g_mountinfo_len, line, (size_t)n);
    g_mountinfo_len += (size_t)n;
    g_mountinfo[g_mountinfo_len] = '\0';
}

/* ══════════════ 实际源码 ══════════════ */

#include "mount_manager.c"

/* ══════════════ 外部依赖的最小桩 ══════════════ */

char* read_file_dynamic(const char* path, size_t* out_size, size_t max_size) {
    (void)path;
    g_read_max_size_seen = max_size;
    if (g_read_fails) {
        errno = EACCES;
        return nullptr;
    }
    char* copy = malloc(g_mountinfo_len + 1);
    if (!copy) return nullptr;
    memcpy(copy, g_mountinfo, g_mountinfo_len);
    copy[g_mountinfo_len] = '\0';
    if (out_size) *out_size = g_mountinfo_len;
    return copy;
}

int ns_probe_target_view(int pid, const char* path, const char* src, bool* is_mount, bool* is_ours) {
    (void)pid;
    (void)path;
    (void)src;
    if (is_mount) *is_mount = false;
    if (is_ours) *is_ours = false;
    return g_probe_rc;
}

const char* get_active_mnt_src(void) { return "/mnt/nsp_global"; }
const char* get_media_mnt_src(void) { return "/mnt/nsp_media"; }

bool ns_mount_needs_repair(int pid, const char* mount_point, bool has_project_fuse) {
    (void)pid;
    (void)mount_point;
    (void)has_project_fuse;
    return false;
}

int ns_bind_mount(int pid, const char* source, const char* target) {
    (void)pid;
    (void)source;
    (void)target;
    return 0;
}

int ns_umount_recursive(int pid, const char* target) {
    (void)pid;
    (void)target;
    return 0;
}

int ns_find_native_submounts(int pid, const char* base_path, char mount_points[][256],
                             int max_count) {
    (void)pid;
    (void)base_path;
    (void)mount_points;
    (void)max_count;
    return 0;
}

int ns_combined_mount(int pid, const char* pkg, const char* source, const char* target,
                      const char* backup, char preserve_paths[][256], int preserve_count,
                      int readiness_ms) {
    (void)pid;
    (void)pkg;
    (void)source;
    (void)target;
    (void)backup;
    (void)preserve_paths;
    (void)preserve_count;
    (void)readiness_ms;
    return 0;
}

int ns_combined_mount_async(int pid, const char* pkg, const char* source, const char* target,
                            const char* backup, char preserve_paths[][256], int preserve_count) {
    (void)pid;
    (void)pkg;
    (void)source;
    (void)target;
    (void)backup;
    (void)preserve_paths;
    (void)preserve_count;
    return 0;
}

int ns_restore_app_fuse(int app_pid, const char* fuse_src, const char* backup_root, int user_id) {
    (void)app_pid;
    (void)fuse_src;
    (void)backup_root;
    (void)user_id;
    return 0;
}

void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}

void print_active_rules(const char* pkg, int pid, uid_t uid, const char* trigger_source) {
    (void)pkg;
    (void)pid;
    (void)uid;
    (void)trigger_source;
}

void config_lock_read(void) {}
void config_unlock_read(void) {}

AppConfig* find_app_cfg_locked(const char* pkg, int user_id) {
    (void)pkg;
    (void)user_id;
    return nullptr;
}

bool category_has_rules_locked(bool is_system_app, int user_id) {
    (void)is_system_app;
    (void)user_id;
    return false;
}

AppConfig g_global_cfg;
InjectMethod g_inject_method = INJECT_METHOD_V1;

bool is_media_provider(const char* pkg) {
    (void)pkg;
    return false;
}

bool sys_pkg_is_system(const char* pkg) {
    (void)pkg;
    return false;
}

bool is_process_safe_to_inject(const char* cmdline) {
    (void)cmdline;
    return false;
}

bool is_target_app(const char* cmdline, uid_t uid, pid_t pid, bool from_ipc) {
    (void)cmdline;
    (void)uid;
    (void)pid;
    (void)from_ipc;
    return false;
}

uid_t get_app_uid(int pid) {
    (void)pid;
    return 10123;
}

void update_uid_map(uid_t uid, const char* pkg) {
    (void)uid;
    (void)pkg;
}

void get_target_storage_path(uid_t uid, char* path, size_t size) {
    (void)uid;
    if (path && size) snprintf(path, size, "/storage/emulated/0");
}

void add_tracked(int pid) { (void)pid; }
void mark_injected(int pid) { (void)pid; }
void unmark_injected(int pid) { (void)pid; }

void cleanup_app_mounts(int pid, const char* target_path, const char* backup_path, uid_t uid) {
    (void)pid;
    (void)target_path;
    (void)backup_path;
    (void)uid;
}

void fast_pid_each(pid_callback_t callback, void* data) {
    (void)callback;
    (void)data;
}

const char* fast_strstr(const char* haystack, const char* needle) { return strstr(haystack, needle); }

/* ══════════════ 用例 ══════════════ */

static int g_fail;
static const char* TARGET = "/storage/emulated/0";

static void check(const char* name, bool ok, const char* detail) {
    if (!ok) g_fail++;
    printf("case=%-52s ok=%d %s\n", name, ok ? 1 : 0, detail ? detail : "");
}

int main(void) {
    MountState st;
    char detail[160];

    /* A：读取失败 = 未知（返回 false），不是「读到没有挂载」 */
    mi_reset();
    g_read_fails = true;
    bool ok = read_mount_state((int)getpid(), TARGET, "", &st);
    snprintf(detail, sizeof detail, "ok=%d", ok ? 1 : 0);
    check("A1_read_failure_is_unknown", !ok, detail);

    /* B：对照组——读到了，但目标不是挂载点：结论确定，与 A 可区分 */
    mi_reset();
    mi_add("0:364", "/mnt/nsp_global");
    mi_add("0:999", "/data");
    ok = read_mount_state((int)getpid(), TARGET, "", &st);
    snprintf(detail, sizeof detail, "ok=%d mounted=%d", ok ? 1 : 0, st.target_is_mounted ? 1 : 0);
    check("B1_success_without_target_is_definite", ok && !st.target_is_mounted, detail);

    /* C：目标排在 5000 行之后——读取无上限，末行照样被看见 */
    mi_reset();
    mi_add("0:364", "/mnt/nsp_global");
    for (int i = 0; i < 4998; i++) {
        char mp[96];
        snprintf(mp, sizeof mp, "/apex/com.android.filler%d", i);
        mi_add("7:77", mp);
    }
    mi_add("0:364", TARGET);
    ok = read_mount_state((int)getpid(), TARGET, "", &st);
    snprintf(detail, sizeof detail, "ok=%d mounted=%d ours=%d", ok ? 1 : 0,
             st.target_is_mounted ? 1 : 0,
             (st.target_has_fuse || st.target_has_fuse_daemon) ? 1 : 0);
    check("C1_last_line_target_is_found", ok && st.target_is_mounted &&
                                             (st.target_has_fuse || st.target_has_fuse_daemon),
          detail);

    /* D：读取按不设上限发起（max_size=0）——固定上限会把条目多的命名空间截断 */
    snprintf(detail, sizeof detail, "max_size=%zu", g_read_max_size_seen);
    check("D1_read_is_unbounded", g_read_max_size_seen == 0, detail);

    printf(g_fail == 0 ? "===== mount state read driver: all cases passed =====\n"
                       : "===== mount state read driver: %d case(s) failed =====\n",
           g_fail);
    return g_fail == 0 ? 0 : 1;
}
