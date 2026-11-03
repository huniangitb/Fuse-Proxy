/*
 * tests/fixtures/mountinfo_dynamic_driver.c
 *
 * mountinfo 读取的容量语义（src/injector/ns_global_replace.c 的
 * ns_read_mountinfo_pid / ns_backup_point_state / ns_global_status）的确定性驱动。
 *
 * 做法：把实际源码 ns_mountinfo.c 与 ns_global_replace.c 整体 #include 进本 TU，
 * 用 -Wl,--wrap=fopen 把 /proc/<pid>/mountinfo 换成合成内容——扫描、解析、扩容、
 * 状态判定全部走真实实现，只有「文件里有什么」被替换成可控值。
 *
 * 覆盖：
 *   A. 5000 条挂载（族根排在第 5000 行）：读取返回 5000 条且末条就是族根——条目数
 *      不设上限，不会被「前 4096 条」截断。
 *   B. 同一份内容下 ns_global_status 判定为 REPLACED（族根在旧上限之后也要被看见）。
 *   C. 打开失败 = 结论未知：读取返回 -1、状态返回 UNKNOWN（绝不能返回 NORMAL：
 *      调用方会把它当成「还没替换」而对活着的视图再替换一次）、备份点状态返回
 *      NS_BACKUP_UNKNOWN（不能当成「可以新建备份」）。
 *   D. 丢弃过超长行 = 结论未知：返回 -1 而不是交回「读到的那部分」。
 *   E. 空挂载表（0 条）是**有效结论**：返回 0 且 *out 为 NULL，与 C/D 的未知区分开。
 *
 * 判别性：旧实现在 4096 条处静默截断——A/B 会失败（读到 4096 条、状态 UNKNOWN）；
 * 把「读失败」当「没有挂载」（返回 0 / 状态 NORMAL）会让 C 失败。
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
#include <sys/mount.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "fast_search.h"
#include "nsp_log.h"
#include "ns_global_replace.h"
#include "ns_utils.h"

/* ══════════════ 合成 mountinfo ══════════════ */

#define MI_BUF_SIZE (4u << 20)
static char g_mountinfo[MI_BUF_SIZE];
static size_t g_mountinfo_len;
static bool g_fail_open;

static void mi_reset(void) {
    g_mountinfo_len = 0;
    g_mountinfo[0] = '\0';
    g_fail_open = false;
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

/* 追加一条与「项目视图」无关的填充挂载 */
static void mi_add_filler(int i) {
    char mp[128];
    snprintf(mp, sizeof mp, "/apex/com.android.filler%d", i);
    mi_add("7:77", mp, "ext4", "/dev/block/dm-77");
}

/* ══════════════ fopen 拦截 ══════════════ */

FILE* __real_fopen(const char* path, const char* mode);

static bool is_mountinfo_path(const char* path) {
    return path && strncmp(path, "/proc/", 6) == 0 &&
           strcmp(path + strlen(path) - strlen("/mountinfo"), "/mountinfo") == 0;
}

FILE* __wrap_fopen(const char* path, const char* mode) {
    if (!is_mountinfo_path(path)) return __real_fopen(path, mode);
    if (g_fail_open) {
        errno = EACCES;
        return nullptr;
    }
    return fmemopen(g_mountinfo, g_mountinfo_len, "r");
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
#define ROOT_USER "/mnt/user/0/emulated"

int main(void) {
    /* A/B：5000 条挂载，族根排在最后一行（旧上限 4096 之后） */
    mi_reset();
    mi_add("0:364", FUSE_SRC, "fuse", "fuse_daemon");
    for (int i = 0; i < 4998; i++) mi_add_filler(i);
    mi_add("0:364", ROOT_USER, "fuse", "fuse_daemon");

    NsMountEntry* all = nullptr;
    int n = ns_read_mountinfo_pid((int)getpid(), &all);
    char detail[160];
    snprintf(detail, sizeof detail, "n=%d", n);
    check("A1_reads_every_entry_without_cap", n == 5000, detail);
    check("A2_last_entry_is_family_root",
          n == 5000 && strcmp(all[n - 1].mount_point, ROOT_USER) == 0,
          n == 5000 ? all[n - 1].mount_point : "");
    check("A3_first_entry_is_fuse_source", n > 0 && strcmp(all[0].mount_point, FUSE_SRC) == 0, "");
    free(all);

    int st = ns_global_status((int)getpid(), FUSE_SRC);
    snprintf(detail, sizeof detail, "status=%d", st);
    check("B1_status_sees_roots_beyond_old_cap", st == NSP_GLOBAL_STATUS_REPLACED, detail);

    /* C：打开失败 → 未知，不是「没有挂载」 */
    mi_reset();
    g_fail_open = true;
    all = nullptr;
    n = ns_read_mountinfo_pid((int)getpid(), &all);
    snprintf(detail, sizeof detail, "n=%d out=%p", n, (void*)all);
    check("C1_open_failure_is_unknown", n == -1 && all == nullptr, detail);
    st = ns_global_status((int)getpid(), FUSE_SRC);
    snprintf(detail, sizeof detail, "status=%d", st);
    check("C2_status_unknown_not_normal", st == NSP_GLOBAL_STATUS_UNKNOWN, detail);
    int backup = ns_backup_point_state((int)getpid(), "/backup/user_0/emulated");
    snprintf(detail, sizeof detail, "backup=%d", backup);
    check("C3_backup_unknown_not_absent", backup == NS_BACKUP_UNKNOWN, detail);
    g_fail_open = false;

    /* D：丢弃过超长行 → 未知（列表不完整就不得当成完整结论） */
    mi_reset();
    mi_add("0:364", FUSE_SRC, "fuse", "fuse_daemon");
    char longline[6000];
    memset(longline, 'x', sizeof longline - 1);
    longline[0] = '9';
    longline[sizeof longline - 1] = '\0';
    /* 直接注入一行超长内容（不含换行：扫描器按「填满缓冲且未遇换行」判定超长） */
    if (g_mountinfo_len + sizeof longline < MI_BUF_SIZE) {
        memcpy(g_mountinfo + g_mountinfo_len, longline, sizeof longline - 1);
        g_mountinfo_len += sizeof longline - 1;
        g_mountinfo[g_mountinfo_len] = '\0';
    }
    mi_add("0:364", ROOT_USER, "fuse", "fuse_daemon");
    all = nullptr;
    n = ns_read_mountinfo_pid((int)getpid(), &all);
    snprintf(detail, sizeof detail, "n=%d", n);
    check("D1_dropped_line_is_unknown", n == -1 && all == nullptr, detail);

    /* E：空挂载表是有效结论（0 条），与 C/D 的未知区分开 */
    mi_reset();
    all = nullptr;
    n = ns_read_mountinfo_pid((int)getpid(), &all);
    snprintf(detail, sizeof detail, "n=%d out=%p", n, (void*)all);
    check("E1_empty_table_is_zero_not_unknown", n == 0 && all == nullptr, detail);

    printf(g_fail == 0 ? "===== mountinfo dynamic driver: all cases passed =====\n"
                       : "===== mountinfo dynamic driver: %d case(s) failed =====\n",
           g_fail);
    return g_fail == 0 ? 0 : 1;
}
