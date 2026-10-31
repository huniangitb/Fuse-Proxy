/*
 * tests/fixtures/ns_umount_overflow_driver.c
 *
 * do_umount_recursive / do_umount_and_rmdir 的 mountinfo 扫描栈越界判别驱动。
 *
 * 做法：把实际源码 src/injector/ns_utils.c 整体 #include 进本 TU（经
 * -DNS_UTILS_SRC= 传入路径）——同 TU 内 static 的两个函数直接可见可调；
 * 再用 -Wl,--wrap=fopen 把 /proc/self/mountinfo 换成合成内容（fmemopen），
 * -Wl,--wrap=umount2 记录每次卸载请求。全路径走真实实现，不依赖命名空间、
 * 特权或真实挂载。
 *
 * 缺陷形态（review-findings §A9）：旧实现 `char mounts[N][256]` 却按
 * `strncpy(mounts[count], mp, PATH_MAX - 1)` 拷贝，扫描到第 N 条（最后一槽）
 * 且其挂载点 >256 字节时，写越界到数组之外的栈（最多 ~3.8KB）。本驱动喂入
 * 恰好填满容量的匹配条目、末条为超长路径 —— ASan 下旧实现必报
 * stack-buffer-overflow，新实现跳过超长条目并 loud 告警。
 *
 * 退出码：全部通过 0，任一失败 1。环境变量 NS_UTILS_SRC 可指向另一份源码副本
 * （用于在旧实现上复现失败）。
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
#include "inject_target.h"
#include "injector.h"
#include "ns_global_replace.h"
#include "ns_utils.h"

/* ══════════════ 测试可控状态 ══════════════ */

#define MAX_UMOUNTS 512

static char g_logbuf[16384];
static char g_umount_paths[MAX_UMOUNTS][4096];
static int g_umount_calls;

/* 合成 mountinfo 内容（由 main 按用例填充） */
static char g_mountinfo[256 * 1024];
static size_t g_mountinfo_len;

static void record_log(const char* fmt, ...) {
    size_t used = strlen(g_logbuf);
    if (used + 2 >= sizeof g_logbuf) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_logbuf + used, sizeof g_logbuf - used, fmt, ap);
    va_end(ap);
}

static bool log_has(const char* needle) { return strstr(g_logbuf, needle) != nullptr; }

void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    size_t used = strlen(g_logbuf);
    if (used + 2 >= sizeof g_logbuf) return;
    va_list ap;
    va_start(ap, format);
    vsnprintf(g_logbuf + used, sizeof g_logbuf - used, format, ap);
    va_end(ap);
}

/* ns_utils.c 的成功回调会清重试记账；本用例不涉及重试队列 */
void retry_mount_succeeded(int pid) { (void)pid; }

/* ══════════════ fopen / umount2 拦截 ══════════════ */

FILE* __real_fopen(const char* path, const char* mode);

FILE* __wrap_fopen(const char* path, const char* mode) {
    if (path && strcmp(path, "/proc/self/mountinfo") == 0 && g_mountinfo_len > 0) {
        /* fmemopen 需要可写缓冲；"r" 模式只读不改内容 */
        return fmemopen(g_mountinfo, g_mountinfo_len, "r");
    }
    return __real_fopen(path, mode);
}

int __wrap_umount2(const char* target, int flags) {
    (void)flags;
    if (target && g_umount_calls < MAX_UMOUNTS) {
        snprintf(g_umount_paths[g_umount_calls], sizeof g_umount_paths[0], "%s", target);
    }
    g_umount_calls++;
    return 0; /* 一律成功：聚焦扫描/拷贝与越界，不关心内核裁决 */
}

/* ══════════════ 其余外部依赖的最小桩（与 ns_combined_rollback_driver 同套） ══════════════ */

uid_t get_app_uid(int pid) {
    (void)pid;
    return 10123;
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
    (void)mp;
    *user_id = 0;
    return -1;
}

int ns_read_mountinfo_pid(int pid, NsMountEntry* out, int max) {
    (void)pid;
    (void)out;
    (void)max;
    return 0;
}

/* ══════════════ 实际源码 ══════════════ */

/* C7：mountinfo 扫描原语独立成 TU（src/injector/ns_mountinfo.c），此处一并编入
   本 TU——ns_utils.c 的四处扫描都经它收口（ns_collect_mounts_under_pid）。 */
#include "ns_mountinfo.c"
#include NS_UTILS_SRC

/* ══════════════ 用例 ══════════════ */

static int g_fail;

static void check(const char* name, bool ok, const char* detail) {
    printf("  %s %s", ok ? "[PASS]" : "[FAIL]", name);
    if (!ok && detail && *detail) printf(" — %s", detail);
    printf("\n");
    if (!ok) g_fail = 1;
}

/* 构造合成 mountinfo：target 下 n 条匹配子挂载，其中第 n 条挂载点超长
   （>256 字节）。每条一行，第 6 字段为挂载点。 */
static void build_mountinfo(const char* target, int n, int long_len) {
    g_mountinfo[0] = '\0';
    size_t off = 0;
    for (int i = 0; i < n; i++) {
        char mp[512];
        if (i == n - 1) {
            /* 末条超长：target + "/" + long_len 个 'd' */
            snprintf(mp, sizeof mp, "%s/", target);
            size_t base = strlen(mp);
            for (int k = 0; k < long_len && base + (size_t)k + 1 < sizeof mp; k++) mp[base + k] = 'd';
            mp[base + (size_t)long_len] = '\0';
        } else {
            snprintf(mp, sizeof mp, "%s/child%03d", target, i);
        }
        int wrote = snprintf(g_mountinfo + off, sizeof g_mountinfo - off,
                             "%d 0 8:1 / %s rw - tmpfs a rw\n", i + 1, mp);
        if (wrote <= 0) break;
        off += (size_t)wrote;
    }
    g_mountinfo_len = off;
}

static void reset_case(void) {
    g_umount_calls = 0;
    g_logbuf[0] = '\0';
    g_mountinfo_len = 0;
}

/* 统计卸载请求里路径长度 ≥ 256 的条数（超长路径若被原样传给 umount2，
   说明它没被「拒绝」而是被拷进了定长槽——正是缺陷形态） */
static int count_oversize_umounts(void) {
    int c = 0;
    for (int i = 0; i < g_umount_calls && i < MAX_UMOUNTS; i++)
        if (strlen(g_umount_paths[i]) >= 256) c++;
    return c;
}

static bool umount_has(const char* p) {
    for (int i = 0; i < g_umount_calls && i < MAX_UMOUNTS; i++)
        if (strcmp(g_umount_paths[i], p) == 0) return true;
    return false;
}

int main(void) {
    const char* target = "/t";

    printf("── do_umount_recursive / do_umount_and_rmdir mountinfo 扫描栈越界（A9） ──\n");

    /* A. do_umount_recursive：填满 128 槽，末条超长 */
    reset_case();
    build_mountinfo(target, 128, 260);
    do_umount_recursive((void*)target);
    check("A1 不崩溃且返回 0", true, "");
    check("A2 超长挂载点未被当成可卸载路径（长度 ≥256 的 umount2 请求为 0）",
          count_oversize_umounts() == 0, "出现超长 umount2 请求");
    check("A3 目标本身仍被卸载", umount_has(target), "未卸载 target");
    check("A4 loud 告警超长已跳过", log_has("超长"), "缺少超长告警日志");
    check("A5 其余 127 条正常子挂载仍被卸载",
          g_umount_calls == 128, "卸载请求数与预期不符");

    /* B. do_umount_and_rmdir：同形态（容量 64） */
    reset_case();
    build_mountinfo(target, 64, 260);
    do_umount_and_rmdir((void*)target);
    check("B1 不崩溃且返回 0", true, "");
    check("B2 超长挂载点未被当成可卸载路径",
          count_oversize_umounts() == 0, "出现超长 umount2 请求");
    check("B3 目标本身仍被卸载", umount_has(target), "未卸载 target");
    check("B4 loud 告警超长已跳过", log_has("超长"), "缺少超长告警日志");
    check("B5 其余 63 条正常子挂载仍被卸载",
          g_umount_calls == 64, "卸载请求数与预期不符");

    /* C. 对照：无超长条目时行为不变（正常子挂载全量卸载） */
    reset_case();
    build_mountinfo(target, 3, 8);
    do_umount_recursive((void*)target);
    check("C1 对照：3 条正常子挂载 + target 全量卸载",
          g_umount_calls == 4, "卸载请求数与预期不符");
    check("C2 对照：无超长告警", !log_has("超长"), "不该出现超长告警");

    /* D. C7：do_force_umount_stale 容量触顶必须 loud 告警。
       旧实现各自手写扫描，此处的 `while (fgets(...) && count < 64)` 触顶后**静默**
       停止——与 do_umount_recursive 的告警语义不一致，正是「各写一套」的漂移证据；
       C7 收口到 ns_collect_mounts_under_pid 后统一告警。 */
    reset_case();
    build_mountinfo(target, 70, 8); /* 70 条匹配 > 容量 64 */
    do_force_umount_stale((void*)target);
    check("D1 容量触顶 loud 告警（拒绝静默截断）", log_has("上限"), "缺少容量触顶告警");
    check("D2 已收集的 64 条 + target 仍全量卸载",
          g_umount_calls == 65, "卸载请求数与预期不符");
    check("D3 触顶丢弃的 6 条未产生卸载请求（不越界、不错卸）",
          count_oversize_umounts() == 0, "出现超长 umount2 请求");

    printf("%s\n", g_fail ? "结果: 存在失败" : "结果: 全部通过");
    return g_fail;
}
