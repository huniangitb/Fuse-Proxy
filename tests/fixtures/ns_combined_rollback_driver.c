/*
 * tests/fixtures/ns_combined_rollback_driver.c
 *
 * do_combined_mount 合并挂载失败回滚的确定性失败注入驱动。
 *
 * 做法：把实际源码 src/injector/ns_utils.c 整体 #include 进本 TU（经
 * -DNS_UTILS_SRC= 传入路径）—— 同一翻译单元内 static 的 do_combined_mount
 * 对本文件可见，可直接调用；再用 -Wl,--wrap=mount/--wrap=umount2 拦截挂载
 * 原语，代码路径全走真实实现，只有内核对 mount 的裁决被替换成可控返回值。
 * 时序不依赖命名空间、FUSE、特权与调度运气。
 *
 * 覆盖：
 *   A. 源 bind 失败 + 族根可用 → 第二次 mount 以族根为源回滚，target 还原为
 *      族根视图，日志含「已回滚」，返回原始 errno（不再让应用停留在裸状态）。
 *   B. 源 bind 失败 + 族根不可用 → 不回滚、只报「回滚未成功」，返回原始 errno。
 *   C. 对照：源 bind 成功 → 不触发任何回滚挂载。
 *
 * 回归价值：移除 ns_utils.c 回滚分支（旧实现只 return err）后 A 必失败。
 */
#define _GNU_SOURCE
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

static void record_log(const char* fmt, ...) {
    size_t used = strlen(g_logbuf);
    if (used + 2 >= sizeof g_logbuf) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_logbuf + used, sizeof g_logbuf - used, fmt, ap);
    va_end(ap);
}

static bool log_has(const char* needle) { return strstr(g_logbuf, needle) != nullptr; }

/* 项目内 log_internal：只做记录，不落盘/不走日志环 */
void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    size_t used = strlen(g_logbuf);
    if (used + 2 >= sizeof g_logbuf) return;
    va_list ap;
    va_start(ap, format);
    vsnprintf(g_logbuf + used, sizeof g_logbuf - used, format, ap);
    va_end(ap);
}

/* ══════════════ 挂载原语拦截 ══════════════ */

int __wrap_mount(const char* source, const char* target, const char* fstype, unsigned long flags,
                 const void* data) {
    (void)fstype;
    (void)flags;
    (void)data;
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
    (void)flags;
    return 0; /* 卸载一律成功：聚焦挂载失败后的回滚分支 */
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

int ns_read_mountinfo_pid(int pid, NsMountEntry* out, int max) {
    (void)pid;
    if (!g_family_root || max < 1) return 0;
    out[0].mount_point[0] = '\0';
    snprintf(out[0].mount_point, sizeof out[0].mount_point, "%s", g_family_root);
    return 1;
}

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
    g_fail_source = fail_source;
    g_family_root = family_root;
}

static int run_combined(void) {
    struct CombinedMountArgs args = {
        .pkg = "com.test.target",
        .source = "/mnt/nsp_global",
        .target = "/storage/emulated",
        .backup = "/var/fuse-proxy/backup/storage",
        .preserve_paths = nullptr,
        .preserve_count = 0,
        .target_pid = 1,
        .readiness_gate = false,
    };
    return do_combined_mount(&args);
}

int main(void) {
    printf("── do_combined_mount 合并挂载失败回滚（失败注入） ──\n");

    /* A. 源不可见 + 族根可用 → 以族根回滚 */
    reset_case("/mnt/nsp_global", "/mnt/user/0/emulated");
    errno = 0;
    int rc = run_combined();
    check("A1 源 bind 失败返回原始 errno(ENOENT)", rc == ENOENT,
          rc == ENOENT ? "" : "返回码与预期不符");
    check("A2 发生第二次 mount（回滚）", g_mount_calls >= 2,
          g_mount_calls >= 2 ? "" : "未触发回滚挂载");
    if (g_mount_calls >= 2) {
        bool src_ok = strcmp(g_mount_src[0], "/mnt/nsp_global") == 0;
        bool rb_src_ok = strcmp(g_mount_src[1], "/mnt/user/0/emulated") == 0;
        bool rb_tgt_ok = strcmp(g_mount_tgt[1], "/storage/emulated") == 0;
        check("A3 首挂载源=项目 FUSE，回滚源=族根且目标不变", src_ok && rb_src_ok && rb_tgt_ok,
              g_mount_calls >= 2 ? "" : "调用记录不足");
    } else {
        check("A3 首挂载源=项目 FUSE，回滚源=族根且目标不变", false, "调用记录不足");
    }
    check("A4 日志报告已回滚（非裸状态）", log_has("已回滚") && !log_has("回滚未成功"),
          log_has("已回滚") ? "" : "缺少回滚成功日志");

    /* B. 源不可见 + 族根不可用 → 不回滚、loud 报错 */
    reset_case("/mnt/nsp_global", nullptr);
    errno = 0;
    rc = run_combined();
    check("B1 仍返回原始 errno(ENOENT)", rc == ENOENT, "");
    check("B2 族根本不可用时不发生回滚挂载", g_mount_calls == 1,
          g_mount_calls == 1 ? "" : "意外发起了回滚挂载");
    check("B3 loud 报告回滚未成功", log_has("回滚未成功"), log_has("回滚未成功") ? "" : "缺少报错");

    /* C. 对照：源可挂载 → 不触发回滚 */
    reset_case(nullptr, "/mnt/user/0/emulated");
    errno = 0;
    rc = run_combined();
    check("C1 源可挂载时成功返回 0", rc == 0, "");
    check("C2 成功路径只挂载一次（无回滚）", g_mount_calls == 1,
          g_mount_calls == 1 ? "" : "成功路径出现了多余挂载");
    check("C3 无回滚日志", !log_has("已回滚") && !log_has("回滚未成功"), "");

    printf("%s\n", g_fail ? "结果: 存在失败" : "结果: 全部通过");
    return g_fail;
}
