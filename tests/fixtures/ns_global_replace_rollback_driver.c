/*
 * tests/fixtures/ns_global_replace_rollback_driver.c
 *
 * 全局替换（do_global_replace）失败回滚的确定性失败注入驱动。
 *
 * 做法：把实际源码 src/injector/ns_global_replace.c 整体 #include 进本 TU
 * （经 -DNS_GLOBAL_REPLACE_SRC= 传入路径）——同 TU 内 static 的 do_global_replace
 * 直接可见可调；再用 -Wl,--wrap=fopen 把 /proc/<pid>/mountinfo 换成合成内容
 * （fmemopen），-Wl,--wrap=mount/--wrap=umount2 拦截挂载原语并让指定
 * (source,target) 的那次 bind 失败。代码路径全走真实实现，只有内核裁决被替换成
 * 可控返回值 —— 不依赖命名空间、FUSE、特权与调度运气。
 *
 * 缺陷形态（review-findings §A19）：替换步骤先卸族根全部挂载再 bind fuse_src，
 * 旧实现任一步失败直接 `return -1` —— 族根停在**裸挂载点**（/mnt/{user,
 * androidwritable,installer}/… 下系统存储视图整体消失），而备份树就在手边却
 * 不 bind 回去。新实现把本次已动过的族根逐一根从备份树还原。
 *
 * 覆盖：
 *   A. 第 2 个族根 bind 失败 → 已替换的第 1、2 个族根都从备份树还原（含
 *      Android/data 子挂载），返回 -1，日志报告回滚。
 *   B. 对照：无失败 → 三族各 bind 一次、无任何回滚挂载、返回 0。
 *   C. 第 1 个族根 bind 失败 → 只回滚第 1 个（不误动未处理的族根）。
 *   D. 备份点缺失 → 如实报告无法回滚（不静默假装成功），返回 -1。
 *
 * 退出码：全部通过 0，任一失败 1。环境变量 NS_GLOBAL_REPLACE_SRC 可指向另一份
 * 源码副本（用于在旧实现上复现失败）。
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

/* ══════════════ 测试可控状态 ══════════════ */

#define MAX_MOUNTS 64

#define FUSE_SRC "/mnt/nsp_global"
#define BACKUP_ROOT "/var/fuse-proxy/global_backup"
#define BTOP BACKUP_ROOT "/user_0/emulated"
#define BTOP_DATA BTOP "/0/Android/data"
#define ROOT_INSTALLER "/mnt/installer/0/emulated"
#define ROOT_ANDROIDW "/mnt/androidwritable/0/emulated"
#define ROOT_USER "/mnt/user/0/emulated"
#define ROOT_USER_DATA ROOT_USER "/0/Android/data"

static char g_logbuf[32768];
static char g_msrc[MAX_MOUNTS][512];
static char g_mtgt[MAX_MOUNTS][512];
static unsigned long g_mflags[MAX_MOUNTS];
static int g_mount_calls;
static const char* g_fail_src;
static const char* g_fail_tgt;

static char g_mountinfo[64 * 1024];
static size_t g_mountinfo_len;

static void record_log(const char* fmt, va_list ap) {
    size_t used = strlen(g_logbuf);
    if (used + 2 >= sizeof g_logbuf) return;
    vsnprintf(g_logbuf + used, sizeof g_logbuf - used, fmt, ap);
}

static bool log_has(const char* needle) { return strstr(g_logbuf, needle) != nullptr; }

void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    va_list ap;
    va_start(ap, format);
    record_log(format, ap);
    va_end(ap);
}

void log_ns_error(const char* format, ...) {
    va_list ap;
    va_start(ap, format);
    record_log(format, ap);
    va_end(ap);
}

/* ══════════════ fopen / mount / umount2 拦截 ══════════════ */

FILE* __real_fopen(const char* path, const char* mode);

FILE* __wrap_fopen(const char* path, const char* mode) {
    if (path && strstr(path, "mountinfo") && g_mountinfo_len > 0)
        return fmemopen(g_mountinfo, g_mountinfo_len, "r");
    return __real_fopen(path, mode);
}

int __wrap_mount(const char* source, const char* target, const char* fstype, unsigned long flags,
                 const void* data) {
    (void)fstype;
    (void)data;
    if (g_mount_calls < MAX_MOUNTS) {
        snprintf(g_msrc[g_mount_calls], sizeof g_msrc[0], "%s", source ? source : "");
        snprintf(g_mtgt[g_mount_calls], sizeof g_mtgt[0], "%s", target ? target : "");
        g_mflags[g_mount_calls] = flags;
    }
    g_mount_calls++;
    if (g_fail_src && g_fail_tgt && source && target && strcmp(source, g_fail_src) == 0 &&
        strcmp(target, g_fail_tgt) == 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int __wrap_umount2(const char* target, int flags) {
    (void)target;
    (void)flags;
    return 0; /* 卸载一律成功：聚焦 bind 失败后的回滚分支 */
}

/* ══════════════ 其余外部依赖的最小桩 ══════════════ */

const char* fast_strstr(const char* haystack, const char* needle) { return strstr(haystack, needle); }

int mkdir_recursive(const char* dir) {
    (void)dir;
    return 0;
}

/* ══════════════ 实际源码（static do_global_replace 由此可见） ══════════════ */

/* C7：mountinfo 扫描原语独立成 TU（src/injector/ns_mountinfo.c），此处一并编入
   本 TU——ns_global_replace.c 的 ns_read_mountinfo_pid 经 ns_scan_mountinfo 收口。 */
#include "ns_mountinfo.c"
#include NS_GLOBAL_REPLACE_SRC

/* ══════════════ 用例 ══════════════ */

static int g_fail;

static void check(const char* name, bool ok, const char* detail) {
    printf("  %s %s", ok ? "[PASS]" : "[FAIL]", name);
    if (!ok && detail && *detail) printf(" — %s", detail);
    printf("\n");
    if (!ok) g_fail = 1;
}

/* 合成 mountinfo：三族族根 + 项目 FUSE 源 + 备份树（with_backup=0 时不含备份树） */
static void build_mountinfo(bool with_backup) {
    g_mountinfo[0] = '\0';
    size_t off = 0;
    off += (size_t)snprintf(g_mountinfo + off, sizeof g_mountinfo - off,
                            "1 0 8:1 / / rw - ext4 /dev/root rw\n");
    off += (size_t)snprintf(g_mountinfo + off, sizeof g_mountinfo - off,
                            "2 0 0:99 / " FUSE_SRC " rw - fuse_daemon nsp_global rw\n");
    off += (size_t)snprintf(g_mountinfo + off, sizeof g_mountinfo - off,
                            "3 0 0:100 / " ROOT_INSTALLER " rw - f2fs /dev/block/sda1 rw\n");
    off += (size_t)snprintf(g_mountinfo + off, sizeof g_mountinfo - off,
                            "4 0 0:100 / " ROOT_ANDROIDW " rw - f2fs /dev/block/sda1 rw\n");
    off += (size_t)snprintf(g_mountinfo + off, sizeof g_mountinfo - off,
                            "5 0 0:100 / " ROOT_USER " rw - f2fs /dev/block/sda1 rw\n");
    off += (size_t)snprintf(g_mountinfo + off, sizeof g_mountinfo - off,
                            "6 0 0:100 / " ROOT_USER_DATA " rw - f2fs /dev/block/sda1 rw\n");
    if (with_backup) {
        off += (size_t)snprintf(g_mountinfo + off, sizeof g_mountinfo - off,
                                "7 0 0:101 / " BTOP " rw - f2fs /dev/block/sda1 rw\n");
        off += (size_t)snprintf(g_mountinfo + off, sizeof g_mountinfo - off,
                                "8 0 0:101 / " BTOP_DATA " rw - f2fs /dev/block/sda1 rw\n");
    }
    g_mountinfo_len = off;
}

static void reset_case(bool with_backup, const char* fail_src, const char* fail_tgt) {
    g_mount_calls = 0;
    g_logbuf[0] = '\0';
    g_fail_src = fail_src;
    g_fail_tgt = fail_tgt;
    build_mountinfo(with_backup);
}

/* 统计「以项目 FUSE 源为源」的 bind 次数（= 实际替换动作数）。
   注意 MS_PRIVATE/MS_SHARED 也走 mount()（source=NULL），不能按调用总数断言 */
static int count_replace_binds(void) {
    int c = 0;
    for (int i = 0; i < g_mount_calls && i < MAX_MOUNTS; i++)
        if (strcmp(g_msrc[i], FUSE_SRC) == 0) c++;
    return c;
}

/* 统计「以备份树节点为源」的 bind 次数（= 回滚还原动作数） */
static int count_restore_mounts(void) {
    int c = 0;
    for (int i = 0; i < g_mount_calls && i < MAX_MOUNTS; i++)
        if (strncmp(g_msrc[i], BACKUP_ROOT, strlen(BACKUP_ROOT)) == 0) c++;
    return c;
}

/* 是否存在「源=备份树节点、目标=指定族根」的还原 bind */
static bool restored_onto(const char* root) {
    for (int i = 0; i < g_mount_calls && i < MAX_MOUNTS; i++)
        if (strcmp(g_mtgt[i], root) == 0 && strncmp(g_msrc[i], BACKUP_ROOT, strlen(BACKUP_ROOT)) == 0)
            return true;
    return false;
}

static int run_replace(void) {
    struct GlobalReplaceArgs args = {FUSE_SRC, BACKUP_ROOT, false};
    return do_global_replace(&args);
}

int main(void) {
    printf("── do_global_replace 替换失败回滚（失败注入，A19） ──\n");

    /* A. 第 2 个族根（androidwritable）bind 失败 → 已动过的 2 个族根都还原 */
    reset_case(true, FUSE_SRC, ROOT_ANDROIDW);
    errno = 0;
    int rc = run_replace();
    check("A1 返回 -1（替换失败）", rc == -1, rc == -1 ? "" : "返回值与预期不符");
    check("A2 已替换的 installer 族根被还原", restored_onto(ROOT_INSTALLER),
          "未对 installer 族根发起还原 bind");
    check("A3 失败的 androidwritable 族根被还原", restored_onto(ROOT_ANDROIDW),
          "未对 androidwritable 族根发起还原 bind");
    check("A4 未处理到的 user 族根未被误动", !restored_onto(ROOT_USER),
          "对未替换的族根发起了还原 bind");
    check("A5 还原含子挂载（Android/data 逐节点 bind）",
          restored_onto(ROOT_INSTALLER "/0/Android/data"), "缺少子挂载还原 bind");
    check("A6 还原动作数 = 2 族根 × 2 节点", count_restore_mounts() == 4,
          "还原 bind 数与预期不符");
    check("A7 失败前只替换了 2 个族根", count_replace_binds() == 2, "替换 bind 数与预期不符");
    check("A8 日志报告已回滚", log_has("回滚") && !log_has("无法回滚"), "缺少回滚日志");

    /* B. 对照：无失败 → 三族各 bind 一次，无还原动作 */
    reset_case(true, nullptr, nullptr);
    errno = 0;
    rc = run_replace();
    check("B1 成功返回 0", rc == 0, "");
    check("B2 三族各替换一次（3 次 bind）", count_replace_binds() == 3, "替换 bind 次数与预期不符");
    check("B3 成功路径无还原动作", count_restore_mounts() == 0, "成功路径出现了还原 bind");
    check("B4 无回滚日志", !log_has("回滚"), "");

    /* C. 第 1 个族根（installer）bind 失败 → 只回滚它自己 */
    reset_case(true, FUSE_SRC, ROOT_INSTALLER);
    errno = 0;
    rc = run_replace();
    check("C1 返回 -1", rc == -1, "");
    check("C2 失败的 installer 族根被还原", restored_onto(ROOT_INSTALLER), "");
    check("C3 未动过的 androidwritable 族根未被误动", !restored_onto(ROOT_ANDROIDW),
          "对未动过的族根发起了还原 bind");
    check("C4 还原动作数 = 1 族根 × 2 节点", count_restore_mounts() == 2,
          "还原 bind 数与预期不符");

    /* D. 备份点缺失 → 如实报告无法回滚，不静默假装成功 */
    reset_case(false, FUSE_SRC, ROOT_ANDROIDW);
    errno = 0;
    rc = run_replace();
    check("D1 仍返回 -1", rc == -1, "");
    check("D2 无还原动作（备份不可用）", count_restore_mounts() == 0, "");
    check("D3 loud 报告无法回滚", log_has("无法回滚"), "缺少「无法回滚」日志");

    printf("%s\n", g_fail ? "结果: 存在失败" : "结果: 全部通过");
    return g_fail;
}
