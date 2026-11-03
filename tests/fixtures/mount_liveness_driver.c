/*
 * tests/fixtures/mount_liveness_driver.c
 *
 * 已挂载视图连接活性判据（src/injector/ns_mount_health.c）的确定性驱动：
 * 直编实际源码，用 -Wl,--wrap=statfs 把「连接是否可用」换成可控返回值，并记录
 * 被探测的路径与调用次数——判据矩阵与「没有项目挂载时一次探测都不做」都在这里断言。
 *
 * 覆盖：
 *   A. 无项目挂载 → 不修复，且 statfs 调用次数为 0（健康路径零额外系统调用）
 *   B. 项目挂载且连接可用 → LIVE、不修复；探测路径 = /proc/<pid>/root<挂载点>
 *   C. 连接已中止（ENOTCONN）→ DEAD、修复
 *   D. 内核拒绝 INIT 回包（ECONNREFUSED）→ DEAD、修复
 *   E/F. 路径不存在 / 权限不足 → UNKNOWN、不修复（探测不了就不动挂载）
 *   G. 非 FUSE 文件系统（tmpfs）→ UNKNOWN、不修复
 *   H. 非法入参（pid<=0、相对路径）→ UNKNOWN，且不产生任何探测
 *
 * 判别性：旧实现没有这套判据（「挂载条目在」= 直接跳过挂载），A/B 两条在旧实现上
 * 无从成立；把 has_project_fuse 的早退删掉 → A2 必失败；把 statfs 换成 stat/getattr
 * → B 在连接断开的真机上会被属性缓存骗过（用例 G 的魔数分支改为属性缓存语义即暴露）。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "ns_utils.h"

#define FUSE_SUPER_MAGIC_FAKE 0x65735546ul
#define TMPFS_MAGIC_FAKE 0x01021994ul

static int g_statfs_calls;
static int g_statfs_rc;
static int g_statfs_errno;
static unsigned long g_statfs_type;
static char g_last_path[512];

int __wrap_statfs(const char* path, struct statfs* buf) {
    g_statfs_calls++;
    snprintf(g_last_path, sizeof(g_last_path), "%s", path ? path : "(null)");
    if (g_statfs_rc != 0) {
        errno = g_statfs_errno;
        return -1;
    }
    memset(buf, 0, sizeof(*buf));
    buf->f_type = (long)g_statfs_type;
    return 0;
}

static int g_failures;

static void check(const char* name, bool ok, const char* detail) {
    if (!ok) g_failures++;
    printf("case=%-46s ok=%d %s\n", name, ok ? 1 : 0, detail ? detail : "");
}

static void reset_probe(int rc, int err, unsigned long type) {
    g_statfs_calls = 0;
    g_statfs_rc = rc;
    g_statfs_errno = err;
    g_statfs_type = type;
    g_last_path[0] = '\0';
}

int main(void) {
    const char* path = "/storage/emulated/0";
    const int pid = 4242;

    /* A. 没有项目挂载：判据直接返回 false，一次探测都不做 */
    reset_probe(0, 0, FUSE_SUPER_MAGIC_FAKE);
    bool needs = ns_mount_needs_repair(pid, path, false);
    check("A1_no_project_fuse_never_repairs", !needs, "");
    check("A2_no_project_fuse_makes_no_probe", g_statfs_calls == 0, "");

    /* B. 项目挂载且连接可用 */
    reset_probe(0, 0, FUSE_SUPER_MAGIC_FAKE);
    int st = ns_mount_conn_state(pid, path);
    check("B1_healthy_fuse_is_live", st == NSP_CONN_LIVE, "");
    check("B2_probe_path_is_proc_root",
          strcmp(g_last_path, "/proc/4242/root/storage/emulated/0") == 0, g_last_path);
    check("B3_healthy_probe_is_single_statfs", g_statfs_calls == 1, "");
    needs = ns_mount_needs_repair(pid, path, true);
    check("B4_healthy_connection_never_repairs", !needs, "");

    /* C. daemon 已退出：连接中止 */
    reset_probe(-1, ENOTCONN, 0);
    check("C1_enotconn_is_dead", ns_mount_conn_state(pid, path) == NSP_CONN_DEAD, "");
    needs = ns_mount_needs_repair(pid, path, true);
    check("C2_dead_connection_repairs", needs, "");

    /* D. 内核拒绝 INIT 回包：daemon 可能还活着但连接已死 */
    reset_probe(-1, ECONNREFUSED, 0);
    check("D1_econnrefused_is_dead", ns_mount_conn_state(pid, path) == NSP_CONN_DEAD, "");
    check("D2_econnrefused_repairs", ns_mount_needs_repair(pid, path, true), "");

    /* E/F. 探测不了 ⇒ 不判定、不动挂载 */
    reset_probe(-1, ENOENT, 0);
    check("E1_enoent_is_unknown", ns_mount_conn_state(pid, path) == NSP_CONN_UNKNOWN, "");
    check("E2_unknown_never_repairs", !ns_mount_needs_repair(pid, path, true), "");
    reset_probe(-1, EACCES, 0);
    check("F1_eacces_is_unknown", ns_mount_conn_state(pid, path) == NSP_CONN_UNKNOWN, "");
    check("F2_eacces_never_repairs", !ns_mount_needs_repair(pid, path, true), "");

    /* G. 非 FUSE 文件系统：不是我们的视图，不判定 */
    reset_probe(0, 0, TMPFS_MAGIC_FAKE);
    check("G1_non_fuse_is_unknown", ns_mount_conn_state(pid, path) == NSP_CONN_UNKNOWN, "");
    check("G2_non_fuse_never_repairs", !ns_mount_needs_repair(pid, path, true), "");

    /* H. 非法入参：不产生探测 */
    reset_probe(-1, ENOTCONN, 0);
    check("H1_pid_zero_is_unknown", ns_mount_conn_state(0, path) == NSP_CONN_UNKNOWN, "");
    check("H2_relative_path_is_unknown",
          ns_mount_conn_state(pid, "storage/emulated/0") == NSP_CONN_UNKNOWN, "");
    check("H3_null_path_is_unknown", ns_mount_conn_state(pid, NULL) == NSP_CONN_UNKNOWN, "");
    check("H4_invalid_args_make_no_probe", g_statfs_calls == 0, "");

    printf("===== failures=%d =====\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
