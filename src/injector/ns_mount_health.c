/*
 * ns_mount_health.c — 已挂载视图的连接活性探测
 *
 * 为什么需要单独探测：daemon 退出后 mountinfo 里的 FUSE 条目**仍然存在**（内核只把
 * 该 superblock 标成断开），所以「目标是项目 FUSE 挂载」回答不了「这个视图现在还能
 * 用吗」。injector 重启不会重建已注入应用命名空间里的旧挂载——那些进程此后每次访问
 * 存储都拿到 ENOTCONN，直到自身换挂载或设备重启。
 *
 * 为什么用 statfs 而不是 stat/getattr：FUSE 的 inode 属性有缓存，连接断开后仍可能
 * 命中旧值而误判为健康；statfs 必然落到超级块（VFS 不缓存 statfs），连接断开时内核
 * 立即返回 ENOTCONN，健康时由 daemon 应答一次无状态请求。
 *
 * 判据保守：只有明确的「连接已断」才返回 DEAD。路径不存在、权限不足、非 FUSE 文件
 * 系统一律 UNKNOWN——调用方按旧行为处理，不因探测不了就动挂载。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "ns_utils.h"

#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif

int ns_mount_conn_state(int pid, const char* mount_point) {
    if (pid <= 0 || !mount_point || mount_point[0] != '/') return NSP_CONN_UNKNOWN;
    char full[PATH_MAX];
    int n = snprintf(full, sizeof(full), "/proc/%d/root%s", pid, mount_point);
    if (n < 0 || (size_t)n >= sizeof(full)) return NSP_CONN_UNKNOWN;
    struct statfs sfs;
    memset(&sfs, 0, sizeof(sfs));
    if (statfs(full, &sfs) == 0) {
        return ((unsigned long)sfs.f_type == (unsigned long)FUSE_SUPER_MAGIC) ? NSP_CONN_LIVE
                                                                              : NSP_CONN_UNKNOWN;
    }
    /* ENOTCONN = 连接已中止（daemon 退出/被杀）；ECONNREFUSED = 内核拒绝 INIT 回包
       （fc->conn_error，daemon 进程可能还活着但连接已死）。两者都不可恢复，
       只能重建挂载。 */
    if (errno == ENOTCONN || errno == ECONNREFUSED) return NSP_CONN_DEAD;
    return NSP_CONN_UNKNOWN;
}

bool ns_mount_needs_repair(int pid, const char* mount_point, bool has_project_fuse) {
    if (!has_project_fuse) return false;
    return ns_mount_conn_state(pid, mount_point) == NSP_CONN_DEAD;
}
