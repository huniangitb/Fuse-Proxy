/*
 * global_replace_ctl — 全局替换式挂载方案测试驱动（仅测试用，GNU 构建）
 *
 * injector 本体仅 Android 交叉构建，GNU 下无法直接运行；本驱动链接
 * ns_utils.c 的全局替换原语（ns_global_replace_system 等），以 CLI 子命令
 * 方式暴露，供 tests/test_global_replace.py 在私有挂载命名空间中模拟安卓
 * emulated 挂载视图并验证 替换/恢复/应用还原/状态查询/配置审查（audit）。
 *
 * 链接说明：本驱动同时链接 inject_target.c（audit/force_recover 等审查逻辑，
 * 其真实定义提供 get_app_uid/get_target_storage_path/remove_tracked 等符号）
 * 与 mount_manager.c（perform_app_restore）。ns_utils.o 引用的注入器专属符号
 * （g_epoll_fd、register_async_mount_pipe、schedule_retry_mount、
 * get_active_mnt_src）由本文件提供最小 stub——测试仅走同步原语路径。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "common.h"
#include "ns_utils.h"
#include "injector.h"
#include "inject_target.h"

/* ---- 链接 stub：满足 ns_utils.o / inject_target.o 的符号引用 ---- */
int g_epoll_fd = -1;
bool register_async_mount_pipe(int fd, void* ctx) {
    (void)fd; (void)ctx;
    return true;
}
void schedule_retry_mount(const char* pkg, int pid) {
    (void)pkg; (void)pid;
}
/* get_active_mnt_src 由测试通过 audit-ctl 前置参数注入（fuse_src），
   模拟 injector.c 中的实现语义：返回当前项目 FUSE 源挂载点 */
static const char* g_ctl_mnt_src = nullptr;
const char* get_active_mnt_src(void) {
    return g_ctl_mnt_src;
}
void set_ctl_mnt_src(const char* src) { g_ctl_mnt_src = src; }

/* 全局替换模式开关（injector.c 定义，本驱动自行提供便于测试控制） */
bool g_global_replace_mode = false;

/* 媒体 FUSE 源 stub：audit/force_recover 路径测试不涉及媒体实例 */
const char* get_media_mnt_src(void) {
    return nullptr;
}

static const char* status_name(int st) {
    switch (st) {
        case NSP_GLOBAL_STATUS_NORMAL:   return "normal";
        case NSP_GLOBAL_STATUS_REPLACED: return "replaced";
        case NSP_GLOBAL_STATUS_MIXED:    return "mixed";
        default:                         return "unknown";
    }
}

static void usage(const char* prog) {
    fprintf(stderr,
        "用法: %s <cmd> [args]\n"
        "  replace <ns_pid> <fuse_src> <backup_root>  全局替换（备份一个族 + 三族替换）\n"
        "  restore <ns_pid> <backup_root>             从备份恢复三族视图\n"
        "  app-restore <app_pid> <fuse_src> <backup_root> <user_id>  应用命名空间还原\n"
        "  status <ns_pid> <fuse_src>                 查询状态(normal/replaced/mixed/unknown)\n"
        "  collect <pid> <base> <include_self> <include_fuse>  列出 base 下挂载点(最深优先)\n"
        "  set-src <fuse_src>                         设置 audit 用项目 FUSE 源\n"
        "  add-tracked <pid> <uid> <pkg>              注册一个追踪应用（供 audit 验证）\n"
        "  audit-run <pid> <fuse_src> <uid> <pkg> <on|off>  单进程执行审查+强制回收并报告\n"
        "                                            挂载状态（audit_mounted= force_mounted=）\n",
        prog);
}

int main(int argc, char* argv[]) {
    log_init("global_replace_ctl");
    if (argc < 2) { usage(argv[0]); return 2; }
    const char* cmd = argv[1];

    if (strcmp(cmd, "set-src") == 0 && argc >= 3) {
        set_ctl_mnt_src(argv[2]);
        printf("set-src ok\n");
        return 0;
    }
    if (strcmp(cmd, "add-tracked") == 0 && argc >= 5) {
        add_tracked(atoi(argv[2]));
        all_apps_upsert(atoi(argv[2]), (uid_t)atoi(argv[3]), argv[4]);
        printf("add-tracked ok\n");
        return 0;
    }
    if (strcmp(cmd, "audit-tracked") == 0 && argc >= 3) {
        g_global_replace_mode = (strcmp(argv[2], "on") == 0);
        audit_tracked_apps();
        printf("audit-tracked done (global_replace=%d)\n", (int)g_global_replace_mode);
        return 0;
    }
    if (strcmp(cmd, "audit-specific") == 0 && argc >= 4) {
        g_global_replace_mode = (strcmp(argv[2], "on") == 0);
        ChangedPkg c = { .user_id = -1 };
        strncpy(c.pkg_name, argv[3], sizeof(c.pkg_name) - 1);
        c.pkg_name[sizeof(c.pkg_name) - 1] = '\0';
        audit_and_remount_specific_apps(&c, 1);
        printf("audit-specific done (global_replace=%d)\n", (int)g_global_replace_mode);
        return 0;
    }
    if (strcmp(cmd, "force-recover") == 0 && argc >= 3) {
        g_global_replace_mode = (strcmp(argv[2], "on") == 0);
        force_recover_tracked_mounts();
        printf("force-recover done (global_replace=%d)\n", (int)g_global_replace_mode);
        return 0;
    }
    if (strcmp(cmd, "audit-run") == 0 && argc >= 7) {
        /* 单进程组合：设置 fuse_src + 注册追踪 + audit + force-recover，
           全程共享进程内状态（g_tracked_hash/g_ctl_mnt_src），最后报告
           /storage/emulated 挂载状态供测试断言 */
        int pid = atoi(argv[2]);
        set_ctl_mnt_src(argv[3]);
        g_global_replace_mode = (strcmp(argv[6], "on") == 0);
        add_tracked(pid);
        all_apps_upsert(pid, (uid_t)atoi(argv[4]), argv[5]);
        audit_tracked_apps();
        int audit_mounted = (ns_is_mounted(pid, "/storage/emulated", nullptr) > 0);
        force_recover_tracked_mounts();
        int force_mounted = (ns_is_mounted(pid, "/storage/emulated", nullptr) > 0);
        printf("audit_mounted=%d force_mounted=%d (global_replace=%d)\n",
               audit_mounted, force_mounted, (int)g_global_replace_mode);
        return 0;
    }
    if (strcmp(cmd, "replace") == 0 && argc >= 5) {
        int pid = atoi(argv[2]);
        int ret = ns_global_replace_system(pid, argv[3], argv[4]);
        printf("replace ret=%d\n", ret);
        return ret == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "restore") == 0 && argc >= 4) {
        int pid = atoi(argv[2]);
        int ret = ns_global_restore_system(pid, argv[3]);
        printf("restore ret=%d\n", ret);
        return ret == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "app-restore") == 0 && argc >= 6) {
        int pid = atoi(argv[2]);
        int ret = ns_restore_app_fuse(pid, argv[3], argv[4], atoi(argv[5]));
        printf("app-restore ret=%d\n", ret);
        return ret == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "status") == 0 && argc >= 4) {
        int pid = atoi(argv[2]);
        int st = ns_global_status(pid, argv[3]);
        printf("status=%s(%d)\n", status_name(st), st);
        return 0;
    }
    if (strcmp(cmd, "collect") == 0 && argc >= 6) {
        int pid = atoi(argv[2]);
        int include_self = atoi(argv[4]);
        int include_fuse = atoi(argv[5]);
        char mps[64][PATH_MAX];
        int n = ns_collect_mounts_under(pid, argv[3], include_self, include_fuse, mps, 64);
        printf("collect count=%d\n", n);
        for (int i = 0; i < n; i++) printf("  %s\n", mps[i]);
        return 0;
    }
    usage(argv[0]);
    return 2;
}
