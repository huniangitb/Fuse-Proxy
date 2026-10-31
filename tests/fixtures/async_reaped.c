/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/*
 * tests/fixtures/async_reaped.c — 异步挂载完成事件的结果判定与收尸解耦（R9）
 * =======================================================================
 *
 * 直编**实际源码** src/injector/ns_utils.c 的 handle_async_mount_event，用真实
 * fork/pipe/waitpid 构造「完成管道已回传 status」与「status 缺失(EOF)」两类结果，
 * 并分别覆盖「主循环 reap_zombies 抢先收尸（waitpid 得 ECHILD）」与「未被抢先」
 * 两种时序。业务回调（schedule_retry_mount / remove_tracked）只记账。
 *
 * 矩阵与期望：
 *   failure_control  payload=ENOENT, 未预收尸 → retries=1 removed=1
 *   failure_ECHILD   payload=ENOENT, 已预收尸 → retries=1 removed=1  ← 旧实现 0/0
 *   EOF_control      无 payload(EOF), 未预收尸 → retries=1 removed=1
 *   EOF_ECHILD       无 payload(EOF), 已预收尸 → retries=1 removed=1  ← 旧实现 0/0
 *   success_control  payload=0, 未预收尸      → retries=0 removed=0
 *   success_ECHILD   payload=0, 已预收尸      → retries=0 removed=0（不得误重试）
 *
 * 判别性：NS_UTILS_SRC 指向 HEAD 副本时，两个 ECHILD 失败组变成 0/0 → 必失败。
 * 退出码：0 全部符合期望；1 存在不符。
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
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "injector.h"
#include "inject_target.h"
#include "ns_global_replace.h"
#include "ns_utils.h"

/* ================= 业务回调桩：只记账 ================= */

static int g_retries;
static int g_removed;

void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}
void schedule_retry_mount(const char* pkg, int pid) {
    (void)pkg;
    (void)pid;
    g_retries++;
}
/* 成功清账的桩：真实现随 injector.c（retry_queue 记账）编入，本直编组不链接它 */
void retry_mount_succeeded(int pid) { (void)pid; }
void remove_tracked(int pid) {
    (void)pid;
    g_removed++;
}
uid_t get_app_uid(int pid) {
    (void)pid;
    return getuid();
}
void get_target_storage_path(uid_t uid, char* path, size_t size) {
    (void)uid;
    snprintf(path, size, "/storage/emulated");
}
const char* fast_strstr(const char* haystack, const char* needle) {
    return strstr(haystack, needle);
}

/* ================= ns_utils.c 其余外部依赖桩（本用例不触达） ================= */

int g_log_forward_fd = -1;
int g_epoll_fd = -1;

bool register_async_mount_pipe(int fd, void* ctx) {
    (void)fd;
    (void)ctx;
    return true;
}
void unregister_async_mount_pipe(int fd) { (void)fd; }
int mkdir_recursive(const char* dir) {
    (void)dir;
    return -1;
}
char* read_file_dynamic(const char* path, size_t* out_size, size_t max_size) {
    (void)path;
    (void)max_size;
    if (out_size) *out_size = 0;
    return NULL;
}
int ns_collect_mounts_under_pid(int pid, const char* base, char (*out)[NS_MOUNT_PATH_MAX],
                                int max, const char* who) {
    (void)pid;
    (void)base;
    (void)out;
    (void)max;
    (void)who;
    return -1;
}
int ns_read_mountinfo_pid(int pid, NsMountEntry* out, int max) {
    (void)pid;
    (void)out;
    (void)max;
    return 0;
}
bool ns_is_digit_char(char c) { return c >= '0' && c <= '9'; }
bool ns_is_family_root(const char* mp) {
    (void)mp;
    return false;
}
int ns_parse_family_root(const char* mp, int* user_id) {
    (void)mp;
    (void)user_id;
    return -1;
}

/* ================= 用例 ================= */

static int g_pass;
static int g_fail;

typedef struct {
    const char* label;
    int payload;    /* >=0：子进程写回该 int；<0：不写（完成管道 EOF） */
    int pre_reap;   /* 1 = 先 waitpid 收尸（模拟主循环 reap_zombies 抢先） */
    int want_retry;
    int want_removed;
} Row;

static void run_row(const Row* r) {
    int p[2];
    if (pipe(p) != 0) {
        printf("  FAIL %s — pipe 失败: %s\n", r->label, strerror(errno));
        g_fail++;
        return;
    }
    pid_t child = fork();
    if (child < 0) {
        printf("  FAIL %s — fork 失败: %s\n", r->label, strerror(errno));
        g_fail++;
        return;
    }
    if (child == 0) {
        close(p[0]);
        if (r->payload >= 0) {
            ssize_t w = write(p[1], &r->payload, sizeof(r->payload));
            (void)w;
        }
        close(p[1]);
        _exit(r->payload == 0 ? 0 : 1);
    }
    close(p[1]);
    if (r->pre_reap) {
        /* 主循环 reap_zombies 抢先收走：之后 handle 里的 waitpid 必得 ECHILD */
        waitpid(child, NULL, 0);
    }
    MountTaskCtx* ctx = calloc(1, sizeof *ctx);
    ctx->status_pipe_fd = p[0];
    ctx->child_pid = child;
    ctx->target_pid = getpid(); /* 目标进程存活，避免走「已死」分支 */
    snprintf(ctx->pkg_name, sizeof ctx->pkg_name, "com.real.target");
    g_retries = 0;
    g_removed = 0;
    handle_async_mount_event(ctx);
    close(p[0]);

    bool okv = (g_retries == r->want_retry) && (g_removed == r->want_removed);
    printf("  %s %s — payload=%d pre_reaped=%d retries=%d(期望%d) removed=%d(期望%d)\n",
           okv ? "PASS" : "FAIL", r->label, r->payload, r->pre_reap, g_retries, r->want_retry,
           g_removed, r->want_removed);
    if (okv) {
        g_pass++;
    } else {
        g_fail++;
    }
    /* 未预收尸的行已被 handle 内的 waitpid 回收；预收尸的行也已回收 */
    if (!r->pre_reap) waitpid(child, NULL, WNOHANG);
}

int main(void) {
    const Row rows[] = {
        {"failure_control（失败码经管道回传，未预收尸）", ENOENT, 0, 1, 1},
        {"failure_ECHILD（失败码经管道回传，主循环先收尸）", ENOENT, 1, 1, 1},
        {"EOF_control（status 缺失=EOF，未预收尸）", -1, 0, 1, 1},
        {"EOF_ECHILD（status 缺失=EOF，主循环先收尸）", -1, 1, 1, 1},
        {"success_control（成功，未预收尸）", 0, 0, 0, 0},
        {"success_ECHILD（成功，主循环先收尸）", 0, 1, 0, 0},
    };
    printf("异步挂载完成事件：结果判定与收尸解耦用例\n");
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) run_row(&rows[i]);
    printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
