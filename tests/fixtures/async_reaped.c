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
 *   late_exit       成功 / 失败 / EOF 回传后仍存活 600ms → 回调 <150ms
 *
 * 判别性：NS_UTILS_SRC 指向未解耦结果的历史源码，两个 ECHILD 失败组变成 0/0；
 * 指向未取消阻塞 waitpid 的源码，三个 late_exit 回调等待约 600ms → 必失败。
 * 退出码：0 全部符合期望；1 存在不符。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
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
/* do_combined_mount 现在一次扫描收多棵子树；本用例走异步通道且 MS_PRIVATE 之外
   不关心扫描结果，桩返回"没有子挂载"即可 */
int ns_collect_mounts_multi(int pid, NsCollectTarget* targets, int ntargets) {
    (void)pid;
    for (int i = 0; i < ntargets; i++) targets[i].n = 0;
    return 0;
}
void ns_mountinfo_last_stats(NsMountinfoStats* out) {
    if (out) memset(out, 0, sizeof *out);
}
int ns_scan_mountinfo_prefixed(int pid, const char* const* prefixes, int nprefixes,
                               NsMountinfoLineFn cb, void* ctx) {
    (void)pid;
    (void)prefixes;
    (void)nprefixes;
    (void)cb;
    (void)ctx;
    return 0;
}
int ns_read_mountinfo_pid(int pid, NsMountEntry** out) {
    (void)pid;
    if (out) *out = nullptr;
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
    int exit_delay_ms;
} Row;

static double monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static void run_row(const Row* r) {
    int p[2];
    if (pipe(p) != 0) {
        printf("  FAIL %s — pipe 失败: %s\n", r->label, strerror(errno));
        g_fail++;
        return;
    }
    MountTaskCtx* ctx = calloc(1, sizeof *ctx);
    if (!ctx) {
        close(p[0]);
        close(p[1]);
        g_fail++;
        return;
    }
    pid_t child = fork();
    if (child < 0) {
        free(ctx);
        close(p[0]);
        close(p[1]);
        printf("  FAIL %s — fork 失败: %s\n", r->label, strerror(errno));
        g_fail++;
        return;
    }
    if (child == 0) {
        signal(SIGALRM, SIG_DFL);
        sigset_t unblock;
        sigemptyset(&unblock);
        sigaddset(&unblock, SIGALRM);
        sigprocmask(SIG_UNBLOCK, &unblock, NULL);
        alarm(2); /* 即使测试父进程异常退出，子进程也不会永久存活。 */
        close(p[0]);
        if (r->payload >= 0) {
            ssize_t w = write(p[1], &r->payload, sizeof(r->payload));
            (void)w;
        }
        close(p[1]);
        if (r->exit_delay_ms) poll(NULL, 0, r->exit_delay_ms);
        _exit(r->payload == 0 ? 0 : 1);
    }
    close(p[1]);
    if (r->pre_reap) {
        /* 主循环 reap_zombies 抢先收走：之后 handle 里的 waitpid 必得 ECHILD */
        waitpid(child, NULL, 0);
    }
    ctx->status_pipe_fd = p[0];
    ctx->child_pid = child;
    ctx->target_pid = getpid(); /* 目标进程存活，避免走「已死」分支 */
    snprintf(ctx->pkg_name, sizeof ctx->pkg_name, "com.real.target");
    g_retries = 0;
    g_removed = 0;
    struct pollfd ready = {.fd = p[0], .events = POLLIN};
    int pr;
    do { pr = poll(&ready, 1, 3000); } while (pr < 0 && errno == EINTR);
    if (pr <= 0) {
        printf("  FAIL %s — status 未就绪\n", r->label);
        g_fail++;
        close(p[0]);
        free(ctx);
        pid_t collected;
        do { collected = waitpid(child, NULL, 0); } while (collected < 0 && errno == EINTR);
        return;
    }
    double before = monotonic_ms();
    handle_async_mount_event(ctx);
    double callback_ms = monotonic_ms() - before;
    close(p[0]);
    if (r->exit_delay_ms) {
        bool fast = callback_ms < 150.0;
        printf("  %s %s 非阻塞收尾 — callback=%.3fms child_exit_delay=%dms\n",
               fast ? "PASS" : "FAIL", r->label, callback_ms, r->exit_delay_ms);
        if (fast) g_pass++; else g_fail++;
    }

    bool okv = (g_retries == r->want_retry) && (g_removed == r->want_removed);
    printf("  %s %s — payload=%d pre_reaped=%d retries=%d(期望%d) removed=%d(期望%d)\n",
           okv ? "PASS" : "FAIL", r->label, r->payload, r->pre_reap, g_retries, r->want_retry,
           g_removed, r->want_removed);
    if (okv) {
        g_pass++;
    } else {
        g_fail++;
    }
    /* 新回调可能把存活子进程交给主循环；本驱动只回收自己的有限寿命子进程。 */
    pid_t collected;
    do { collected = waitpid(child, NULL, 0); } while (collected < 0 && errno == EINTR);
    errno = 0;
    bool reaped = waitpid(child, NULL, WNOHANG) == -1 && errno == ECHILD;
    printf("  %s %s 子进程已回收\n", reaped ? "PASS" : "FAIL", r->label);
    if (reaped) g_pass++; else g_fail++;
}

int main(void) {
    const Row rows[] = {
        {"failure_control（失败码经管道回传，未预收尸）", ENOENT, 0, 1, 1, 0},
        {"failure_ECHILD（失败码经管道回传，主循环先收尸）", ENOENT, 1, 1, 1, 0},
        {"EOF_control（status 缺失=EOF，未预收尸）", -1, 0, 1, 1, 0},
        {"EOF_ECHILD（status 缺失=EOF，主循环先收尸）", -1, 1, 1, 1, 0},
        {"success_control（成功，未预收尸）", 0, 0, 0, 0, 0},
        {"success_ECHILD（成功，主循环先收尸）", 0, 1, 0, 0, 0},
        {"success_late_exit", 0, 0, 0, 0, 600},
        {"failure_late_exit", ENOENT, 0, 1, 1, 600},
        {"EOF_late_exit", -1, 0, 1, 1, 600},
    };
    printf("异步挂载完成事件：结果判定与收尸解耦用例\n");
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) run_row(&rows[i]);
    errno = 0;
    bool no_children = waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD;
    printf("  %s 所有测试子进程均已回收\n", no_children ? "PASS" : "FAIL");
    if (no_children) g_pass++; else g_fail++;
    printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
