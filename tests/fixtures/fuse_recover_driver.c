/* FUSE 崩溃恢复阶段化的判别夹具：直编真实 src/injector/fuse_recover.c，
 * 用「慢回调」代替真实重启序列（等旧实例退出 + 卸载复核 + fork 新实例 +
 * 全进程扫描），只验证阶段本身：请求不阻塞调用线程、回调不在调用线程上跑、
 * 完成经 eventfd 交回、突发请求合并、shutdown 等手上那轮跑完。 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "fuse_recover.h"

static _Atomic int g_runs;
static _Atomic long long g_work_us = 150000;
static _Atomic int g_cb_off_main;
static pid_t g_main_tid;

static pid_t self_tid(void) { return (pid_t)syscall(SYS_gettid); }

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

/* /proc/self/task 下的真实 TID 目录数（worker 退出后应回到 1） */
static int threads_now(void) {
    DIR* d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    struct dirent* ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        n++;
    }
    closedir(d);
    return n;
}

/* 线程退出后 /proc/self/task 条目摘除晚于完成通知/关停返回：观测改成有界收敛
   （最多 300ms），断言仍要求等于 1——不把内核收尾的那几微秒当成线程泄漏。 */
static int threads_settled(void) {
    for (int i = 0; i < 300; i++) {
        const int n = threads_now();
        if (n == 1) return n;
        usleep(1000);
    }
    return threads_now();
}

static void slow_cb(void* ctx) {
    (void)ctx;
    if (self_tid() != g_main_tid) atomic_store(&g_cb_off_main, 1);
    usleep((useconds_t)atomic_load(&g_work_us));
    atomic_fetch_add(&g_runs, 1);
}

static int wait_ready(int fd, int timeout_ms, long long* ready_ms) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
    const long long t0 = now_us();
    const int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return 0;
    unsigned long long drained = 0;
    while (read(fd, &drained, sizeof drained) == (ssize_t)sizeof drained) {
    }
    if (ready_ms) *ready_ms = (now_us() - t0) / 1000;
    return 1;
}

static void mode_offload(int work_ms) {
    atomic_store(&g_work_us, (long long)work_ms * 1000);
    const int fd = nsp_fuse_recover_start(slow_cb, NULL);
    if (fd < 0) {
        printf("start_failed=1\n");
        return;
    }
    const long long t0 = now_us();
    const bool queued = nsp_fuse_recover_request();
    const long long request_us = now_us() - t0;
    long long ready_ms = -1;
    const int got = wait_ready(fd, 10000, &ready_ms);
    const bool took = got && nsp_fuse_recover_take();
    usleep(20000);
    printf("request_us=%lld ready_ms=%lld got=%d took=%d runs=%d cb_off_main=%d threads=%d\n",
           request_us, ready_ms, got, (int)took, atomic_load(&g_runs), atomic_load(&g_cb_off_main),
           threads_settled());
    printf("queued=%d\n", (int)queued);
    nsp_fuse_recover_shutdown();
}

static void mode_inline(int work_ms) {
    atomic_store(&g_work_us, (long long)work_ms * 1000);
    const long long t0 = now_us();
    slow_cb(NULL);
    const long long inline_ms = (now_us() - t0) / 1000;
    printf("inline_ms=%lld cb_off_main=%d runs=%d\n", inline_ms, atomic_load(&g_cb_off_main),
           atomic_load(&g_runs));
}

static void mode_coalesce(int work_ms) {
    atomic_store(&g_work_us, (long long)work_ms * 1000);
    const int fd = nsp_fuse_recover_start(slow_cb, NULL);
    if (fd < 0) {
        printf("start_failed=1\n");
        return;
    }
    nsp_fuse_recover_request();
    usleep(5000); /* 让第一轮先跑起来，后续请求落进「再来一轮」 */
    const long long t0 = now_us();
    for (int i = 0; i < 40; i++) nsp_fuse_recover_request();
    const long long burst_us = now_us() - t0;
    long long ready_ms = -1;
    const int got = wait_ready(fd, 10000, &ready_ms);
    const bool took = got && nsp_fuse_recover_take();
    /* 等合并出来的第二轮也跑完（合并上限是「再来一轮」） */
    usleep((useconds_t)(work_ms * 3 * 1000));
    printf("burst_us=%lld ready_ms=%lld took=%d rounds=%d threads=%d\n", burst_us, ready_ms,
           (int)took, atomic_load(&g_runs), threads_settled());
    nsp_fuse_recover_shutdown();
}

static void mode_shutdown(int work_ms) {
    atomic_store(&g_work_us, (long long)work_ms * 1000);
    const int fd = nsp_fuse_recover_start(slow_cb, NULL);
    if (fd < 0) {
        printf("start_failed=1\n");
        return;
    }
    nsp_fuse_recover_request();
    usleep(10000);
    const long long t0 = now_us();
    nsp_fuse_recover_shutdown();
    const long long shutdown_ms = (now_us() - t0) / 1000;
    const int runs_before = atomic_load(&g_runs);
    /* 关停之后再请求必须被拒绝（不新起线程） */
    const bool after_req = nsp_fuse_recover_request();
    usleep(20000);
    printf("shutdown_ms=%lld runs_before=%d runs_after=%d after_req=%d threads=%d\n", shutdown_ms,
           runs_before, atomic_load(&g_runs), (int)after_req, threads_settled());
}

static void mode_early(void) {
    const int fd = nsp_fuse_recover_start(slow_cb, NULL);
    if (fd < 0) {
        printf("start_failed=1\n");
        return;
    }
    const bool early = nsp_fuse_recover_take();
    printf("early_take=%d threads=%d\n", (int)early, threads_settled());
    nsp_fuse_recover_shutdown();
}

int main(int argc, char** argv) {
    g_main_tid = self_tid();
    if (argc < 2) {
        fprintf(stderr, "usage: %s offload|inline|coalesce|shutdown|early [work_ms]\n", argv[0]);
        return 2;
    }
    const int work_ms = argc >= 3 ? atoi(argv[2]) : 150;
    if (strcmp(argv[1], "offload") == 0) mode_offload(work_ms);
    else if (strcmp(argv[1], "inline") == 0) mode_inline(work_ms);
    else if (strcmp(argv[1], "coalesce") == 0) mode_coalesce(work_ms);
    else if (strcmp(argv[1], "shutdown") == 0) mode_shutdown(work_ms);
    else if (strcmp(argv[1], "early") == 0) mode_early();
    else {
        fprintf(stderr, "unknown mode\n");
        return 2;
    }
    return 0;
}
