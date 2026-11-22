/* 配置视图两段式读取的判别夹具：直编真实 reload_stage.c + 真实 config_parser.c。
 *
 * 目的：证明「读盘 + pm 探测」不在调用线程（事件循环）上发生。主配置文件的
 * fopen 经 --wrap=fopen 拦截并人为变慢（work_ms），因此：
 *   offload  —— request 必须在微秒级返回，视图由 worker 读回来后取走；
 *   inline   —— 同二进制对照组：直接 config_read_view 会把调用线程冻住整段；
 *   coalesce —— 慢读进行中再发 50 次请求，只许多读 1~2 轮（请求合并）；
 *   shutdown —— 退出等手上那轮读完（有界），结果丢弃、线程数回 1；
 *   empty    —— 读到空视图（count==0）也必须算「取到」，否则重载会被静默丢弃；
 *   early    —— 没有备好视图时 take 必须返回 false。
 *
 * 用法：driver <mode> <main_conf_path> <work_ms>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config_parser.h"
#include "reload_stage.h"

static char g_main_path[PATH_MAX];
static int g_work_ms;
static _Atomic int g_reads;
static _Atomic int g_in_flight;
static _Atomic int g_tid_seen;
static pthread_t g_read_tid;

static int64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* -1 或 -2 表示读不进来（夹具用空视图）；主配置文件在这里人为变慢 */
FILE* __real_fopen(const char* path, const char* mode);
FILE* __wrap_fopen(const char* path, const char* mode) {
    if (path && mode && g_main_path[0] && strcmp(path, g_main_path) == 0) {
        atomic_fetch_add(&g_reads, 1);
        g_read_tid = pthread_self();
        atomic_store(&g_tid_seen, 1);
        atomic_store(&g_in_flight, 1);
        if (g_work_ms > 0) usleep((useconds_t)g_work_ms * 1000u);
        FILE* f = __real_fopen(path, mode);
        atomic_store(&g_in_flight, 0);
        return f;
    }
    return __real_fopen(path, mode);
}

static int task_count(void) {
    DIR* d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    struct dirent* de;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] != '.') n++;
    }
    closedir(d);
    return n;
}

/* 线程退出后，/proc/self/task 里的条目摘除晚于 pthread_join/shutdown 返回：
   直接读一次会在负载下看到「已 join 的线程还留着」（实测 8 连跑红 2 次）。
   这里只把观测改成有界收敛（最多 300ms，轮询 1ms），断言仍要求回到 1——
   不是放宽判据，而是不把内核收尾的那几微秒当成产品泄漏。 */
static int task_count_settled(void) {
    for (int i = 0; i < 300; i++) {
        const int n = task_count();
        if (n == 1) return n;
        usleep(1000);
    }
    return task_count();
}

static bool wait_in_flight(int timeout_ms) {
    for (int waited = 0; waited < timeout_ms; waited++) {
        if (atomic_load(&g_in_flight)) return true;
        usleep(1000);
    }
    return false;
}

/* 等读取 worker 发布结果（就绪 eventfd 可读），返回实际等待毫秒数；超时返回 -1 */
static int wait_ready(int fd, int timeout_ms) {
    const int64_t t0 = now_us();
    for (;;) {
        uint64_t v = 0;
        if (read(fd, &v, sizeof v) == (ssize_t)sizeof v)
            return (int)((now_us() - t0) / 1000);
        if ((now_us() - t0) / 1000 > timeout_ms) return -1;
        usleep(1000);
    }
}

static void report(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void report(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

static int mode_offload(void) {
    const int fd = nsp_reload_stage_start(g_main_path);
    if (fd < 0) { report("start=0"); return 1; }
    const int64_t t0 = now_us();
    nsp_reload_stage_request();
    const int64_t request_us = now_us() - t0;
    const int ready_ms = wait_ready(fd, 5000);
    NspCfgRec* recs = nullptr;
    int count = 0;
    const bool took = nsp_reload_stage_take(&recs, &count);
    const bool on_worker = atomic_load(&g_tid_seen) && !pthread_equal(g_read_tid, pthread_self());
    if (recs) config_free_view(recs, count);
    nsp_reload_stage_shutdown();
    report("start=1 request_us=%lld ready_ms=%d took=%d count=%d read_on_worker=%d reads=%d "
           "threads_after=%d",
           (long long)request_us, ready_ms, took ? 1 : 0, count, on_worker ? 1 : 0,
           atomic_load(&g_reads), task_count_settled());
    return 0;
}

static int mode_inline(void) {
    const int64_t t0 = now_us();
    NspCfgRec* recs = nullptr;
    int count = 0;
    (void)config_read_view(g_main_path, &recs, &count);
    const int64_t inline_ms = (now_us() - t0) / 1000;
    const bool on_main = atomic_load(&g_tid_seen) && pthread_equal(g_read_tid, pthread_self());
    if (recs) config_free_view(recs, count);
    report("inline_ms=%lld count=%d read_on_main=%d", (long long)inline_ms, count,
           on_main ? 1 : 0);
    return 0;
}

static int mode_coalesce(void) {
    const int fd = nsp_reload_stage_start(g_main_path);
    if (fd < 0) { report("start=0"); return 1; }
    nsp_reload_stage_request();
    if (!wait_in_flight(2000)) { report("start=1 inflight=0"); nsp_reload_stage_shutdown(); return 1; }
    const int64_t t0 = now_us();
    for (int i = 0; i < 50; i++) nsp_reload_stage_request();
    const int64_t burst_us = now_us() - t0;
    /* 收完全部轮次：每轮就绪取一次，直到 quiet_ms 内既没在读也没有新结果 */
    int rounds = 0;
    int quiet = 0;
    while (quiet < 50) {
        if (read(fd, &(uint64_t){0}, sizeof(uint64_t)) == (ssize_t)sizeof(uint64_t)) {
            NspCfgRec* recs = nullptr;
            int count = 0;
            if (nsp_reload_stage_take(&recs, &count)) {
                if (recs) config_free_view(recs, count);
                rounds++;
            }
            quiet = 0;
            continue;
        }
        if (atomic_load(&g_in_flight)) {
            quiet = 0;
        } else {
            quiet++;
        }
        usleep(1000);
    }
    nsp_reload_stage_shutdown();
    report("start=1 burst_us=%lld rounds=%d reads=%d threads_after=%d", (long long)burst_us,
           rounds, atomic_load(&g_reads), task_count_settled());
    return 0;
}

static int mode_shutdown(void) {
    const int fd = nsp_reload_stage_start(g_main_path);
    if (fd < 0) { report("start=0"); return 1; }
    nsp_reload_stage_request();
    if (!wait_in_flight(2000)) { report("start=1 inflight=0"); nsp_reload_stage_shutdown(); return 1; }
    const int64_t t0 = now_us();
    nsp_reload_stage_shutdown();
    const int64_t shutdown_ms = (now_us() - t0) / 1000;
    NspCfgRec* recs = nullptr;
    int count = 0;
    const bool leftover = nsp_reload_stage_take(&recs, &count);
    if (recs) config_free_view(recs, count);
    report("start=1 shutdown_ms=%lld leftover=%d reads=%d threads_after=%d",
           (long long)shutdown_ms, leftover ? 1 : 0, atomic_load(&g_reads), task_count_settled());
    return 0;
}

static int mode_empty(void) {
    const int fd = nsp_reload_stage_start(g_main_path);
    if (fd < 0) { report("start=0"); return 1; }
    nsp_reload_stage_request();
    const int ready_ms = wait_ready(fd, 5000);
    NspCfgRec* recs = nullptr;
    int count = -1;
    const bool took = nsp_reload_stage_take(&recs, &count);
    if (recs) config_free_view(recs, count);
    nsp_reload_stage_shutdown();
    report("start=1 ready_ms=%d took=%d count=%d", ready_ms, took ? 1 : 0, count);
    return 0;
}

static int mode_early(void) {
    const int fd = nsp_reload_stage_start(g_main_path);
    if (fd < 0) { report("start=0"); return 1; }
    NspCfgRec* recs = nullptr;
    int count = -1;
    const bool took = nsp_reload_stage_take(&recs, &count);
    if (recs) config_free_view(recs, count);
    nsp_reload_stage_shutdown();
    report("start=1 early_take=%d", took ? 1 : 0);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <mode> <main_conf> <work_ms>\n", argv[0]);
        return 2;
    }
    const char* mode = argv[1];
    snprintf(g_main_path, sizeof g_main_path, "%s", argv[2]);
    g_work_ms = atoi(argv[3]);
    config_set_scan_users_skip_pm(true); /* 夹具不跑 pm：慢读由 --wrap=fopen 注入 */
    if (strcmp(mode, "offload") == 0) return mode_offload();
    if (strcmp(mode, "inline") == 0) return mode_inline();
    if (strcmp(mode, "coalesce") == 0) return mode_coalesce();
    if (strcmp(mode, "shutdown") == 0) return mode_shutdown();
    if (strcmp(mode, "empty") == 0) return mode_empty();
    if (strcmp(mode, "early") == 0) return mode_early();
    fprintf(stderr, "unknown mode %s\n", mode);
    return 2;
}
