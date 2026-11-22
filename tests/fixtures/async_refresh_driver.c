/* 异步刷新判别夹具：直编真实 src/injector/async_refresh.c（无替身）。
 *
 * 目的：证明「一次慢查询」不会再拖住调用线程，且突发请求被合并成 1~2 轮回调、
 * 始终只有一个 worker 线程。inline 模式复刻旧形态（调用线程直接执行慢回调），
 * 用来量化被冻住的时长。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "async_refresh.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static _Atomic int g_calls;
static _Atomic int g_active;
static _Atomic int g_peak;
static int g_cb_ms = 120;

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000LL;
}

static void sleep_ms(int ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

/* 真实慢查询替身：只占住 worker 自己，不碰任何生产状态 */
static void slow_cb(void* ctx) {
    (void)ctx;
    const int running = atomic_fetch_add_explicit(&g_active, 1, memory_order_acq_rel) + 1;
    int peak = atomic_load_explicit(&g_peak, memory_order_acquire);
    while (running > peak &&
           !atomic_compare_exchange_weak_explicit(&g_peak, &peak, running,
                                                  memory_order_acq_rel, memory_order_acquire)) {
    }
    sleep_ms(g_cb_ms);
    atomic_fetch_add_explicit(&g_calls, 1, memory_order_acq_rel);
    atomic_fetch_sub_explicit(&g_active, 1, memory_order_acq_rel);
}

static int thread_count(void) {
    DIR* d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_name[0] != '.') n++;
    }
    closedir(d);
    return n;
}

/* 等到没有 worker 在跑、且回调计数稳定；返回等到线程数归一的耗时 */
static long long settle(int* final_threads) {
    const long long start = now_ms();
    int last = -1;
    for (;;) {
        const int calls = atomic_load_explicit(&g_calls, memory_order_acquire);
        if (!nsp_async_refresh_active() && calls == last) break;
        last = calls;
        if (now_ms() - start > 20000) break;
        sleep_ms(5);
    }
    int threads = thread_count();
    while (threads > 1 && now_ms() - start <= 20000) {
        sleep_ms(5);
        threads = thread_count();
    }
    *final_threads = threads;
    return now_ms() - start;
}

static int mode_burst(int requests) {
    nsp_async_refresh_init(slow_cb, NULL);
    long long max_call_us = 0;
    const long long start_us = now_us();
    for (int i = 0; i < requests; i++) {
        const long long t0 = now_us();
        nsp_async_refresh_request();
        const long long dur = now_us() - t0;
        if (dur > max_call_us) max_call_us = dur;
    }
    const long long total_us = now_us() - start_us;
    int threads = -1;
    const long long settle_ms = settle(&threads);
    printf("mode=burst requests=%d call_max_us=%lld call_total_us=%lld invocations=%d "
           "peak=%d threads_after=%d settle_ms=%lld active_after=%d\n",
           requests, max_call_us, total_us, atomic_load_explicit(&g_calls, memory_order_acquire),
           atomic_load_explicit(&g_peak, memory_order_acquire), threads, settle_ms,
           (int)nsp_async_refresh_active());
    return 0;
}

static int mode_late(void) {
    nsp_async_refresh_init(slow_cb, NULL);
    const int before = atomic_load_explicit(&g_calls, memory_order_acquire);
    nsp_async_refresh_request();
    int threads = -1;
    (void)settle(&threads);
    const int after = atomic_load_explicit(&g_calls, memory_order_acquire);
    printf("mode=late before=%d after=%d delta=%d threads_after=%d\n", before, after,
           after - before, threads);
    return 0;
}

static int mode_shutdown(void) {
    nsp_async_refresh_init(slow_cb, NULL);
    nsp_async_refresh_request();
    sleep_ms(20); /* 让 worker 已经进到慢回调里 */
    const long long t0 = now_ms();
    nsp_async_refresh_shutdown();
    const long long shutdown_ms = now_ms() - t0;
    const int calls_after_shutdown = atomic_load_explicit(&g_calls, memory_order_acquire);
    nsp_async_refresh_request();
    sleep_ms(80);
    const int calls_after_late = atomic_load_explicit(&g_calls, memory_order_acquire);
    int threads = -1;
    (void)settle(&threads);
    printf("mode=shutdown cb_ms=%d shutdown_ms=%lld calls_after_shutdown=%d late_requests=%d "
           "threads_after=%d\n",
           g_cb_ms, shutdown_ms, calls_after_shutdown, calls_after_late - calls_after_shutdown,
           threads);
    return 0;
}

/* 旧形态：调用线程同步执行同一段慢回调（无异步刷新） */
static int mode_inline(int requests) {
    const long long t0 = now_ms();
    for (int i = 0; i < requests; i++) slow_cb(NULL);
    printf("mode=inline requests=%d inline_total_ms=%lld\n", requests, now_ms() - t0);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s burst|late|shutdown|inline [n] [cb_ms]\n", argv[0]);
        return 2;
    }
    if (argc >= 4) g_cb_ms = atoi(argv[3]);
    const char* mode = argv[1];
    if (strcmp(mode, "burst") == 0) return mode_burst(argc >= 3 ? atoi(argv[2]) : 50);
    if (strcmp(mode, "late") == 0) return mode_late();
    if (strcmp(mode, "shutdown") == 0) return mode_shutdown();
    if (strcmp(mode, "inline") == 0) return mode_inline(argc >= 3 ? atoi(argv[2]) : 50);
    fprintf(stderr, "unknown mode %s\n", mode);
    return 2;
}
