/* 审计工作线程判别夹具：直编真实 src/injector/audit_worker.c（无替身），
 * 只把审计本体（audit_tracked_apps / audit_and_remount_specific_apps /
 * audit_running_apps）换成「慢动作 + 记账」的替身——它们是挂载/卸载的边界，
 * 夹具不碰真实挂载。
 *
 * 用途：
 *   defer    —— 30 次突发请求在调用线程上必须 µs 级返回，慢审计只跑 1~3 轮，
 *               恒只有一个 worker、跑在别的线程上，空闲后线程数回到 1；
 *   inline   —— 旧形态对照：同样的慢审计在调用线程上直接跑，量化被冻住的时长；
 *   mode_v1 / mode_reset_v2 / mode_specific_v2 —— 粒度选择与变更集合语义
 *               （v1 全量对账、reset 走全量审计、具体变更去重后原样送达）；
 *   shutdown —— 退出等手上那一轮跑完，之后的请求不再执行。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "audit_worker.h"
#include "injector.h" /* InjectMethod 与 g_inject_method（生产侧同样包含） */

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* 生产侧注入方法全局（injector.h 里两个 inline 判定读它） */
InjectMethod g_inject_method = INJECT_METHOD_V2;

static _Atomic int g_calls_tracked;
static _Atomic int g_calls_specific;
static _Atomic int g_calls_running;
static _Atomic int g_active;
static _Atomic int g_peak;
static _Atomic int g_offmain;
static _Atomic int g_max_items;
static char g_seen_pkgs[NSP_AUDIT_MAX_CHANGED][128];
static int g_seen_user[NSP_AUDIT_MAX_CHANGED];
static _Atomic int g_seen_count;
static int g_slow_ms = 150;
static pthread_t g_main_thread;

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

/* 慢审计替身：只占住 worker 自己，不碰任何生产状态 */
static void enter_slow(void) {
    const int running = atomic_fetch_add_explicit(&g_active, 1, memory_order_acq_rel) + 1;
    int peak = atomic_load_explicit(&g_peak, memory_order_acquire);
    while (running > peak &&
           !atomic_compare_exchange_weak_explicit(&g_peak, &peak, running,
                                                  memory_order_acq_rel, memory_order_acquire)) {
    }
    if (!pthread_equal(pthread_self(), g_main_thread))
        atomic_fetch_add_explicit(&g_offmain, 1, memory_order_acq_rel);
    sleep_ms(g_slow_ms);
    atomic_fetch_sub_explicit(&g_active, 1, memory_order_acq_rel);
}

void audit_tracked_apps(void) {
    enter_slow();
    atomic_fetch_add_explicit(&g_calls_tracked, 1, memory_order_acq_rel);
}

void audit_and_remount_specific_apps(ChangedPkg* changed, int count) {
    int seen = atomic_load_explicit(&g_seen_count, memory_order_acquire);
    if (seen == 0) {
        const int n = count > NSP_AUDIT_MAX_CHANGED ? NSP_AUDIT_MAX_CHANGED : count;
        for (int i = 0; i < n; i++) {
            snprintf(g_seen_pkgs[i], sizeof g_seen_pkgs[i], "%s", changed[i].pkg_name);
            g_seen_user[i] = changed[i].user_id;
        }
        atomic_store_explicit(&g_seen_count, n, memory_order_release);
    }
    int mx = atomic_load_explicit(&g_max_items, memory_order_acquire);
    while (count > mx &&
           !atomic_compare_exchange_weak_explicit(&g_max_items, &mx, count,
                                                  memory_order_acq_rel, memory_order_acquire)) {
    }
    enter_slow();
    atomic_fetch_add_explicit(&g_calls_specific, 1, memory_order_acq_rel);
}

void audit_running_apps(void) {
    enter_slow();
    atomic_fetch_add_explicit(&g_calls_running, 1, memory_order_acq_rel);
}

static void settle(void) {
    const long long start = now_us();
    int last = -1;
    for (;;) {
        const int total = atomic_load_explicit(&g_calls_tracked, memory_order_acquire) +
                          atomic_load_explicit(&g_calls_specific, memory_order_acquire) +
                          atomic_load_explicit(&g_calls_running, memory_order_acquire);
        if (!nsp_audit_active() && total == last) break;
        last = total;
        if (now_us() - start > 20000000LL) break;
        sleep_ms(5);
    }
    /* worker 空闲 200ms 自退，再多等一会儿确保线程真的没了 */
    sleep_ms(400);
}

static int total_runs(void) {
    return atomic_load_explicit(&g_calls_tracked, memory_order_acquire) +
           atomic_load_explicit(&g_calls_specific, memory_order_acquire) +
           atomic_load_explicit(&g_calls_running, memory_order_acquire);
}

static void report(const char* mode, long long call_us_max, long long total_us, int runs) {
    printf("mode=%s call_us_max=%lld total_us=%lld runs=%d tracked=%d specific=%d running=%d "
           "offmain=%d peak=%d threads=%d max_items=%d seen=%d\n",
           mode, call_us_max, total_us, runs,
           atomic_load_explicit(&g_calls_tracked, memory_order_acquire),
           atomic_load_explicit(&g_calls_specific, memory_order_acquire),
           atomic_load_explicit(&g_calls_running, memory_order_acquire),
           atomic_load_explicit(&g_offmain, memory_order_acquire),
           atomic_load_explicit(&g_peak, memory_order_acquire), thread_count(),
           atomic_load_explicit(&g_max_items, memory_order_acquire),
           atomic_load_explicit(&g_seen_count, memory_order_acquire));
}

static void run_defer(void) {
    long long call_us_max = 0;
    const long long start = now_us();
    for (int i = 0; i < 30; i++) {
        ChangedPkg c;
        memset(&c, 0, sizeof c);
        snprintf(c.pkg_name, sizeof c.pkg_name, "com.burst.app%d", i);
        c.user_id = 0;
        const long long t0 = now_us();
        nsp_audit_request(&c, 1, false);
        const long long dt = now_us() - t0;
        if (dt > call_us_max) call_us_max = dt;
        sleep_ms(2);
    }
    const long long total_us = now_us() - start;
    settle();
    report("defer", call_us_max, total_us, total_runs());
}

static void run_inline(void) {
    /* 旧形态：调用线程自己跑慢审计（对照，不进 worker） */
    const long long start = now_us();
    for (int i = 0; i < 30; i++) {
        ChangedPkg c;
        memset(&c, 0, sizeof c);
        snprintf(c.pkg_name, sizeof c.pkg_name, "com.burst.app%d", i);
        c.user_id = 0;
        audit_and_remount_specific_apps(&c, 1);
    }
    const long long total_us = now_us() - start;
    report("inline", 0, total_us, total_runs());
}

static void run_mode(const char* mode) {
    if (strcmp(mode, "mode_v1") == 0) {
        g_inject_method = INJECT_METHOD_V1;
        nsp_audit_request(nullptr, 0, false);
    } else if (strcmp(mode, "mode_reset_v2") == 0) {
        g_inject_method = INJECT_METHOD_V2;
        ChangedPkg c;
        memset(&c, 0, sizeof c);
        snprintf(c.pkg_name, sizeof c.pkg_name, "com.reset.app");
        c.user_id = -1;
        nsp_audit_request(&c, 1, true);
    } else { /* mode_specific_v2：两次请求，第二次带重复条目 */
        g_inject_method = INJECT_METHOD_V2;
        g_slow_ms = 120;
        ChangedPkg a[2];
        memset(a, 0, sizeof a);
        snprintf(a[0].pkg_name, sizeof a[0].pkg_name, "com.one.app");
        a[0].user_id = 0;
        snprintf(a[1].pkg_name, sizeof a[1].pkg_name, "com.two.app");
        a[1].user_id = 10;
        nsp_audit_request(a, 2, false);
        ChangedPkg b[3];
        memset(b, 0, sizeof b);
        snprintf(b[0].pkg_name, sizeof b[0].pkg_name, "com.one.app");
        b[0].user_id = 0; /* 与上一轮重复，必须去重 */
        snprintf(b[1].pkg_name, sizeof b[1].pkg_name, "com.three.app");
        b[1].user_id = 0;
        snprintf(b[2].pkg_name, sizeof b[2].pkg_name, "com.four.app");
        b[2].user_id = 10;
        nsp_audit_request(b, 3, false);
    }
    settle();
    report(mode, 0, 0, total_runs());
    if (atomic_load_explicit(&g_seen_count, memory_order_acquire) > 0) {
        printf("seen_items=");
        for (int i = 0; i < atomic_load_explicit(&g_seen_count, memory_order_acquire); i++) {
            printf("%s:%d,", g_seen_pkgs[i], g_seen_user[i]);
        }
        printf("\n");
    }
}

static void run_shutdown(void) {
    g_inject_method = INJECT_METHOD_V2;
    g_slow_ms = 150;
    ChangedPkg c;
    memset(&c, 0, sizeof c);
    snprintf(c.pkg_name, sizeof c.pkg_name, "com.shutdown.app");
    c.user_id = 0;
    nsp_audit_request(&c, 1, false);
    sleep_ms(20); /* 让 worker 先把这一轮抓走 */
    const long long t0 = now_us();
    nsp_audit_shutdown();
    const long long shutdown_us = now_us() - t0;
    const int runs_before = total_runs();
    nsp_audit_request(&c, 1, false); /* 退出后请求不再执行 */
    sleep_ms(300);
    const int runs_after = total_runs();
    printf("mode=shutdown shutdown_us=%lld runs_before=%d runs_after=%d threads=%d offmain=%d "
           "active=%d\n",
           shutdown_us, runs_before, runs_after, thread_count(),
           atomic_load_explicit(&g_offmain, memory_order_acquire),
           nsp_audit_active() ? 1 : 0);
}

int main(int argc, char** argv) {
    g_main_thread = pthread_self();
    const char* mode = argc > 1 ? argv[1] : "defer";
    if (strcmp(mode, "defer") == 0) {
        run_defer();
    } else if (strcmp(mode, "inline") == 0) {
        run_inline();
    } else if (strcmp(mode, "shutdown") == 0) {
        run_shutdown();
    } else {
        run_mode(mode);
    }
    return 0;
}
