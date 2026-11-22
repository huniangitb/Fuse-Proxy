/* L0 夹具：直编真实 src/injector/mount_ops.c，验证「一轮挂载操作独占」的锁语义。
 *
 * 这不是挂载/内核证明：只证明这把锁本身——互斥、trylock 绝不阻塞调用线程、
 * 跨线程真串行（同一刻只有一个持有者）。挂载是否真被串行化由注入器的接线静态检查
 * 与真机验收覆盖。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* usleep/useconds_t：-std=c23 是严格 ISO 模式 */
#endif

#include "mount_ops.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TRY_MAX_US 1000        /* trylock 只在锁字上空转：上限 1ms（实测 <2µs） */
#define HOLD_US 150000          /* block 模式：持有者按住 150ms */
#define ITERS 200
#define WORKERS 4

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000 + (long long)ts.tv_nsec / 1000;
}

static _Atomic int g_ready;
static _Atomic int g_release;
static long g_hold_us;

static void* hold_thread(void* arg) {
    (void)arg;
    mount_ops_begin();
    atomic_store(&g_ready, 1);
    if (g_hold_us > 0) {
        usleep((useconds_t)g_hold_us);
    } else {
        while (!atomic_load(&g_release)) usleep(1000);
    }
    mount_ops_end();
    return NULL;
}

static bool wait_ready(long long limit_us) {
    const long long deadline = now_us() + limit_us;
    while (now_us() < deadline) {
        if (atomic_load(&g_ready)) return true;
        usleep(500);
    }
    return atomic_load(&g_ready) != 0;
}

/* 有别的线程持有时 trylock 必须立刻失败；释放后必须成功——且都不许阻塞。 */
static int mode_try(void) {
    g_hold_us = -1;
    atomic_store(&g_ready, 0);
    atomic_store(&g_release, 0);
    pthread_t th;
    if (pthread_create(&th, NULL, hold_thread, NULL) != 0) {
        printf("start_failed=1\n");
        return 1;
    }
    if (!wait_ready(5000000)) {
        printf("holder_ready=0\n");
        atomic_store(&g_release, 1);
        pthread_join(th, NULL);
        return 1;
    }
    long long t0 = now_us();
    const bool busy = mount_ops_try_begin();
    const long long busy_us = now_us() - t0;
    atomic_store(&g_release, 1);
    pthread_join(th, NULL);
    t0 = now_us();
    const bool free_again = mount_ops_try_begin();
    const long long free_us = now_us() - t0;
    if (free_again) mount_ops_end();
    printf("try_busy=%d try_busy_us=%lld try_free=%d try_free_us=%lld\n",
           (int)busy, busy_us, (int)free_again, free_us);
    return 0;
}

/* begin 阻塞到真正拿到锁：持有者按 150ms，等待必须覆盖它的剩余持有时间。 */
static int mode_block(void) {
    g_hold_us = HOLD_US;
    atomic_store(&g_ready, 0);
    pthread_t th;
    if (pthread_create(&th, NULL, hold_thread, NULL) != 0) {
        printf("start_failed=1\n");
        return 1;
    }
    if (!wait_ready(5000000)) {
        printf("holder_ready=0\n");
        pthread_join(th, NULL);
        return 1;
    }
    const long long t0 = now_us();
    mount_ops_begin();
    const long long waited_us = now_us() - t0;
    mount_ops_end();
    pthread_join(th, NULL);
    printf("block_wait_us=%lld hold_us=%lld\n", waited_us, (long long)HOLD_US);
    return 0;
}

static _Atomic int g_inside;
static _Atomic int g_max_inside;
static _Atomic int g_ops;

static void bump_max(int cur) {
    int prev = atomic_load(&g_max_inside);
    while (cur > prev && !atomic_compare_exchange_weak(&g_max_inside, &prev, cur)) {
    }
}

static void* work_thread(void* arg) {
    (void)arg;
    for (int i = 0; i < ITERS; i++) {
        mount_ops_begin();
        bump_max(atomic_fetch_add(&g_inside, 1) + 1);
        usleep(50);
        atomic_fetch_sub(&g_inside, 1);
        mount_ops_end();
        atomic_fetch_add(&g_ops, 1);
    }
    return NULL;
}

/* 多线程各跑 200 轮：临界区里同一刻只能有一个线程（并发计数最大 1）。 */
static int mode_serialize(void) {
    atomic_store(&g_inside, 0);
    atomic_store(&g_max_inside, 0);
    atomic_store(&g_ops, 0);
    pthread_t th[WORKERS];
    for (int i = 0; i < WORKERS; i++) {
        if (pthread_create(&th[i], NULL, work_thread, NULL) != 0) {
            printf("start_failed=1\n");
            for (int j = 0; j < i; j++) pthread_join(th[j], NULL);
            return 1;
        }
    }
    for (int i = 0; i < WORKERS; i++) pthread_join(th[i], NULL);
    printf("concurrency_max=%d ops=%d workers=%d iters=%d\n", atomic_load(&g_max_inside),
           atomic_load(&g_ops), WORKERS, ITERS);
    return 0;
}

/* 无人持有时的 trylock 成功率与耗时要稳（事件循环每 tick 都可能试一次）。 */
static int mode_tryfree(void) {
    long long worst = 0;
    int taken = 0;
    for (int i = 0; i < 1000; i++) {
        const long long t0 = now_us();
        const bool got = mount_ops_try_begin();
        const long long cost = now_us() - t0;
        if (got) {
            taken++;
            mount_ops_end();
        }
        if (cost > worst) worst = cost;
    }
    printf("tryfree_taken=%d tryfree_worst_us=%lld\n", taken, worst);
    return 0;
}

int main(int argc, char** argv) {
    const char* mode = argc > 1 ? argv[1] : "try";
    if (strcmp(mode, "try") == 0) return mode_try();
    if (strcmp(mode, "block") == 0) return mode_block();
    if (strcmp(mode, "serialize") == 0) return mode_serialize();
    if (strcmp(mode, "tryfree") == 0) return mode_tryfree();
    fprintf(stderr, "usage: %s try|block|serialize|tryfree\n", argv[0]);
    return 2;
}
