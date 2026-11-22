#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* fast_pid 缓存的跨线程判别：线程 A 扮演 FUSE 恢复 worker（反复 fast_pid_each），
   线程 B 扮演事件循环（每轮 fast_pid_cache_clear + fast_pid_each）。旧实现没有锁，
   A 的修剪/追加与 B 的释放会撞成 use-after-free——ASan 构建下必然报到。 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "fast_pid.h"

static _Atomic long g_saw_a;
static _Atomic long g_saw_b;

static int cb_a(int pid, const char* cmd, void* data) {
    (void)pid; (void)cmd; (void)data;
    atomic_fetch_add_explicit(&g_saw_a, 1, memory_order_relaxed);
    return 0;
}

static int cb_b(int pid, const char* cmd, void* data) {
    (void)pid; (void)cmd; (void)data;
    atomic_fetch_add_explicit(&g_saw_b, 1, memory_order_relaxed);
    return 0;
}

static int g_iters = 300;

static void* worker_scan(void* unused) {
    (void)unused;
    for (int i = 0; i < g_iters; i++) fast_pid_each(cb_a, NULL);
    return NULL;
}

static void* loop_clear(void* unused) {
    (void)unused;
    for (int i = 0; i < g_iters; i++) {
        fast_pid_cache_clear();
        fast_pid_each(cb_b, NULL);
    }
    return NULL;
}

int main(int argc, char** argv) {
    if (argc > 1) g_iters = atoi(argv[1]);
    if (g_iters <= 0) g_iters = 300;
    if (fast_pid_init() != 0) {
        printf("init=fail\n");
        return 2;
    }
    pthread_t a;
    pthread_t b;
    if (pthread_create(&a, NULL, worker_scan, NULL) != 0) return 3;
    if (pthread_create(&b, NULL, loop_clear, NULL) != 0) return 3;
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    /* 两线程都退出后再校验缓存仍可用：旧实现可能在 trim 与 clear 之间留下
       已释放的指针，这里再走一遍能抓到「清理后仍访问」的形态。 */
    fast_pid_cache_clear();
    fast_pid_each(cb_a, NULL);
    const long saw_a = atomic_load(&g_saw_a);
    const long saw_b = atomic_load(&g_saw_b);
    printf("iters=%d calls_a=%ld calls_b=%ld clear_after_join=ok\n", g_iters, saw_a, saw_b);
    fast_pid_cleanup();
    printf("cleanup=ok\n");
    return (saw_a > 0 && saw_b > 0) ? 0 : 4;
}
