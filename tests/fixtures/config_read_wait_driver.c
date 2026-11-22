/* 判别夹具：写者窗口（g_cfg_gen 奇数）里的读者必须阻塞等待，而不是自旋烧 CPU。

   链接的是真实 src/config/config_parser.c：config_read_begin/end、
   config_publish_begin/drain_readers/publish_end 全走生产实现，没有替身。
   场景等价于生产中「一个慢读者还在槽内 → 写者已置奇 → 多个 FUSE worker 进来」。
   输出一行 key=value，供 tests/test_config_read_wait.py 断言。 */
#include "config_parser.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define READERS 8
#define SLOW_IN_SLOT_US (300 * 1000) /* 槽内慢活：给排空阶段留出可判别的等待窗口 */
#define SAMPLE_US (60 * 1000)

static atomic_int g_go;
static atomic_int g_slow_in_slot;
static long long g_cpu_ns[READERS];
static long long g_wait_ns[READERS];
static long long g_return_at[READERS];
static long long g_publish_at;

static long long now_ns(clockid_t cid) {
    struct timespec ts;
    clock_gettime(cid, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void* slow_reader(void* arg) {
    (void)arg;
    uint64_t gen = config_read_begin(); /* 先持旧代际读槽 */
    atomic_store(&g_slow_in_slot, 1);
    usleep(SLOW_IN_SLOT_US); /* 槽内慢活：生产中一次慢读者 */
    config_read_end(gen);
    return nullptr;
}

static void* reader(void* arg) {
    int idx = (int)(long)arg;
    while (!atomic_load(&g_go)) sched_yield();
    long long cpu0 = now_ns(CLOCK_THREAD_CPUTIME_ID);
    long long wall0 = now_ns(CLOCK_MONOTONIC);
    uint64_t gen = config_read_begin(); /* 写者窗口里：必须阻塞等放行 */
    long long wall1 = now_ns(CLOCK_MONOTONIC);
    long long cpu1 = now_ns(CLOCK_THREAD_CPUTIME_ID);
    g_cpu_ns[idx] = cpu1 - cpu0;
    g_wait_ns[idx] = wall1 - wall0;
    g_return_at[idx] = wall1;
    (void)config_read_end(gen);
    return nullptr;
}

int main(void) {
    pthread_t slow;
    if (pthread_create(&slow, nullptr, slow_reader, nullptr) != 0) return 2;
    while (!atomic_load(&g_slow_in_slot)) usleep(1000);
    uint64_t old = config_publish_begin(); /* gen 置奇：发布窗口开始 */

    pthread_t th[READERS];
    for (int i = 0; i < READERS; i++) {
        if (pthread_create(&th[i], nullptr, reader, (void*)(long)i) != 0) return 2;
    }
    atomic_store(&g_go, 1);

    /* 采样窗口：慢读者仍持槽，读者应全部在等（不烧 CPU） */
    usleep(SAMPLE_US);
    long long cpu_a = now_ns(CLOCK_PROCESS_CPUTIME_ID);
    usleep(SAMPLE_US);
    long long cpu_b = now_ns(CLOCK_PROCESS_CPUTIME_ID);

    /* 写者排空：此刻慢读者仍持旧槽，旧实现（裸 sched_yield 自旋）会在这里
       烧掉整个窗口的 CPU；新实现退避睡眠，CPU 应接近 0。 */
    long long drain_cpu0 = now_ns(CLOCK_THREAD_CPUTIME_ID);
    long long drain_wall0 = now_ns(CLOCK_MONOTONIC);
    config_drain_readers(old); /* 真实写者排空旧读者 */
    long long drain_cpu = now_ns(CLOCK_THREAD_CPUTIME_ID) - drain_cpu0;
    long long drain_wall = now_ns(CLOCK_MONOTONIC) - drain_wall0;
    pthread_join(slow, nullptr);
    g_publish_at = now_ns(CLOCK_MONOTONIC);
    config_publish_end(old); /* 放行 + 唤醒 */
    for (int i = 0; i < READERS; i++) pthread_join(th[i], nullptr);

    long long max_cpu = 0, max_wait = 0, max_lag = 0;
    for (int i = 0; i < READERS; i++) {
        if (g_cpu_ns[i] > max_cpu) max_cpu = g_cpu_ns[i];
        if (g_wait_ns[i] > max_wait) max_wait = g_wait_ns[i];
        long long lag = g_return_at[i] - g_publish_at;
        if (lag > max_lag) max_lag = lag;
    }
    printf("readers=%d window_cpu_ms=%lld max_reader_cpu_ms=%lld max_reader_wait_ms=%lld "
           "max_return_lag_ms=%lld drain_wall_ms=%lld drain_cpu_ms=%lld\n",
           READERS, (cpu_b - cpu_a) / 1000000, max_cpu / 1000000, max_wait / 1000000,
           max_lag / 1000000, drain_wall / 1000000, drain_cpu / 1000000);
    return 0;
}
