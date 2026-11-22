/* FUSE 维护 worker 的判别夹具：直编真实 src/injector/fuse_recover.c，用「慢回调」
 * 代替真实慢活（重启序列 / 启动扫描 / 重挂全部追踪应用），只验证阶段本身：
 * 请求不阻塞调用线程、回调不在调用线程上跑、任务位原样传到回调、完成经 eventfd
 * 交回、突发请求按位合并、shutdown 等手上那轮跑完。
 *
 * queue2 模式用 --wrap=pthread_create 把「建 worker」推迟到两次请求之后：
 * 模块必须在 pending 上按位 OR，用赋值会把先到的任务覆盖掉（一次恢复就此丢失）。 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
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
static _Atomic unsigned g_bits_seen;
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

static void slow_cb(unsigned jobs, void* ctx) {
    (void)ctx;
    if (self_tid() != g_main_tid) atomic_store(&g_cb_off_main, 1);
    atomic_fetch_or(&g_bits_seen, jobs);
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
    const bool queued = nsp_fuse_recover_request(NSP_FUSE_JOB_RECOVER);
    const long long request_us = now_us() - t0;
    long long ready_ms = -1;
    const int got = wait_ready(fd, 10000, &ready_ms);
    const unsigned took_bits = got ? nsp_fuse_recover_take() : 0;
    usleep(20000);
    printf("request_us=%lld ready_ms=%lld got=%d took=%d took_bits=%u rrec=%u runs=%d "
           "cb_off_main=%d threads=%d\n",
           request_us, ready_ms, got, (int)(took_bits != 0), took_bits,
           atomic_load(&g_bits_seen) & NSP_FUSE_JOB_RECOVER, atomic_load(&g_runs),
           atomic_load(&g_cb_off_main), threads_settled());
    printf("queued=%d\n", (int)queued);
    nsp_fuse_recover_shutdown();
}

static void mode_inline(int work_ms) {
    atomic_store(&g_work_us, (long long)work_ms * 1000);
    const long long t0 = now_us();
    slow_cb(NSP_FUSE_JOB_RECOVER, NULL);
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
    nsp_fuse_recover_request(NSP_FUSE_JOB_RECOVER);
    usleep(5000); /* 让第一轮先跑起来，后续请求落进「再来一轮」 */
    const long long t0 = now_us();
    for (int i = 0; i < 40; i++) nsp_fuse_recover_request(NSP_FUSE_JOB_RECOVER);
    const long long burst_us = now_us() - t0;
    long long ready_ms = -1;
    const int got = wait_ready(fd, 10000, &ready_ms);
    const unsigned took_bits = got ? nsp_fuse_recover_take() : 0;
    /* 等合并出来的第二轮也跑完（合并上限是「再来一轮」） */
    usleep((useconds_t)(work_ms * 3 * 1000));
    printf("burst_us=%lld ready_ms=%lld took=%d rounds=%d threads=%d\n", burst_us, ready_ms,
           (int)(took_bits != 0), atomic_load(&g_runs), threads_settled());
    nsp_fuse_recover_shutdown();
}

static void mode_shutdown(int work_ms) {
    atomic_store(&g_work_us, (long long)work_ms * 1000);
    const int fd = nsp_fuse_recover_start(slow_cb, NULL);
    if (fd < 0) {
        printf("start_failed=1\n");
        return;
    }
    nsp_fuse_recover_request(NSP_FUSE_JOB_RECOVER);
    usleep(10000);
    const long long t0 = now_us();
    nsp_fuse_recover_shutdown();
    const long long shutdown_ms = (now_us() - t0) / 1000;
    const int runs_before = atomic_load(&g_runs);
    /* 关停之后再请求必须被拒绝（不新起线程） */
    const bool after_req = nsp_fuse_recover_request(NSP_FUSE_JOB_RECOVER);
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
    const unsigned early = nsp_fuse_recover_take();
    printf("early_take=%u threads=%d\n", early, threads_settled());
    nsp_fuse_recover_shutdown();
}

/* 一次请求带上三段任务位：回调必须一次看到全部位（顺序由 injector 侧固定），
   请求方仍然只是入队。 */
static void mode_jobs(int work_ms) {
    atomic_store(&g_work_us, (long long)work_ms * 1000);
    const int fd = nsp_fuse_recover_start(slow_cb, NULL);
    if (fd < 0) {
        printf("start_failed=1\n");
        return;
    }
    const long long t0 = now_us();
    const bool queued = nsp_fuse_recover_request(NSP_FUSE_JOB_ALL);
    const long long request_us = now_us() - t0;
    long long ready_ms = -1;
    const int got = wait_ready(fd, 10000, &ready_ms);
    const unsigned took_bits = got ? nsp_fuse_recover_take() : 0;
    usleep(20000);
    printf("queued=%d request_us=%lld got=%d took_bits=%u bits_seen=%u has_recover=%d "
           "has_scan=%d has_remount=%d has_media=%d runs=%d cb_off_main=%d threads=%d\n",
           (int)queued, request_us, got, took_bits, atomic_load(&g_bits_seen),
           (atomic_load(&g_bits_seen) & NSP_FUSE_JOB_RECOVER) ? 1 : 0,
           (atomic_load(&g_bits_seen) & NSP_FUSE_JOB_STARTUP_SCAN) ? 1 : 0,
           (atomic_load(&g_bits_seen) & NSP_FUSE_JOB_REMOUNT) ? 1 : 0,
           (atomic_load(&g_bits_seen) & NSP_FUSE_JOB_MEDIA) ? 1 : 0, atomic_load(&g_runs),
           atomic_load(&g_cb_off_main), threads_settled());
    nsp_fuse_recover_shutdown();
}

/* 把模块的「建 worker」推迟到两次请求之后：模块此刻 running=true 且 pending 已置位，
   第二次请求只能并进 pending。按位 OR 的两个任务位都要跑到；用赋值会丢第一个。 */
static _Atomic int g_defer_spawn;
static void* (*g_def_fn)(void*);
static void* g_def_arg;

int __real_pthread_create(pthread_t* tid, const pthread_attr_t* attr, void* (*fn)(void*),
                          void* arg);

/* spawn 失败路径的判别：A 建 worker 失败的同时，B 的请求已经并入 pending 并拿到 true。
   模块必须只撤回 A 自己那几位、把 B 的位留住（下一次建线程跑它），否则 B 的任务位
   永久丢失且无人内联。旧实现失败路径 g_fr_pending = 0 就会丢掉 B 的 REMOUNT。 */
static _Atomic int g_fail_spawn;
static _Atomic int g_helper_done;
static _Atomic int g_helper_ret;
static pthread_t g_helper_tid;

static void* helper_request(void* arg) {
    (void)arg;
    atomic_store(&g_helper_ret, nsp_fuse_recover_request(NSP_FUSE_JOB_REMOUNT) ? 1 : 0);
    atomic_store(&g_helper_done, 1);
    return NULL;
}

static void mode_spawn_fail(int work_ms) {
    atomic_store(&g_work_us, (long long)work_ms * 1000);
    const int fd = nsp_fuse_recover_start(slow_cb, NULL);
    if (fd < 0) {
        printf("start_failed=1\n");
        return;
    }
    atomic_store(&g_fail_spawn, 1);
    const bool q1 = nsp_fuse_recover_request(NSP_FUSE_JOB_STARTUP_SCAN);
    if (!q1) slow_cb(NSP_FUSE_JOB_STARTUP_SCAN, NULL); /* 按 injector 口径内联自己那几位 */
    long long ready_ms = -1;
    const int got = wait_ready(fd, 10000, &ready_ms);
    const unsigned took_bits = got ? nsp_fuse_recover_take() : 0;
    usleep(30000);
    printf("q1=%d helper_ret=%d got=%d took_bits=%u bits_seen=%u has_scan=%d has_remount=%d "
           "runs=%d threads=%d\n",
           (int)q1, atomic_load(&g_helper_ret), got, took_bits, atomic_load(&g_bits_seen),
           (atomic_load(&g_bits_seen) & NSP_FUSE_JOB_STARTUP_SCAN) ? 1 : 0,
           (atomic_load(&g_bits_seen) & NSP_FUSE_JOB_REMOUNT) ? 1 : 0, atomic_load(&g_runs),
           threads_settled());
    nsp_fuse_recover_shutdown();
}
int __wrap_pthread_create(pthread_t* tid, const pthread_attr_t* attr, void* (*fn)(void*),
                          void* arg) {
    if (atomic_exchange(&g_fail_spawn, 0) == 1) {
        if (__real_pthread_create(&g_helper_tid, NULL, helper_request, NULL) != 0) {
            atomic_store(&g_helper_ret, -1);
            atomic_store(&g_helper_done, 1);
        } else {
            (void)pthread_detach(g_helper_tid);
        }
        for (int i = 0; i < 2000 && !atomic_load(&g_helper_done); i++) usleep(1000);
        return EAGAIN; /* 首次建 worker 失败，且此时 B 的请求已并入 pending */
    }
    if (atomic_load(&g_defer_spawn)) {
        g_def_fn = fn;
        g_def_arg = arg;
        return 0; /* 假装创建成功，实际推迟到 queue2 自己建 */
    }
    return __real_pthread_create(tid, attr, fn, arg);
}static void mode_queue2(int work_ms) {
    atomic_store(&g_work_us, (long long)work_ms * 1000);
    const int fd = nsp_fuse_recover_start(slow_cb, NULL);
    if (fd < 0) {
        printf("start_failed=1\n");
        return;
    }
    atomic_store(&g_defer_spawn, 1);
    const bool q1 = nsp_fuse_recover_request(NSP_FUSE_JOB_RECOVER);
    const bool q2 = nsp_fuse_recover_request(NSP_FUSE_JOB_REMOUNT);
    atomic_store(&g_defer_spawn, 0);
    const bool have_fn = g_def_fn != NULL;
    if (have_fn) {
        pthread_attr_t attr;
        pthread_t tid;
        if (pthread_attr_init(&attr) == 0) {
            (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            (void)__real_pthread_create(&tid, &attr, g_def_fn, g_def_arg);
            pthread_attr_destroy(&attr);
        }
    }
    long long ready_ms = -1;
    const int got = have_fn ? wait_ready(fd, 10000, &ready_ms) : 0;
    const unsigned took_bits = got ? nsp_fuse_recover_take() : 0;
    usleep(20000);
    printf("q1=%d q2=%d got=%d took_bits=%u bits_seen=%u has_recover=%d has_remount=%d "
           "rounds=%d threads=%d\n",
           (int)q1, (int)q2, got, took_bits, atomic_load(&g_bits_seen),
           (atomic_load(&g_bits_seen) & NSP_FUSE_JOB_RECOVER) ? 1 : 0,
           (atomic_load(&g_bits_seen) & NSP_FUSE_JOB_REMOUNT) ? 1 : 0, atomic_load(&g_runs),
           threads_settled());
    nsp_fuse_recover_shutdown();
}

int main(int argc, char** argv) {
    g_main_tid = self_tid();
    if (argc < 2) {
        fprintf(stderr,
                "usage: %s offload|inline|coalesce|shutdown|early|jobs|queue2|spawn_fail [work_ms]\n",
                argv[0]);
        return 2;
    }
    const int work_ms = argc >= 3 ? atoi(argv[2]) : 150;
    if (strcmp(argv[1], "offload") == 0) mode_offload(work_ms);
    else if (strcmp(argv[1], "inline") == 0) mode_inline(work_ms);
    else if (strcmp(argv[1], "coalesce") == 0) mode_coalesce(work_ms);
    else if (strcmp(argv[1], "shutdown") == 0) mode_shutdown(work_ms);
    else if (strcmp(argv[1], "early") == 0) mode_early();
    else if (strcmp(argv[1], "jobs") == 0) mode_jobs(work_ms);
    else if (strcmp(argv[1], "queue2") == 0) mode_queue2(work_ms);
    else if (strcmp(argv[1], "spawn_fail") == 0) mode_spawn_fail(work_ms);
    else {
        fprintf(stderr, "unknown mode\n");
        return 2;
    }
    return 0;
}
