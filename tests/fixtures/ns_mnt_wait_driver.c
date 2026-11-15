/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 有界等待体的驱动：直编 src/injector/ns_mnt_wait.c，用真实 /proc 与真实时间量
 * 它的行为（既不 mock 时间也不 mock stat）。
 *
 * 事件源换成这里的 stub：既能复现「打开失败」（调用方应退回纯节拍），也能用一对
 * 管道模拟「挂载表变了」的那一次唤醒——把管道的写端关掉，读端回 EPOLLHUP（与
 * EPOLLERR 同类：不受 events 掩码约束，正是 mounts_poll 用的那条路）。每次 arm
 * 都记一个时间戳，于是「事件来了是立刻醒还是睡满节拍」可以直接量出来。
 *
 * 切换由子进程 unshare(CLONE_NEWUSER|CLONE_NEWNS) 触发：命名空间身份真的变了，
 * 而挂载表没变——这正是被测代码要处理的那种「静默切换」。
 *
 * 输出一律 key=value，供 tests/test_ns_mnt_wait.py 解析。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ns_mnt_wait.h"

/* ── 事件源 stub ───────────────────────────────────────────────────────── */

enum { STUB_REAL = 0, STUB_FAIL = 1, STUB_PIPE = 2 };

#define ARM_SLOTS 4096

static int g_stub = STUB_REAL;
/* 事件线程与等待线程都要看这两个量（对齐 arm、数唤醒次数），故用 volatile：
   不加的话 -O1 会把 g_arms 缓存在寄存器里，spin 等对齐就成了死循环。 */
static volatile int g_arms = 0;
static volatile long g_arm_at[ARM_SLOTS];
static int g_pipe_r = -1;
static int g_pipe_w = -1;
static pthread_mutex_t g_pipe_lock = PTHREAD_MUTEX_INITIALIZER;

static long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000L + ts.tv_nsec / 1000L;
}

static void note_arm(void) {
    if (g_arms < ARM_SLOTS) g_arm_at[g_arms] = now_us();
    g_arms++;
}

int ns_mnt_watch_open(int ns_pid) {
    note_arm();
    if (g_stub == STUB_FAIL) {
        errno = ENOENT;
        return -1;
    }
    if (g_stub == STUB_PIPE) {
        int fds[2];
        pthread_mutex_lock(&g_pipe_lock);
        /* 上一轮那对已经没人用了：不回收会攒 fd，也掩盖读端是否真的被关闭 */
        if (g_pipe_r >= 0) close(g_pipe_r);
        if (g_pipe_w >= 0) close(g_pipe_w);
        g_pipe_r = g_pipe_w = -1;
        if (pipe(fds) != 0) {
            pthread_mutex_unlock(&g_pipe_lock);
            return -1;
        }
        g_pipe_r = fds[0];
        g_pipe_w = fds[1];
        pthread_mutex_unlock(&g_pipe_lock);
        return fcntl(fds[0], F_DUPFD_CLOEXEC, 0);
    }
    char path[64];
    int n = snprintf(path, sizeof path, "/proc/%d/mountinfo", ns_pid);
    if (n < 0 || (size_t)n >= sizeof path) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return open(path, O_RDONLY | O_CLOEXEC);
}

/* 把「当前那一份」事件源的写端关掉：读端随即报 EPOLLHUP，等价于挂载表变化 */
static void fire_event(void) {
    pthread_mutex_lock(&g_pipe_lock);
    if (g_pipe_w >= 0) {
        close(g_pipe_w);
        g_pipe_w = -1;
    }
    pthread_mutex_unlock(&g_pipe_lock);
}

static void close_pipes(void) {
    pthread_mutex_lock(&g_pipe_lock);
    if (g_pipe_r >= 0) close(g_pipe_r);
    if (g_pipe_w >= 0) close(g_pipe_w);
    g_pipe_r = g_pipe_w = -1;
    pthread_mutex_unlock(&g_pipe_lock);
}

/* ── 用例 ─────────────────────────────────────────────────────────────── */

static long thread_cpu_us(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_THREAD, &ru) != 0) return -1;
    return (ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1000000L +
           (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec);
}

/* 不切换：量「有界退出」「没有空转」「节拍落到 2ms 档」 */
static int mode_idle(long budget_ms) {
    dev_t d;
    ino_t i;
    if (!ns_mnt_wait_capture((int)getpid(), &d, &i)) {
        printf("capture_ok=0\n");
        return 1;
    }
    long cpu0 = thread_cpu_us();
    long arms0 = g_arms;
    bool sw = true;
    long us = ns_mnt_wait_switch((int)getpid(), d, i, budget_ms, &sw);
    long cpu = thread_cpu_us() - cpu0;
    printf("capture_ok=1 switched=%d waited_us=%ld cpu_us=%ld arms=%d\n", sw ? 1 : 0, us, cpu,
           g_arms - (int)arms0);
    return 0;
}

/* budget<=0：只复核一次 */
static int mode_zero(void) {
    dev_t d;
    ino_t i;
    if (!ns_mnt_wait_capture((int)getpid(), &d, &i)) return 1;
    bool sw = true;
    long t0 = now_us();
    long us = ns_mnt_wait_switch((int)getpid(), d, i, 0, &sw);
    printf("switched=%d waited_us=%ld wall_us=%ld\n", sw ? 1 : 0, us, now_us() - t0);
    return 0;
}

/* 进程已死：不该陪着它等满预算 */
static int mode_dead(void) {
    dev_t d;
    ino_t i;
    pid_t child = fork();
    if (child == 0) _exit(0);
    int st = 0;
    waitpid(child, &st, 0);
    if (!ns_mnt_wait_capture((int)child, &d, &i)) {
        /* 已收尸的 pid 读不到 ns：用任意基线，等的是「进程死亡」这条退出路径 */
        d = 0;
        i = 0;
    }
    bool sw = true;
    long us = ns_mnt_wait_switch((int)child, d, i, 300, &sw);
    printf("switched=%d waited_us=%ld\n", sw ? 1 : 0, us);
    return 0;
}

/* 切换：子进程 unshare 换命名空间身份，父进程从基线开始等。
   基线必须在放开子进程之前取：若让子进程先报「我起来了」再取基线，负载重时
   父进程会被推迟几百微秒，基线就落在切换之后——那一轮永远等不到变化，量出来
   是整个预算（并发跑全量时偶发）。start 管道把顺序钉死：先取基线，后放行。 */
static int mode_switch(long delay_us, int reps, const char* label) {
    long best = -1, worst = 0, sum = 0;
    int switched_n = 0, unshare_fail = 0, capture_fail = 0, child_gone = 0;
    /* 无效轮（unshare 不可用、子进程自己退出）不计入 reps，重跑一轮补上；
       上限给到 3 倍，环境一直不正常时不会变成死循环。 */
    int done = 0, attempts = 0;
    long best_lag = -1, worst_lag = 0, sum_lag = 0;
    /* 子进程记下自己真的换了命名空间的时刻：fork/唤醒/调度都把「切换」推后，
       那是子进程的事，不该算进「检测得多快」。共享页把零点交给子进程写。 */
    struct shared_clock {
        volatile long long t_start;
        volatile long long t_switched;
    }* sh = mmap(NULL, sizeof *sh, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sh == MAP_FAILED) return 1;
    while (done < reps && attempts < reps * 3 + 5) {
        attempts++;
        sh->t_start = 0;
        sh->t_switched = 0;
        int start_pipe[2];
        if (pipe(start_pipe) != 0) return 1;
        pid_t child = fork();
        if (child == 0) {
            close(start_pipe[1]);
            char c;
            if (read(start_pipe[0], &c, 1) != 1) _exit(92);
            close(start_pipe[0]);
            struct timespec step = {.tv_sec = delay_us / 1000000L,
                                    .tv_nsec = (delay_us % 1000000L) * 1000L};
            nanosleep(&step, NULL);
            if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) _exit(91);
            sh->t_switched = now_us();
            /* 屏蔽全部信号再等：pause() 被任何信号打断就会返回，落回父进程那段
               代码里自己退出——等待方于是看到「进程已死」提前收工，量出来的延迟
               变成一次节拍（并发负载下偶发）。SIGKILL 不受屏蔽影响，父进程收尾照旧。 */
            sigset_t all;
            sigfillset(&all);
            sigprocmask(SIG_BLOCK, &all, NULL);
            for (;;) pause();
        }
        close(start_pipe[0]);
        dev_t d;
        ino_t i;
        if (!ns_mnt_wait_capture((int)child, &d, &i)) {
            capture_fail++;
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
            close(start_pipe[1]);
            continue;
        }
        /* 基线已在手，这时才放子进程去换命名空间 */
        sh->t_start = now_us();
        char c = 'g';
        if (write(start_pipe[1], &c, 1) != 1) {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
            close(start_pipe[1]);
            continue;
        }
        close(start_pipe[1]);
        bool sw = false;
        long us = ns_mnt_wait_switch((int)child, d, i, 500, &sw);
        int st = 0;
        kill(child, SIGKILL);
        waitpid(child, &st, 0);
        if (WIFEXITED(st) && WEXITSTATUS(st) == 91) {
            unshare_fail++;
            continue;
        }
        /* 自己退出的子进程（不是我们 SIGKILL 的）说明这一轮没有可比性：
           等待提前以「进程已死」收工，量出来的不是切换检测延迟。 */
        if (WIFEXITED(st)) {
            child_gone++;
            continue;
        }
        long long off = (sh->t_switched > 0 && sh->t_start > 0) ? sh->t_switched - sh->t_start : 0;
        long lag = (long)(us > off ? us - off : 0);
        if (sw) {
            switched_n++;
            sum += us;
            if (best < 0 || us < best) best = us;
            if (us > worst) worst = us;
            sum_lag += lag;
            if (best_lag < 0 || lag < best_lag) best_lag = lag;
            if (lag > worst_lag) worst_lag = lag;
        }
        printf("run%d switched=%d waited_us=%ld lag_us=%ld switch_at_us=%lld\n", done, sw ? 1 : 0, us,
               lag, off);
        done++;
    }
    printf("%s switched_n=%d reps=%d best_us=%ld worst_us=%ld avg_us=%ld best_lag_us=%ld "
           "worst_lag_us=%ld avg_lag_us=%ld unshare_fail=%d capture_fail=%d child_gone=%d\n",
           label, switched_n, reps, best, worst, switched_n ? sum / switched_n : -1, best_lag,
           worst_lag, switched_n ? sum_lag / switched_n : -1, unshare_fail, capture_fail, child_gone);
    munmap(sh, sizeof *sh);
    return 0;
}

/* 一次「挂载表变了」的假事件，投递在一次节拍刚开始之后约 100µs。
   gap_us = 投递时刻 → 下一次 arm 的间隔：真被事件叫醒是百微秒量级（醒来立刻复
   核、立刻重新 arm），纯节拍则要睡满剩下的节拍（fire=0 是对照组，只对齐不投递）。
   投递点必须落在这一个节拍里：先跨过一次 arm 边界再睡 100µs，于是投递时刻最多
   在 arm 开始后 ~400µs，离下一次节拍还远。 */
struct fire_arg {
    int fire;
    long t_arm;
    long gap_us;
};

static void* fire_thread(void* raw) {
    struct fire_arg* a = (struct fire_arg*)raw;
    a->gap_us = -1;
    /* 先等过高速窗：16ms 之后节拍才是 2ms 档，读数不会被窗内 200µs 的节拍混淆 */
    struct timespec warm = {.tv_sec = 0, .tv_nsec = 20 * 1000L * 1000L};
    nanosleep(&warm, NULL);
    int seen = g_arms;
    long stop = now_us() + 20 * 1000L;
    while (g_arms == seen && now_us() < stop) sched_yield(); /* 跨过一次 arm 边界 */
    if (g_arms == seen) return NULL;
    struct timespec into = {.tv_sec = 0, .tv_nsec = 100 * 1000L};
    nanosleep(&into, NULL); /* 睡进这次 arm 里，事件才「早」于下一次节拍 */
    long t_fire = now_us();
    if (a->fire) fire_event();
    int after = g_arms;
    long hard_stop = t_fire + 10 * 1000L;
    while (g_arms == after && now_us() < hard_stop) sched_yield();
    a->t_arm = t_fire;
    if (g_arms != after) a->gap_us = g_arm_at[g_arms - 1] - t_fire;
    return NULL;
}

static int mode_event(long budget_ms, int fire) {
    g_stub = STUB_PIPE;
    dev_t d;
    ino_t i;
    if (!ns_mnt_wait_capture((int)getpid(), &d, &i)) return 1;
    struct fire_arg a = {.fire = fire, .t_arm = 0, .gap_us = -1};
    pthread_t tid;
    if (pthread_create(&tid, NULL, fire_thread, &a) != 0) return 1;
    bool sw = true;
    long us = ns_mnt_wait_switch((int)getpid(), d, i, budget_ms, &sw);
    pthread_join(tid, NULL);
    printf("switched=%d waited_us=%ld arms=%d fire=%d gap_us=%ld\n", sw ? 1 : 0, us, g_arms, fire,
           a.gap_us);
    close_pipes();
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s idle|zero|dead|switch|fallback|event ...\n", argv[0]);
        return 2;
    }
    const char* mode = argv[1];
    if (strcmp(mode, "idle") == 0) return mode_idle(argc > 2 ? atol(argv[2]) : 300);
    if (strcmp(mode, "zero") == 0) return mode_zero();
    if (strcmp(mode, "dead") == 0) return mode_dead();
    if (strcmp(mode, "switch") == 0)
        return mode_switch(argc > 2 ? atol(argv[2]) : 300, argc > 3 ? atoi(argv[3]) : 5,
                           "switch_s");
    if (strcmp(mode, "fallback") == 0) {
        g_stub = STUB_FAIL;
        return mode_switch(argc > 2 ? atol(argv[2]) : 300, argc > 3 ? atoi(argv[3]) : 5,
                           "fallback_s");
    }
    if (strcmp(mode, "event") == 0)
        return mode_event(argc > 2 ? atol(argv[2]) : 80, argc > 3 ? atoi(argv[3]) : 0);
    fprintf(stderr, "unknown mode: %s\n", mode);
    return 2;
}