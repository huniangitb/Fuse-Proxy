/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ns_mnt_wait.h"

#include "ns_mnt_watch.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* 切换高发窗口，以及窗口内/外的节拍。实测应用的命名空间切换落在 0–9ms，
   窗口内 200µs 一跳足够密；窗口外退回 2ms —— 那是旧的步进粒度，1.2s 预算里
   多出来的唤醒可以忽略，长时间等待的 CPU 占用不因此上升。 */
#define NS_MNT_WAIT_FAST_WINDOW_US (16 * 1000L)
#define NS_MNT_WAIT_ARM_FAST_US 200L
#define NS_MNT_WAIT_ARM_US 2000L

static long mono_elapsed_us(const struct timespec* from, const struct timespec* to) {
    return (to->tv_sec - from->tv_sec) * 1000000L + (to->tv_nsec - from->tv_nsec) / 1000L;
}

static void arm_to_timespec(struct timespec* ts, long us) {
    if (us < 0) us = 0;
    ts->tv_sec = us / 1000000L;
    ts->tv_nsec = (us % 1000000L) * 1000L;
}

bool ns_mnt_wait_capture(int pid, dev_t* ns_dev, ino_t* ns_ino) {
    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return false;
    }
    struct stat st;
    if (stat(path, &st) != 0) return false;
    if (ns_dev) *ns_dev = st.st_dev;
    if (ns_ino) *ns_ino = st.st_ino;
    return true;
}

long ns_mnt_wait_switch(int pid, dev_t ns_dev, ino_t ns_ino, long budget_ms, bool* switched) {
    if (switched) *switched = false;
    long budget_us = budget_ms * 1000L;
    struct timespec t0, tn;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* 事件源按「当前」命名空间打开：切换之后它盯的还是旧命名空间，所以每一轮
       醒来都换一份新的，应用自己的命名空间里发生的装配才叫得醒我们。 */
    int watch_fd = ns_mnt_watch_open(pid);
    for (;;) {
        if (kill(pid, 0) != 0) break; /* 进程已死，等下去没有意义 */
        dev_t now_dev;
        ino_t now_ino;
        if (ns_mnt_wait_capture(pid, &now_dev, &now_ino) &&
            (now_dev != ns_dev || now_ino != ns_ino)) {
            if (switched) *switched = true;
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &tn);
        long waited_us = mono_elapsed_us(&t0, &tn);
        long left_us = budget_us - waited_us;
        if (left_us <= 0) break;
        long arm_us = (watch_fd >= 0 && waited_us < NS_MNT_WAIT_FAST_WINDOW_US)
                          ? NS_MNT_WAIT_ARM_FAST_US
                          : NS_MNT_WAIT_ARM_US;
        if (arm_us > left_us) arm_us = left_us; /* 最后一跳只睡到预算 */
        struct timespec arm;
        arm_to_timespec(&arm, arm_us);
        if (watch_fd >= 0) {
            /* events 必须为 0：mounts_poll 对任何打开恒置 EPOLLIN，带进掩码就是
               电平触发的忙轮询；EPOLLERR 不受掩码约束，只留它才是「挂载表变了」。
               超时到点同样只当「该复核了」——事件本身不是充分条件。 */
            struct pollfd pfd = {.fd = watch_fd, .events = 0, .revents = 0};
            int pr = ppoll(&pfd, 1, &arm, NULL);
            if (pr < 0 && errno == EINTR) continue;
            if (pr < 0) {
                /* poll 都报错就别再拿它当事件源，剩下的预算按节拍走完 */
                close(watch_fd);
                watch_fd = -1;
                continue;
            }
            close(watch_fd);
            watch_fd = ns_mnt_watch_open(pid);
        } else {
            nanosleep(&arm, NULL);
        }
    }
    if (watch_fd >= 0) close(watch_fd);
    clock_gettime(CLOCK_MONOTONIC, &tn);
    return mono_elapsed_us(&t0, &tn);
}
